/**
 * @file    LinuxVMDetector.cpp
 * @author  Nikolay Yevik
 * @date    2025-12-20
 */

#include "LinuxBlueRedPill.h"

#include <iostream>
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <csetjmp>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <sstream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * This preprocessor check ensures the code only includes <cpuid.h> when compiling on x86 or x86_64 targets. 
 * The macros __i386__ and __x86_64__ are predefined by the compiler for 32-bit and 64-bit x86 respectively.
 * <cpuid.h> exposes intrinsics for the CPUID instruction, which is specific to the x86 family. 
 * Guarding the include prevents build errors on non-x86 architectures that lack this header or the 
 * underlying instruction.
 * This code is designed for x86 where CPUID is available.
 */
#if defined(__i386__) || defined(__x86_64__)
  #include <cpuid.h>
#endif

// ----------------------------- Legacy constants -----------------------------

#define VMWARE_PORT_HYPERVISOR_MAGIC    0x564D5868u
#define VMWARE_HYPERVISOR_PORT          0x5658u
#define VMWARE_PORT_CMD_GETVERSION      10u

#define VMWARE_STR "VMware"
#define XEN_STR "Xen"
#define PAR_STR "Parallels"
#define QEMU_STR "QEMU"
#define NOTFOUND_STR "NOTFOUND"
#define HYPERV_MAGIC_STR "Microsoft Hv"
#define VMWARE_MAGIC_STR "VMwareVMware"
#define XEN_MAGIC_STR "XenVMMXenVMM"
#define KVM_MAGIC_STR "KVMKVMKVM"
#define VBOX_MAGIC_STR "VBoxVBoxVBox"
#define BHYVE_MAGIC_STR "bhyve bhyve "

#define DMIDECODE_CMD "dmidecode"
#define DMYSYSVENDOR "/sys/devices/virtual/dmi/id/sys_vendor"
#define CPUINFO_PATH "/proc/cpuinfo"

#define DEBUG   1 // Enable debug logging, set to 1 to enable, 0 to disable

static inline void copy_magic(char dst[HV_BRAND_MAX_NAME_LEN], const char* src)
{
    std::memset(dst, 0, HV_BRAND_MAX_NAME_LEN);
    if (!src) return;
    const size_t n = std::min(std::strlen(src), static_cast<size_t>(HV_BRAND_MAX_NAME_LEN - 1));
    std::memcpy(dst, src, n);
    dst[n] = '\0';
}

// ----------------------------- Internal legacy signal helpers -----------------------------

namespace LVMHVD
{
    volatile sig_atomic_t eflag = 0; //intended to be safely 
    /** modified from within a signal handler, SIGSEGV_Handler present.
    Can change asynchronously outside of normal program flow.
    *****! Not appropriate for multi-threaded use !******
    @todo Consider making this thread-safe if multi-threaded use is required.(std::atomic<sig_atomic_t>)
    */
    sigjmp_buf sigill_jmp;

    void SIGILL_Handler(int) { siglongjmp(sigill_jmp, 1); }
    void SIGSEGV_Handler(int) { eflag = 1; }
}

// ----------------------------- Utility (modern) -----------------------------

static inline std::string toLowerCopy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool LinuxVMHyperDetector::PathExists_Modern(const std::string &path)
{
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0;
}

std::string LinuxVMHyperDetector::Trim_Modern(std::string s)
{
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || std::isspace(static_cast<unsigned char>(s.back()))))
        s.pop_back();
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
        ++i;
    if (i > 0) s.erase(0, i);
    return s;
}

bool LinuxVMHyperDetector::ContainsIcase_Modern(const std::string &haystack, const std::string &needle)
{
    const std::string h = toLowerCopy(haystack);
    const std::string n = toLowerCopy(needle);
    return h.find(n) != std::string::npos;
}

bool LinuxVMHyperDetector::ReadTextFile_Modern(const std::string &path, std::string &out, size_t maxBytes)
{
    out.clear();
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open())
        return false;

    std::string tmp;
    tmp.resize(maxBytes);
    in.read(tmp.data(), static_cast<std::streamsize>(maxBytes));
    const auto got = static_cast<size_t>(in.gcount());
    tmp.resize(got);
    out = tmp;
    return true;
}

LinuxVMHyperDetector::ExecResult LinuxVMHyperDetector::ExecCapture_Modern(const std::vector<std::string> &argv, int timeout_seconds)
{
    ExecResult r;
    if (argv.empty())
        return r;

    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto &s : argv)
        cargv.push_back(const_cast<char*>(s.c_str()));
    cargv.push_back(nullptr);

    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};

    if (::pipe(out_pipe) != 0)
        return r;
    if (::pipe(err_pipe) != 0)
    {
        ::close(out_pipe[0]); ::close(out_pipe[1]);
        return r;
    }

    pid_t pid = ::fork();
    if (pid < 0)
    {
        ::close(out_pipe[0]); ::close(out_pipe[1]);
        ::close(err_pipe[0]); ::close(err_pipe[1]);
        return r;
    }

    if (pid == 0)
    {
        // child
        ::dup2(out_pipe[1], STDOUT_FILENO);
        ::dup2(err_pipe[1], STDERR_FILENO);

        ::close(out_pipe[0]); ::close(out_pipe[1]);
        ::close(err_pipe[0]); ::close(err_pipe[1]);

        ::execvp(cargv[0], cargv.data());
        _exit(127);
    }

    // parent
    ::close(out_pipe[1]);
    ::close(err_pipe[1]);

    auto read_all = [](int fd) -> std::string {
        std::string out;
        std::array<char, 4096> buf{};
        for (;;)
        {
            const ssize_t n = ::read(fd, buf.data(), buf.size());
            if (n > 0) out.append(buf.data(), static_cast<size_t>(n));
            else break;
        }
        return out;
    };

    // crude timeout: poll waitpid with sleep
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    for (;;)
    {
        const pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (w == 0)
        {
            if (std::chrono::steady_clock::now() > deadline)
            {
                ::kill(pid, SIGKILL);
                ::waitpid(pid, &status, 0);
                break;
            }
            ::usleep(50 * 1000);
            continue;
        }
        // error
        break;
    }

    r.stdout_data = read_all(out_pipe[0]);
    r.stderr_data = read_all(err_pipe[0]);
    ::close(out_pipe[0]);
    ::close(err_pipe[0]);

    if (WIFEXITED(status))
        r.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        r.exit_code = 128 + WTERMSIG(status);
    else
        r.exit_code = -1;

    return r;
}

bool LinuxVMHyperDetector::Cpuid_Modern(uint32_t leaf, uint32_t subleaf,
                                       uint32_t &eax, uint32_t &ebx, uint32_t &ecx, uint32_t &edx)
{
#if defined(__i386__) || defined(__x86_64__)
    __cpuid_count(leaf, subleaf, eax, ebx, ecx, edx);
    return true;
#else
    (void)leaf; (void)subleaf; (void)eax; (void)ebx; (void)ecx; (void)edx;
    return false;
#endif
}

// ----------------------------- Class impl -----------------------------
/** Constructor for LinuxVMHyperDetector */
LinuxVMHyperDetector::LinuxVMHyperDetector()
{
    std::memset(_HVID, 0, sizeof(_HVID));
    copy_magic(_HVID, NOTFOUND_STR);

#ifdef DEBUG
    std::cout << "Hypervisor ID initialized to: " << _HVID << " in function: "
              << __PRETTY_FUNCTION__ << " at line: " << __LINE__ << std::endl;
#endif

}

std::string LinuxVMHyperDetector::GetHypervisorName()
{
    return std::string(_HVID);
}

std::vector<std::string> LinuxVMHyperDetector::GetEvidence() const
{
    return _evidence_modern;
}

/** 
 * @brief Determine if the current system is running inside a virtual machine.
 *
 * This function uses the modern detection path to check for the presence of a hypervisor.
 * It does not automatically invoke legacy detection methods.
 * @return int Returns a value indicating the VM status: VM if a hypervisor is detected, NOTFOUND otherwise.
 * @see LinuxVMHyperDetector::IsVM_Modern
 * @see LinuxVMHyperDetector::Detect_Modern
 * @note Wrapper around the modern detection path.
 */
int LinuxVMHyperDetector::IsVM()
{
    // Default: modern path. Legacy preserved but not automatically invoked.
    return IsVM_Modern();
}

void LinuxVMHyperDetector::SetVendorMagic_Modern(const std::string &magic)
{
    std::memset(_HVID, 0, sizeof(_HVID));
    if (magic.empty())
        copy_magic(_HVID, NOTFOUND_STR);
    else
        copy_magic(_HVID, magic.c_str());
    _HVID[HV_BRAND_MAX_NAME_LEN - 1] = '\0';
}

static inline std::string cpuid_vendor_string(uint32_t ebx, uint32_t ecx, uint32_t edx)
{
    char v[13];
    std::memcpy(v + 0, &ebx, 4);
    std::memcpy(v + 4, &ecx, 4);
    std::memcpy(v + 8, &edx, 4);
    v[12] = '\0';
    return std::string(v);
}

int LinuxVMHyperDetector::DetectViaCpuid_Modern(std::string &vendor_magic_out)
{
    vendor_magic_out.clear();

#if !(defined(__i386__) || defined(__x86_64__))
    return NOTFOUND;
#else
    uint32_t a=0,b=0,c=0,d=0;

    // Hypervisor present bit: CPUID.(EAX=1):ECX[31]
    Cpuid_Modern(1, 0, a,b,c,d);
    const bool hypervisor_bit = (c & (1u << 31)) != 0;
    if (!hypervisor_bit)
    {
        _evidence_modern.emplace_back("CPUID leaf 1: hypervisor bit NOT set");
        return NOTFOUND;
    }
    _evidence_modern.emplace_back("CPUID leaf 1: hypervisor bit set");

    // Hypervisor vendor leaf: 0x40000000
    Cpuid_Modern(0x40000000u, 0, a,b,c,d);
    const std::string hv_vendor = cpuid_vendor_string(b,c,d);
    _evidence_modern.emplace_back("CPUID 0x40000000 vendor: " + hv_vendor);

    // Map to canonical magic strings where possible
    if (hv_vendor == VMWARE_MAGIC_STR) vendor_magic_out = VMWARE_MAGIC_STR;
    else if (hv_vendor == XEN_MAGIC_STR) vendor_magic_out = XEN_MAGIC_STR;
    else if (hv_vendor == KVM_MAGIC_STR) vendor_magic_out = KVM_MAGIC_STR;
    else if (hv_vendor == HYPERV_MAGIC_STR) vendor_magic_out = HYPERV_MAGIC_STR;
    else if (hv_vendor == VBOX_MAGIC_STR) vendor_magic_out = VBOX_MAGIC_STR;
    else if (hv_vendor == BHYVE_MAGIC_STR) vendor_magic_out = BHYVE_MAGIC_STR;
    else
        vendor_magic_out = hv_vendor; // unknown vendor string; still evidence of VM

    return VM;
#endif
}

int LinuxVMHyperDetector::DetectViaDmiSysfs_Modern(std::string &vendor_magic_out)
{
    vendor_magic_out.clear();

    // Common DMI paths (prefer /sys/class/dmi/id on modern distros)
    const std::vector<std::string> paths = {
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/product_version",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        DMYSYSVENDOR
    };

    std::string aggregate;
    for (const auto &p : paths)
    {
        std::string s;
        if (ReadTextFile_Modern(p, s, 4096))
        {
            s = Trim_Modern(s);
            if (!s.empty())
                aggregate += p + "=" + s + "\n";
        }
    }

    if (aggregate.empty())
        return NOTFOUND;

    _evidence_modern.emplace_back("DMI sysfs:\n" + aggregate);

    // Heuristic mapping
    if (ContainsIcase_Modern(aggregate, "vmware"))
    {
        vendor_magic_out = VMWARE_MAGIC_STR;
        return VM;
    }
    if (ContainsIcase_Modern(aggregate, "virtualbox") || ContainsIcase_Modern(aggregate, "innotek") || ContainsIcase_Modern(aggregate, "oracle"))
    {
        vendor_magic_out = VBOX_MAGIC_STR;
        return VM;
    }
    if (ContainsIcase_Modern(aggregate, "kvm") || ContainsIcase_Modern(aggregate, "qemu") || ContainsIcase_Modern(aggregate, "rhev") || ContainsIcase_Modern(aggregate, "ovirt") || ContainsIcase_Modern(aggregate, "red hat"))
    {
        // Note: "Red Hat" can occur on bare metal too; but in DMI it often implies KVM/QEMU.
        vendor_magic_out = KVM_MAGIC_STR;
        return VM;
    }
    if (ContainsIcase_Modern(aggregate, "xen"))
    {
        vendor_magic_out = XEN_MAGIC_STR;
        return VM;
    }
    if (ContainsIcase_Modern(aggregate, "microsoft corporation") || ContainsIcase_Modern(aggregate, "hyper-v"))
    {
        vendor_magic_out = HYPERV_MAGIC_STR;
        return VM;
    }
    if (ContainsIcase_Modern(aggregate, "parallels"))
    {
        vendor_magic_out = PAR_STR;
        return VM;
    }
    if (ContainsIcase_Modern(aggregate, "bhyve"))
    {
        vendor_magic_out = BHYVE_MAGIC_STR;
        return VM;
    }

    return NOTFOUND;
}

int LinuxVMHyperDetector::DetectViaXenSysfs_Modern(std::string &vendor_magic_out)
{
    vendor_magic_out.clear();

    std::string s;
    if (ReadTextFile_Modern("/sys/hypervisor/type", s, 128))
    {
        s = Trim_Modern(s);
        _evidence_modern.emplace_back("/sys/hypervisor/type=" + s);
        if (ContainsIcase_Modern(s, "xen"))
        {
            vendor_magic_out = XEN_MAGIC_STR;
            return VM;
        }
    }

    if (PathExists_Modern("/proc/xen/capabilities") || PathExists_Modern("/proc/xen"))
    {
        _evidence_modern.emplace_back("Found /proc/xen*");
        vendor_magic_out = XEN_MAGIC_STR;
        return VM;
    }

    return NOTFOUND;
}

int LinuxVMHyperDetector::DetectViaGuestDrivers_Modern(std::string &vendor_magic_out)
{
    vendor_magic_out.clear();

    struct ModHint { const char* path; const char* vendor; const char* note; };
    const ModHint hints[] = {
        { "/sys/module/vboxguest", VBOX_MAGIC_STR, "vboxguest module present" },
        { "/sys/module/vmwgfx", VMWARE_MAGIC_STR, "vmwgfx module present" },
        { "/sys/module/hv_vmbus", HYPERV_MAGIC_STR, "Hyper-V vmbus module present" },
        { "/sys/module/xenfs", XEN_MAGIC_STR, "xenfs module present" },
        { "/sys/module/kvm", KVM_MAGIC_STR, "kvm module present (weak signal inside guest)" },
    };

    for (const auto &h : hints)
    {
        if (PathExists_Modern(h.path))
        {
            _evidence_modern.emplace_back(std::string("Guest driver signal: ") + h.note + " (" + h.path + ")");
            vendor_magic_out = h.vendor;
            return VM;
        }
    }

    return NOTFOUND;
}

int LinuxVMHyperDetector::DetectViaCpuInfo_Modern(std::string &vendor_magic_out)
{
    vendor_magic_out.clear();

    std::string cpuinfo;
    if (!ReadTextFile_Modern(CPUINFO_PATH, cpuinfo, 64 * 1024))
        return NOTFOUND;

    // Common QEMU/KVM strings
    if (ContainsIcase_Modern(cpuinfo, "QEMU Virtual") || ContainsIcase_Modern(cpuinfo, "TCG") || ContainsIcase_Modern(cpuinfo, "KVM"))
    {
        _evidence_modern.emplace_back("/proc/cpuinfo contains QEMU/KVM/TCG string");
        vendor_magic_out = KVM_MAGIC_STR;
        return VM;
    }

    // Some environments include "hypervisor" in flags but vendor leaf is hidden.
    if (ContainsIcase_Modern(cpuinfo, " hypervisor "))
    {
        _evidence_modern.emplace_back("/proc/cpuinfo indicates hypervisor flag");
        vendor_magic_out.clear();
        return VM;
    }

    return NOTFOUND;
}

int LinuxVMHyperDetector::DetectViaHelperTools_Modern(std::string &vendor_magic_out)
{
    vendor_magic_out.clear();

    // systemd-detect-virt (optional)
    {
        ExecResult r = ExecCapture_Modern({ "systemd-detect-virt", "--vm" }, 3);
        if (r.exit_code == 0)
        {
            std::string out = Trim_Modern(r.stdout_data);
            if (!out.empty() && out != "none")
            {
                _evidence_modern.emplace_back("systemd-detect-virt --vm: " + out);
                // Map some known outputs
                if (out == "kvm" || out == "qemu") vendor_magic_out = KVM_MAGIC_STR;
                else if (out == "vmware") vendor_magic_out = VMWARE_MAGIC_STR;
                else if (out == "oracle" || out == "vbox") vendor_magic_out = VBOX_MAGIC_STR;
                else if (out == "microsoft" || out == "hyperv") vendor_magic_out = HYPERV_MAGIC_STR;
                else if (out == "xen") vendor_magic_out = XEN_MAGIC_STR;
                else if (out == "parallels") vendor_magic_out = PAR_STR;
                return VM;
            }
        }
    }

    // virt-what (optional)
    {
        ExecResult r = ExecCapture_Modern({ "virt-what" }, 3);
        if (r.exit_code == 0)
        {
            std::string out = Trim_Modern(r.stdout_data);
            if (!out.empty())
            {
                _evidence_modern.emplace_back("virt-what: " + out);
                if (ContainsIcase_Modern(out, "kvm") || ContainsIcase_Modern(out, "qemu")) vendor_magic_out = KVM_MAGIC_STR;
                else if (ContainsIcase_Modern(out, "vmware")) vendor_magic_out = VMWARE_MAGIC_STR;
                else if (ContainsIcase_Modern(out, "xen")) vendor_magic_out = XEN_MAGIC_STR;
                else if (ContainsIcase_Modern(out, "hyperv")) vendor_magic_out = HYPERV_MAGIC_STR;
                else if (ContainsIcase_Modern(out, "virtualbox")) vendor_magic_out = VBOX_MAGIC_STR;
                else if (ContainsIcase_Modern(out, "parallels")) vendor_magic_out = PAR_STR;
                return VM;
            }
        }
    }

    return NOTFOUND;
}

int LinuxVMHyperDetector::IsVM_Modern()
{
    _evidence_modern.clear();

    // Start with the most direct signals
    std::string magic;

    if (DetectViaCpuid_Modern(magic) == VM)
    {
        SetVendorMagic_Modern(magic);
        return VM;
    }

    if (DetectViaXenSysfs_Modern(magic) == VM)
    {
        SetVendorMagic_Modern(magic);
        return VM;
    }

    if (DetectViaDmiSysfs_Modern(magic) == VM)
    {
        SetVendorMagic_Modern(magic);
        return VM;
    }

    if (DetectViaGuestDrivers_Modern(magic) == VM)
    {
        SetVendorMagic_Modern(magic);
        return VM;
    }

    // weaker / heuristic signals
    const int cpuinfo_rc = DetectViaCpuInfo_Modern(magic);
    if (cpuinfo_rc == VM)
    {
        if (!magic.empty()) SetVendorMagic_Modern(magic);
        else SetVendorMagic_Modern(std::string());
        return VM;
    }

    if (DetectViaHelperTools_Modern(magic) == VM)
    {
        if (!magic.empty()) SetVendorMagic_Modern(magic);
        else SetVendorMagic_Modern(std::string());
        return VM;
    }

    SetVendorMagic_Modern(std::string());
    _evidence_modern.emplace_back("No VM signals found (modern path) -> assuming bare metal");
    return BAREMETAL;
}

// ----------------------------- Legacy implementation -----------------------------

void LinuxVMHyperDetector::Xen_CPUID_Legacy(uint32_t idx, uint32_t *regs, int pv_context)
{
#if defined(__i386__)
    asm volatile (
        "push %%eax; push %%ebx; push %%ecx; push %%edx\n\t"
        "test %1,%1 ; jz 1f ; ud2a ; .ascii \"xen\" ; 1: cpuid\n\t"
        "mov %%eax,(%2); mov %%ebx,4(%2)\n\t"
        "mov %%ecx,8(%2); mov %%edx,12(%2)\n\t"
        "pop %%edx; pop %%ecx; pop %%ebx; pop %%eax\n\t"
        : : "a" (idx), "c" (pv_context), "S" (regs) : "memory" );
#elif defined(__x86_64__)
    asm volatile (
        "test %5,%5 ; jz 1f ; ud2a ; .ascii \"xen\" ; 1: cpuid\n\t"
        : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
        : "0" (idx), "1" (pv_context), "2" (0) );
#else
    (void)idx; (void)regs; (void)pv_context;
#endif
}

unsigned int LinuxVMHyperDetector::CPUID_Legacy(unsigned int eax, char *sig)
{
#if defined(__i386__) || defined(__x86_64__)
    unsigned int *sig32 = reinterpret_cast<unsigned int *>(sig);

    asm volatile (
        "xchgl %%ebx,%1; xor %%ebx,%%ebx; cpuid; xchgl %%ebx,%1"
        : "=a" (eax), "+r" (sig32[0]), "=c" (sig32[1]), "=d" (sig32[2])
        : "0" (eax));

    sig[12] = 0;
    return eax;
#else
    (void)eax; (void)sig;
    return 0;
#endif
}
/**
 * Checks for the presence of a Xen hypervisor using the legacy CPUID method.
 * @param pv_context The paravirtualization context to use for the CPUID check.
 * @return The CPUID result indicating the presence of a Xen hypervisor, or 0 if not found.
 * @pre The caller must ensure that the CPU supports the CPUID instruction.
 * @post The hypervisor ID is stored in the _HVID member variable if a Xen hypervisor is detected.
 */
int LinuxVMHyperDetector::Check_For_Xen_Legacy(int pv_context)
{
    uint32_t regs[4] = {0,0,0,0}; /**< Array to store CPUID register values */
    uint32_t base; /**< Base CPUID leaf for Xen hypervisor detection */

    for (base = 0x40000000; base < 0x40010000; base += 0x100)
    {
        Xen_CPUID_Legacy(base, regs, pv_context);

        std::memcpy(_HVID + 0, &regs[1], 4);
        std::memcpy(_HVID + 4, &regs[2], 4);
        std::memcpy(_HVID + 8, &regs[3], 4);
        _HVID[HV_BRAND_MAX_NAME_LEN - 1] = '\0';

        /**< Check if the hypervisor ID matches the Xen magic string and if the CPUID leaf is valid  */
        if (!std::strcmp(XEN_MAGIC_STR, _HVID) && (regs[0] >= (base + 2)))
            goto found;
    }

    return 0;

found: /**< Found a Xen hypervisor*/ 
    Xen_CPUID_Legacy(base + 1, regs, pv_context); /**< Retrieve the next CPUID leaf for Xen hypervisor detection */
    return static_cast<int>(regs[0]); 
}//end of LinuxVMHyperDetector::Check_For_Xen_Legacy()

int LinuxVMHyperDetector::CheckProcCPUInfo4QEMU_Legacy()
{
    std::string dataRead;
    if (!ReadTextFile_Modern(CPUINFO_PATH, dataRead, 64 * 1024))
        return -1;

    if (dataRead.find("QEMU Virtual", 0) != std::string::npos)
    {
        copy_magic(_HVID, QEMU_STR);
        return QEMU;
    }

    copy_magic(_HVID, NOTFOUND_STR);
    return NOTFOUND;
}

int LinuxVMHyperDetector::Check_DMI_Legacy()
{
    std::string dataRead;
    if (!ReadTextFile_Modern(DMYSYSVENDOR, dataRead, 4096))
        return -1;

    dataRead = Trim_Modern(dataRead);

    if (dataRead.rfind(VMWARE_STR, 0) == 0)
    {
        copy_magic(_HVID, VMWARE_MAGIC_STR);
        return VMWARE;
    }
    if (dataRead.rfind(XEN_STR, 0) == 0)
    {
        copy_magic(_HVID, XEN_MAGIC_STR);
        return XEN;
    }
    if (dataRead.rfind(PAR_STR, 0) == 0)
    {
        copy_magic(_HVID, PAR_STR);
        return PAR;
    }

    return NOTFOUND;
}
/** Legacy DMI decode check using dmidecode command
 * This function uses the dmidecode command to query the system manufacturer
 * and determine if the system is running on a known virtual machine hypervisor.
 * It captures the output of the command in a worker thread to avoid blocking
 * the main thread and then parses the output to identify the hypervisor.
 * This approach ensures that the main thread remains responsive while the
 * potentially slow dmidecode command executes.
 * Expected to exit 1 on bare metal!
 * To specifically validate the dmidecode fallback, run the legacy detector on a system where 
 * /sys/devices/virtual/dmi/id/sys_vendor is unavailable or temporarily restrict access, 
 * then re-run linux-safe-vm-detect --evidence.
 */
int LinuxVMHyperDetector::Check_DMIdecode_Legacy()
{
    // Legacy dmidecode path: run in a worker thread, capture stdout, then join.
    ExecResult exec;
    std::jthread worker([&exec] {
        exec = ExecCapture_Modern({ DMIDECODE_CMD, "-s", "system-manufacturer" });
    });
    worker.join(); // synchronization point before consuming exec

    if (exec.exit_code < 0)
        return -1;

    std::string dataRead = Trim_Modern(exec.stdout_data);

    if (dataRead.rfind(VMWARE_STR, 0) == 0)
    {
        copy_magic(_HVID, VMWARE_MAGIC_STR);
        return VMWARE;
    }
    if (dataRead.rfind(XEN_STR, 0) == 0)
    {
        copy_magic(_HVID, XEN_MAGIC_STR);
        return XEN;
    }
    if (dataRead.rfind(PAR_STR, 0) == 0)
    {
        copy_magic(_HVID, PAR_STR);
        return PAR;
    }

    copy_magic(_HVID, NOTFOUND_STR);
    return NOTFOUND;
}


/** Legacy DMI decode check, risky, don't like popen */
/*int LinuxVMHyperDetector::Check_DMIdecode_Legacy()
{
    // Legacy popen-based path preserved (no Boost). This may require root.
    FILE* fpipe = ::popen(DMIDECODE_CMD, "r");
    if (!fpipe)
        return -1;

    std::unique_ptr<FILE, int(*)(FILE*)> pipe_guard(fpipe, ::pclose);

    std::string dataRead;
    std::array<char, 1024> buf{};
    size_t readBytes = 0;
    while (::fgets(buf.data(), static_cast<int>(buf.size()), fpipe) != nullptr)
    {
        dataRead.append(buf.data());
        readBytes += std::strlen(buf.data()); // fixed: += (not =+)
        if (readBytes >= 50 * 1024)
            break;
    }

    if (dataRead.rfind(VMWARE_STR, 0) == 0)
    {
        copy_magic(_HVID, VMWARE_MAGIC_STR);
        return VMWARE;
    }
    if (dataRead.rfind(XEN_STR, 0) == 0)
    {
        copy_magic(_HVID, XEN_MAGIC_STR);
        return XEN;
    }
    if (dataRead.rfind(PAR_STR, 0) == 0)
    {
        copy_magic(_HVID, PAR_STR);
        return PAR;
    }

    copy_magic(_HVID, NOTFOUND_STR);
    return NOTFOUND;
}*/

int LinuxVMHyperDetector::VmwareCheckVM_Legacy()
{
    auto run_vmware_checkvm = []() -> ExecResult {
        ExecResult r;
        int out_pipe[2] = {-1, -1};

        if (::pipe(out_pipe) != 0)
            return r;

        const pid_t pid = ::fork();
        if (pid < 0)
        {
            ::close(out_pipe[0]);
            ::close(out_pipe[1]);
            return r;
        }

        if (pid == 0)
        {
            // child: stdout -> pipe, stderr -> /dev/null
            ::dup2(out_pipe[1], STDOUT_FILENO);
            ::close(out_pipe[0]);
            ::close(out_pipe[1]);

            const int devnull = ::open("/dev/null", O_WRONLY);
            if (devnull >= 0)
            {
                ::dup2(devnull, STDERR_FILENO);
                ::close(devnull);
            }

            char* const argv[] = {const_cast<char*>("vmware-checkvm"), nullptr};
            ::execvp(argv[0], argv);
            _exit(127);
        }

        ::close(out_pipe[1]);

        std::string dataRead;
        std::array<char, 4096> buf{};
        size_t readBytes = 0;
        for (;;)
        {
            const ssize_t n = ::read(out_pipe[0], buf.data(), buf.size());
            if (n <= 0)
                break;

            const size_t remaining = (readBytes < 50 * 1024) ? (50 * 1024 - readBytes) : 0;
            const size_t to_copy = std::min(static_cast<size_t>(n), remaining);
            if (to_copy > 0)
            {
                dataRead.append(buf.data(), to_copy);
                readBytes += to_copy;
            }
        }
        ::close(out_pipe[0]);

        int status = 0;
        if (::waitpid(pid, &status, 0) == pid)
        {
            if (WIFEXITED(status))
                r.exit_code = WEXITSTATUS(status);
            else if (WIFSIGNALED(status))
                r.exit_code = 128 + WTERMSIG(status);
        }

        r.stdout_data = dataRead;
        return r;
    };

    ExecResult exec;
    std::jthread worker([&exec, run_vmware_checkvm] {
        exec = run_vmware_checkvm();
    });
    worker.join(); // ensure result is ready before parsing

    if (exec.exit_code < 0)
        return -1;

    if (exec.stdout_data.find(VMWARE_STR) == std::string::npos)
    {
        copy_magic(_HVID, NOTFOUND_STR);
        return NOTFOUND;
    }

    copy_magic(_HVID, VMWARE_MAGIC_STR);
    return VMWARE;
} // end of VmwareCheckVM_Legacy()

// My Legacy VmwareCheckVM using popen, I don't like it.
/*int LinuxVMHyperDetector::VmwareCheckVM_Legacy()
{
    FILE* fpipe = ::popen("vmware-checkvm 2>/dev/null", "r");
    if (!fpipe)
        return -1;

    std::unique_ptr<FILE, int(*)(FILE*)> pipe_guard(fpipe, ::pclose);

    std::string dataRead;
    std::array<char, 1024> buf{};
    size_t readBytes = 0;
    while (::fgets(buf.data(), static_cast<int>(buf.size()), fpipe) != nullptr)
    {
        dataRead.append(buf.data());
        readBytes += std::strlen(buf.data()); // fixed: +=
        if (readBytes >= 50 * 1024)
            break;
    }

    if (dataRead.find(VMWARE_STR) == std::string::npos)
    {
        copy_magic(_HVID, NOTFOUND_STR);
        return NOTFOUND;
    }

    copy_magic(_HVID, VMWARE_MAGIC_STR);
    return VMWARE;
} // end of VmwareCheckVM_Legacy()
*/

#if defined(__x86_64__)
static inline void vmware_port_getversion(uint32_t &eax, uint32_t &ebx, uint32_t &ecx, uint32_t &edx)
{
    asm volatile (
        "inl (%%dx)"
        : "=a"(eax), "=c"(ecx), "=d"(edx), "=b"(ebx)
        : "0"(VMWARE_PORT_HYPERVISOR_MAGIC),
          "1"(VMWARE_PORT_CMD_GETVERSION),
          "2"(VMWARE_HYPERVISOR_PORT),
          "3"(UINT32_MAX)
        : "memory"
    );
}
#endif

int LinuxVMHyperDetector::VMware_HV_Port_Check_Legacy()
{
#if !LVMHVD_ENABLE_RISKY_LEGACY_PROBES
    // Preserved but disabled by default.
    return NOTFOUND;
#else
    // As in original: only run after DMI strongly indicates VMware
    const int dmi_rc = Check_DMI_Legacy();
    if (dmi_rc != VMWARE)
        return NOTFOUND;

    struct sigaction new_act{}, old_act{};
    sigemptyset(&new_act.sa_mask);
    new_act.sa_flags = 0;
    new_act.sa_handler = LVMHVD::SIGSEGV_Handler;
    if (sigaction(SIGSEGV, &new_act, &old_act) == -1)
    {
        copy_magic(_HVID, NOTFOUND_STR);
        return NOTFOUND;
    }

#if defined(__x86_64__)
    uint32_t eax=0, ebx=0, ecx=0, edx=0;
    vmware_port_getversion(eax, ebx, ecx, edx);
    if (ebx == VMWARE_PORT_HYPERVISOR_MAGIC)
    {
        copy_magic(_HVID, VMWARE_MAGIC_STR);
        sigaction(SIGSEGV, &old_act, nullptr);
        return VMWARE;
    }
#endif

    if (LVMHVD::eflag == 1)
        LVMHVD::eflag = 0;

    sigaction(SIGSEGV, &old_act, nullptr);
    copy_magic(_HVID, NOTFOUND_STR);
    return NOTFOUND;
#endif
}

int LinuxVMHyperDetector::IsVM_Legacy()
{
#if !(defined(__i386__) || defined(__x86_64__))
    copy_magic(_HVID, NOTFOUND_STR);
    return BAREMETAL;
#else
    copy_magic(_HVID, NOTFOUND_STR);

    // 1) VMware tools check (legacy external)
    const int vmware_tools = VmwareCheckVM_Legacy();
    if (vmware_tools == VMWARE)
        return VM;

    // 2) Hypervisor vendor leaf scan (legacy CPUID)
    unsigned int base = 0x40000000u;
    unsigned int leaf = base;
    char sig[HV_BRAND_MAX_NAME_LEN] = {};
    CPUID_Legacy(leaf, sig);

    bool hyperv_detect = false;
    bool qemu_kvm_detect = false;

    for (leaf = base; leaf <= 0x40010000u; leaf += 0x100u)
    {
        std::memset(sig, 0, sizeof(sig));
        CPUID_Legacy(leaf, sig);

        if (!std::strcmp(sig, VMWARE_MAGIC_STR))
        {
            copy_magic(_HVID, VMWARE_MAGIC_STR);
            return VM;
        }
        if (!std::strcmp(sig, HYPERV_MAGIC_STR))
        {
            hyperv_detect = true;
        }
        if (!std::strcmp(sig, XEN_MAGIC_STR) && (leaf > base))
        {
            copy_magic(_HVID, XEN_MAGIC_STR);
            return VM;
        }
        if (!std::strcmp(sig, KVM_MAGIC_STR))
        {
            qemu_kvm_detect = true;
        }
        if (hyperv_detect && (leaf > base))
        {
            copy_magic(_HVID, HYPERV_MAGIC_STR);
            return VM;
        }
    }

    // 3) Xen HVM / PV detection (legacy; PV hook is gated)
    struct sigaction old_act{};
    sigaction(SIGILL, nullptr, &old_act);

    int version = Check_For_Xen_Legacy(0);
    if (version != 0)
    {
        copy_magic(_HVID, XEN_MAGIC_STR);
        return VM;
    }

#if LVMHVD_ENABLE_RISKY_LEGACY_PROBES
    if (!sigsetjmp(LVMHVD::sigill_jmp, 1) &&
        (signal(SIGILL, LVMHVD::SIGILL_Handler) != SIG_ERR) &&
        ((version = Check_For_Xen_Legacy(1)) != 0))
    {
        sigaction(SIGILL, &old_act, nullptr);
        copy_magic(_HVID, XEN_MAGIC_STR);
        return VM;
    }
#endif

    sigaction(SIGILL, &old_act, nullptr);

    // 4) VMware HV port check (disabled by default)
    if (VMware_HV_Port_Check_Legacy() == VMWARE)
        return VM;

    // 5) KVM/Parallels DMI disambiguation
    if (qemu_kvm_detect)
    {
        const int sys_dmi_rc = Check_DMI_Legacy();
        if (sys_dmi_rc == PAR)
        {
            copy_magic(_HVID, PAR_STR);
            return VM;
        }

        copy_magic(_HVID, KVM_MAGIC_STR);
        return VM;
    }

    // 6) QEMU fallback via /proc/cpuinfo string
    if (CheckProcCPUInfo4QEMU_Legacy() == QEMU)
        return VM;

    // 7) Final resort DMI (sysfs then dmidecode if sysfs missing)
    const int sys_dmi_rc = Check_DMI_Legacy();
    if (sys_dmi_rc == VMWARE || sys_dmi_rc == XEN || sys_dmi_rc == PAR)
        return VM;

    if (sys_dmi_rc == -1) // sysfs DMI not available -> try dmidecode
    {
        const int dmi_decode = Check_DMIdecode_Legacy();
        if (dmi_decode == VMWARE || dmi_decode == XEN || dmi_decode == PAR)
            return VM;
    }

    copy_magic(_HVID, NOTFOUND_STR);
    return BAREMETAL;
#endif
}
