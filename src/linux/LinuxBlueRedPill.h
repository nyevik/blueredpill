/**
 * @file    LinuxBlueRedPill.h
 * @author  Nikolay Yevik
 * @date    2025-12-20
 *
 * @brief Detect (best-effort) whether the current Linux process runs inside a VM/hypervisor.
 *
 * The public class name and overall return semantics:
 * - LinuxVMHyperDetector::IsVM() returns VM (1) or BAREMETAL (0).
 * - LinuxVMHyperDetector::GetHypervisorName() returns a 12-char vendor magic string (when known),
 *   or "NOTFOUND".
 *  EXPERIMENTAL! FOR SAFER AND MORE TRADITIONAL VM DETECTION USE *_Modern() METHODS and/or 
 *  code in linux-safe-vm-detect.
 *
 * Features:
 *  - Standalone.
 *  - GCC 15.2, -std=c++23, -fPIC friendly.
 *  - Brittle methods marked  *_Legacy() and documented as brittle in Doxygen.
 *  - Modern methods added as *_Modern() and used by default.
 *  - Avoid popen(); provide a fork/exec+waitpid capture helper instead, to prevent zombie processes.
 *
 * IMPORTANT NOTE:
 *   VM detection is inherently probabilistic. A sufficiently configured hypervisor
 *   can hide many signals. This code reports best-effort evidence and tries to name
 *   the hypervisor where reasonably supported by multiple signals.
 */

#ifndef LINUXBLUEREDPILL_H
#define LINUXBLUEREDPILL_H

#include <cstdint>
#include <string>
#include <vector>

/** Typical magic string length including terminating null. */
#define HV_BRAND_MAX_NAME_LEN 13
using u64 = unsigned long long;  

/**
 * Enable risky legacy probes (default: 0).
 *
 * @warning These legacy probes can crash or behave unexpectedly on bare metal, or
 *          on unusual hypervisors/hardware configurations:
 *          - VMware I/O port probe (the "backdoor" port)
 *          - Xen PV ud2a "xen" CPUID hook
 *
 * If you enable this, prefer to do it only after other methods already strongly
 * indicate you're inside a VM. Otherwise, you may trigger unexpected behavior on bare metal, like SIGSEGV.
 */
#ifndef LVMHVD_ENABLE_RISKY_LEGACY_PROBES
#define LVMHVD_ENABLE_RISKY_LEGACY_PROBES 1 /**< Enable risky legacy probes by default !!!!!!!*/
#endif

/**
 * @brief Minimal interface.
 *
 * This interface defines the minimal contract for a VM/Hypervisor detector.
 * Implementations should provide methods to determine if the current environment
 * is a virtual machine and to retrieve the hypervisor's vendor string if available.
 */
class IVMHyperDetector
{
public:
    virtual ~IVMHyperDetector() = default;
    virtual int IsVM() = 0;
    virtual std::string GetHypervisorName() = 0;
};

/**
 * @brief VM / Hypervisor detector for x86_64 Linux (best-effort).
 *
 * Supported / recognized hypervisors (best-effort):
 * - VMware
 * - VirtualBox
 * - Hyper-V
 * - Xen
 * - KVM/QEMU
 * - Parallels
 * - bhyve (best-effort)
 *
 * @note A hypervisor can spoof or hide signals. No "red pill" exists that is
 *       universally definitive.
 */
class LinuxVMHyperDetector : public IVMHyperDetector
{
public:

    explicit LinuxVMHyperDetector();/**constructor, no implicit conversions,initializes internal state */
    ~LinuxVMHyperDetector() override = default; /**<destructor, defaulted */

    /**
     * @brief Default entry point (kept for backward compatibility).
     *
     * By default this calls IsVM_Modern() and only falls back to IsVM_Legacy()
     * when explicitly requested via IsVM_Legacy() or if you wire it yourself.
     */
    int IsVM() override; /**<default entry point, calls IsVM_Modern() by default */

    /**
     * @brief Modern implementation: no inline-asm, no popen().
     *
     * Uses CPUID intrinsics, sysfs/procfs signals, optional helper tools if present.
     * Safer, more warning-free under modern toolchains.
     */
    int IsVM_Modern();

    /**
     * @brief Legacy implementation preserved from the 2012 code.
     *
     * @warning BRITTLE:
     * - uses inline assembly hooks (Xen PV check)
     * - optionally uses VMware I/O port probe (can misbehave on bare metal)
     * - used to rely on popen(); still available as legacy
     *
     * This method is retained for compatibility and for environments where
     * modern signals are intentionally hidden but legacy ones still surface.
     */
    int IsVM_Legacy();

    /**
     * @brief Return the detected hypervisor vendor magic string.
     *
     * If known, this is typically one of:
     * - "VMwareVMware" // VMware
     * - "XenVMMXenVMM" // Xen
     * - "KVMKVMKVM" // KVM/QEMU
     * - "Microsoft Hv" // Hyper-V
     * - "VBoxVBoxVBox" // VirtualBox
     * - "bhyve bhyve " // bhyve "BSD hypervisor"
     * Otherwise: "NOTFOUND"
     */
    std::string GetHypervisorName() override;

    /**
     * @brief Optional: return human-readable evidence collected by IsVM_Modern().
     *
     * Intended for CLI output / diagnostics and later GUI wrapping.
     */
    std::vector<std::string> GetEvidence() const;

private:
    // ---- Original enums (kept; values matter for return semantics) ----
    enum Box { BAREMETAL = 0, VM = 1 };
    enum VMs { NOTFOUND = 0, VMWARE = 1, XEN = 2, KVM = 3, PAR = 4, QEMU = 5, HYPERV = 6, VBOX = 7, BHYVE = 8 };
    enum XenMode { XEN_PV = 1, XEN_HVM = 2, XEN_NONE = 3 };

    // ---- Shared state ----
    char _HVID[HV_BRAND_MAX_NAME_LEN];              ///< vendor magic string, NUL-terminated
    std::vector<std::string> _evidence_modern;      ///< evidence collected by modern path

    // ---- Modern helpers ----
    static bool Cpuid_Modern(uint32_t leaf, uint32_t subleaf, uint32_t &eax, uint32_t &ebx, uint32_t &ecx, uint32_t &edx);
    static bool ReadTextFile_Modern(const std::string &path, std::string &out, size_t maxBytes = 64 * 1024);
    static std::string Trim_Modern(std::string s);
    static bool ContainsIcase_Modern(const std::string &haystack, const std::string &needle);
    /**
     * @brief Get the value of the RCX register.
     * @return The current value of the RCX register.
     */
    static u64 getRCX(void)
    {
        u64 value = 0;
        // Capture RCX into a C++ variable and return it.
        // Note: Using "pop %rcx" here would corrupt the stack; do not do that.
        __asm__ volatile("mov %%rcx, %0" : "=r"(value));
        return value;
    }//end getRCX()

private:
    struct ExecResult
    {
        int exit_code = -1;              ///< process exit code (or -1 if not started)
        std::string stdout_data;         ///< captured stdout (best-effort)
        std::string stderr_data;         ///< captured stderr (best-effort)
    };

    /**
     * @brief Run a program (argv[0]) without invoking a shell; capture stdout/stderr; waitpid().
     *
     * This is the recommended alternative to popen() for robust process control:
     * - no shell expansion
     * - clear error reporting
     * - no zombies (waitpid)
     */
    static ExecResult ExecCapture_Modern(const std::vector<std::string> &argv, int timeout_seconds = 10);

    static bool PathExists_Modern(const std::string &path);

    int DetectViaCpuid_Modern(std::string &vendor_magic_out);
    int DetectViaDmiSysfs_Modern(std::string &vendor_magic_out);
    int DetectViaXenSysfs_Modern(std::string &vendor_magic_out);
    int DetectViaGuestDrivers_Modern(std::string &vendor_magic_out);
    int DetectViaCpuInfo_Modern(std::string &vendor_magic_out);
    int DetectViaHelperTools_Modern(std::string &vendor_magic_out);

    void SetVendorMagic_Modern(const std::string &magic);

    // ---- Legacy helpers (preserved; annotated as brittle) ----

    /**
     * @brief Xen-specific inline assembly CPUID hook (legacy).
     *
     * @warning BRITTLE: relies on Xen PV/HVM behavior and inline asm constraints.
     */
    void Xen_CPUID_Legacy(uint32_t idx, uint32_t *regs, int pv_context);

    /**
     * @brief Generic CPUID (legacy inline asm).
     *
     * @warning BRITTLE under -fPIC and aggressive optimization; modern code uses cpuid.h intrinsics.
     */
    unsigned int CPUID_Legacy(unsigned int eax, char *sig);

    /**
     * @brief Xen HVM/PV detection (legacy).
     *
     * @warning BRITTLE; uses Xen_CPUID_Legacy and may SIGILL in non-Xen contexts.
     */
    int Check_For_Xen_Legacy(int pv_context);

    /**
     * @brief VMware I/O port probe (legacy).
     *
     * @warning RISKY: Must not be run on bare metal. Controlled by LVMHVD_ENABLE_RISKY_LEGACY_PROBES.
     */
    int VMware_HV_Port_Check_Legacy();

    /**
     * @brief Try reading sysfs DMI vendor (legacy).
     *
     * Reads /sys/devices/virtual/dmi/id/sys_vendor (or similar).
     */
    int Check_DMI_Legacy();

    /**
     * @brief Try running dmidecode (legacy).
     *
     * @warning BRITTLE: dmidecode generally requires root; runs in a worker thread.
     */
    int Check_DMIdecode_Legacy();

    /**
     * @brief Check /proc/cpuinfo for QEMU strings (legacy).
     */
    int CheckProcCPUInfo4QEMU_Legacy();

    /**
     * @brief VMware checkvm tool (legacy).
     *
     * @warning BRITTLE: depends on external tool (vmware-checkvm) being present.
     */
    int VmwareCheckVM_Legacy();
};

#endif /* LINUXVMDETECTOR_H */
