/**
 * @file    LinuxSafeVMDetector.cpp
 * @author  Nikolay Yevik
 * @date    2025-12-20
 *
 * @brief Safe VM detection for Linux (BEST_EFFORT).
 *
 * This implementation provides safer alternatives to legacy VM detection methods,
 * avoiding risky inline assembly and popen() usage. It relies on reading sysfs/procfs
 * signals, CPUID intrinsics, and optional helper tools if available.
 */

#include "LinuxSafeVMDetector.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{
    /**
     * @brief Append a string to a vector if the optional string is present and non-empty.
     *
     * This helper function checks if the provided optional string is non-empty and, if so,
     * appends it to the given vector with the specified prefix.
     * @pre v is a valid vector, s is a valid optional string, prefix is a valid string
     * @post If s is non-empty, v contains a new element equal to prefix + *s
     * @related LinuxSafeVMHyperDetector::GetEvidence
     * @related LinuxSafeVMHyperDetector::ReadFirstLine
     * @related LinuxSafeVMHyperDetector::ReadAll
     * @related LinuxSafeVMHyperDetector::FileExists
     * @related LinuxSafeVMHyperDetector::IContains
     * @related LinuxSafeVMHyperDetector::AppendIf
     * @related LinuxSafeVMHyperDetector::Clamp100
     * @related LinuxSafeVMHyperDetector::ExecCapture
     * @remarks This function is intended to simplify the process of conditionally appending strings
     *          to a vector, reducing boilerplate code and improving readability when collecting
     *          evidence or other optional data.
     * @note This function does not modify the input vector if the optional string is empty or not present.
     * @note This function is thread-safe as it does not modify any shared state.
     * @note The prefix is always prepended to the string before appending, even if the string is empty.
     * @note This function does not throw exceptions.
     * @throws None
     * @param v The vector to append to.
     * @param s The optional string to append.
     * @param prefix A prefix to prepend to the string before appending.
     * @return void
     */
    void AppendIf(std::vector<std::string>& v, const std::optional<std::string>& s, const std::string& prefix)
    {
        if (s && !s->empty())
            v.push_back(prefix + *s);
    }

    int Clamp100(int x) /**< Clamp the input value to the range [0, 100] */
    {
        if (x < 0) return 0;
        if (x > 100) return 100;
        return x;
    }
}//end of anonymous namespace

/**
 * @brief Checks if a file exists at the specified path.
 *
 * This function uses the access() system call to determine if the file exists.
 * It returns true if the file exists, false otherwise.
 *
 * @param path The path to the file to check.
 * @return true if the file exists, false otherwise.
 * @note This function is thread-safe as it does not modify any shared state.
 * @throws None
 * @note This helper function does not follow symbolic links; 
 *       it only checks the existence of the file at the specified path.
 */
bool LinuxSafeVMHyperDetector::FileExists(const std::string& path)
{
    return ::access(path.c_str(), F_OK) == 0;
}

std::string LinuxSafeVMHyperDetector::Trim(std::string s)
{
    auto is_space = [](unsigned char c){ return std::isspace(c) != 0; };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](unsigned char c){ return !is_space(c); }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [&](unsigned char c){ return !is_space(c); }).base(), s.end());
    return s;
}

bool LinuxSafeVMHyperDetector::IContains(const std::string& haystack, const std::string& needle)
{
    auto lower = [](std::string x){
        std::transform(x.begin(), x.end(), x.begin(),
                       [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        return x;
    };
    return lower(haystack).find(lower(needle)) != std::string::npos;
}

std::optional<std::string> LinuxSafeVMHyperDetector::ReadFirstLine(const std::string& path)
{
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::nullopt;

    std::string buf;
    buf.resize(4096);
    ssize_t n = ::read(fd, buf.data(), buf.size() - 1);
    ::close(fd);
    if (n <= 0) return std::nullopt;

    buf.resize(static_cast<size_t>(n));
    auto pos = buf.find('\n');
    if (pos != std::string::npos)
        buf.resize(pos);
    return Trim(buf);
}

std::optional<std::string> LinuxSafeVMHyperDetector::ReadAll(const std::string& path)
{
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::nullopt;

    std::string out;
    std::array<char, 8192> tmp{};
    for (;;)
    {
        ssize_t n = ::read(fd, tmp.data(), tmp.size());
        if (n == 0) break;
        if (n < 0)
        {
            if (errno == EINTR) continue;
            ::close(fd);
            return std::nullopt;
        }
        out.append(tmp.data(), static_cast<size_t>(n));
    }
    ::close(fd);
    return out;
}

LinuxSafeVMHyperDetector::ExecResult LinuxSafeVMHyperDetector::ExecCapture(const std::vector<std::string>& argv)
{
    ExecResult r;
    if (argv.empty())
        return r;

    int out_pipe[2]{-1,-1};
    int err_pipe[2]{-1,-1};

    if (::pipe2(out_pipe, O_CLOEXEC) != 0) return r;
    if (::pipe2(err_pipe, O_CLOEXEC) != 0)
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

        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const auto& s : argv)
            cargv.push_back(const_cast<char*>(s.c_str()));
        cargv.push_back(nullptr);

        ::execvp(cargv[0], cargv.data());
        _exit(127);
    }

    // parent
    ::close(out_pipe[1]);
    ::close(err_pipe[1]);

    auto read_fd = [](int fd) -> std::string {
        std::string out;
        std::array<char, 4096> buf{};
        for (;;)
        {
            ssize_t n = ::read(fd, buf.data(), buf.size());
            if (n == 0) break;
            if (n < 0)
            {
                if (errno == EINTR) continue;
                break;
            }
            out.append(buf.data(), static_cast<size_t>(n));
        }
        return out;
    };

    r.out = read_fd(out_pipe[0]);
    r.err = read_fd(err_pipe[0]);

    ::close(out_pipe[0]);
    ::close(err_pipe[0]);

    int status = 0;
    if (::waitpid(pid, &status, 0) == pid)
    {
        if (WIFEXITED(status))
            r.exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status))
            r.exit_code = 128 + WTERMSIG(status);
    }
    return r;
}

bool LinuxSafeVMHyperDetector::LooksLikeContainerVendor(const std::string& v)
{
    // systemd-detect-virt container strings are usually: docker, podman, lxc, systemd-nspawn, openvz, ...
    static const char* k[] = {"docker","podman","lxc","lxd","nspawn","systemd-nspawn","openvz","wsl"};
    for (auto* s : k) if (IContains(v, s)) return true;
    return false;
}

bool LinuxSafeVMHyperDetector::LooksLikeVMVendor(const std::string& v)
{
    static const char* k[] = {"kvm","qemu","vmware","microsoft","hyper-v","xen","virtualbox","oracle","bhyve","parallels"};
    for (auto* s : k) if (IContains(v, s)) return true;
    return false;
}

LinuxSafeVMHyperDetector::DetectResult LinuxSafeVMHyperDetector::Detect_Modern()
{
    DetectResult res;
    res.kind = VirtKind::Unknown;
    res.vendor.clear();
    res.confidence_percent = 0;
    res.evidence.clear();

    int score = 0;

    // (A) systemd-detect-virt (if installed)
    {
        ExecResult sdv = ExecCapture({"systemd-detect-virt"});
        std::string out = Trim(sdv.out);
        if (!out.empty())
        {
            res.evidence.push_back("systemd-detect-virt: " + out);
            if (out != "none")
            {
                res.vendor = out;
                if (LooksLikeContainerVendor(out))
                {
                    res.kind = VirtKind::Container;
                    score += 60;
                }
                else
                {
                    res.kind = VirtKind::VM;
                    score += 60;
                }
            }
            else
            {
                if (res.kind == VirtKind::Unknown) res.kind = VirtKind::BareMetal;
            }
        }
    }

    // (B) sysfs DMI strings (no root required to read on most distros)
    {
        auto sys_vendor   = ReadFirstLine("/sys/class/dmi/id/sys_vendor");
        auto product_name = ReadFirstLine("/sys/class/dmi/id/product_name");
        auto bios_vendor  = ReadFirstLine("/sys/class/dmi/id/bios_vendor");

        if (sys_vendor)   res.evidence.push_back("dmi sys_vendor: " + *sys_vendor);
        if (product_name) res.evidence.push_back("dmi product_name: " + *product_name);
        if (bios_vendor)  res.evidence.push_back("dmi bios_vendor: " + *bios_vendor);

        std::string combined;
        if (sys_vendor) combined += *sys_vendor + " ";
        if (product_name) combined += *product_name + " ";
        if (bios_vendor) combined += *bios_vendor;

        if (!combined.empty())
        {
            // Very common VM strings
            if (IContains(combined, "vmware") || IContains(combined, "virtualbox") ||
                IContains(combined, "qemu")   || IContains(combined, "kvm") ||
                IContains(combined, "xen")    || IContains(combined, "microsoft"))
            {
                if (res.kind == VirtKind::Unknown || res.kind == VirtKind::BareMetal)
                    res.kind = VirtKind::VM;
                score += 25;

                if (res.vendor.empty())
                {
                    // choose a stable vendor label
                    if (IContains(combined, "vmware")) res.vendor = "vmware";
                    else if (IContains(combined, "virtualbox") || IContains(combined, "innotek")) res.vendor = "virtualbox";
                    else if (IContains(combined, "xen")) res.vendor = "xen";
                    else if (IContains(combined, "microsoft")) res.vendor = "hyper-v";
                    else if (IContains(combined, "kvm")) res.vendor = "kvm";
                    else if (IContains(combined, "qemu")) res.vendor = "qemu";
                }
            }
        }
    }

    // (C) /sys/hypervisor/type and Xen markers
    {
        auto hyp_type = ReadFirstLine("/sys/hypervisor/type");
        if (hyp_type && !hyp_type->empty())
        {
            res.evidence.push_back("/sys/hypervisor/type: " + *hyp_type);
            if (res.kind == VirtKind::Unknown || res.kind == VirtKind::BareMetal)
                res.kind = VirtKind::VM;
            score += 25;
            if (res.vendor.empty())
                res.vendor = *hyp_type;
        }

        if (FileExists("/proc/xen") || FileExists("/proc/xen/capabilities"))
        {
            res.evidence.push_back("xen procfs marker: present");
            if (res.kind == VirtKind::Unknown || res.kind == VirtKind::BareMetal)
                res.kind = VirtKind::VM;
            score += 20;
            if (res.vendor.empty())
                res.vendor = "xen";
        }
    }

    // (D) CPU "hypervisor" flag in /proc/cpuinfo (weak-ish, but useful)
    {
        auto cpuinfo = ReadAll("/proc/cpuinfo");
        if (cpuinfo && IContains(*cpuinfo, " hypervisor"))
        {
            res.evidence.push_back("/proc/cpuinfo flags: includes 'hypervisor'");
            if (res.kind == VirtKind::Unknown || res.kind == VirtKind::BareMetal)
                res.kind = VirtKind::VM;
            score += 15;
        }
    }

    // (E) virt-what (optional, if installed)
    {
        ExecResult vw = ExecCapture({"virt-what"});
        std::string out = Trim(vw.out);
        if (!out.empty())
        {
            res.evidence.push_back("virt-what: " + out);
            if (res.kind == VirtKind::Unknown || res.kind == VirtKind::BareMetal)
                res.kind = VirtKind::VM;
            score += 25;
            if (res.vendor.empty())
            {
                // virt-what can output multiple lines; take first token
                auto pos = out.find_first_of(" \n\r\t");
                res.vendor = (pos == std::string::npos) ? out : out.substr(0, pos);
            }
        }
    }

    // Finalize kind if still unknown
    if (res.kind == VirtKind::Unknown)
        res.kind = VirtKind::BareMetal;

    // If vendor still empty, set to "none" (consistent with systemd-detect-virt)
    if (res.vendor.empty())
        res.vendor = (res.kind == VirtKind::BareMetal) ? "none" : "unknown";

    res.confidence_percent = Clamp100(score);

    last_result_ = res;
    return res;
}

int LinuxSafeVMHyperDetector::IsVM()
{
    DetectResult r = Detect_Modern();
    return (r.kind == VirtKind::VM) ? VM : BAREMETAL;
}
