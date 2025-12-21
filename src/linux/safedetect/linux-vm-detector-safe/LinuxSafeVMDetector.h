/**
 * @author Nikolay Yevik
 * @file   LinuxSafeVMDetector.h
 * @brief  VM / container detection using standard, documented host signals.
 * Heuristic-based detection using evidence from the host system. NO SILVER BULLET.
 * This header defines the LinuxSafeVMHyperDetector class, which provides methods
 * to detect whether the host system is running on bare metal, a virtual machine,
 * or inside a container.
 *
 * This implementation is designed for legitimate sysadmin / diagnostics use:
 * - It collects evidence from sysfs/proc and (optionally) helper tools.
 * - It returns a structured result suitable for CLI or a Qt GUI wrapper.
 *
 * No "probe" techniques that can trip hardware or rely on undefined behavior are used here.
 */
#ifndef LINUX_SAFE_VM_DETECTOR_H
#define LINUX_SAFE_VM_DETECTOR_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class LinuxSafeVMHyperDetector
{
public:
    enum VM
    {
        BAREMETAL = 0, ///< Physical machine
        VM        = 1  ///< Virtual machine
    };

    enum class VirtKind : std::uint8_t
    {
        Unknown   = 0, ///< Unknown virtualization state
        BareMetal = 1, ///< Physical machine
        VM        = 2, ///< Virtual machine
        Container = 3  ///< Container
    };

    /**
     * @brief Aggregated result, suitable for UI.
     *
     * - vendor: best-effort vendor/type label (e.g. "kvm", "vmware", "docker", "none").
     * - confidence_percent: 0..100 heuristic derived from the strength/diversity of evidence.
     * - evidence: human-readable evidence strings ("source: value") for logging/UI.
     *
     * @note This is intentionally "explainable": confidence is never based on a single
     *       opaque probe. It is a heuristic score, not a guarantee.
     */
    struct DetectResult
    {
        VirtKind kind = VirtKind::Unknown;
        std::string vendor;
        int confidence_percent = 0;
        std::vector<std::string> evidence;

        bool is_virtualized() const { return kind == VirtKind::VM || kind == VirtKind::Container; }
        bool is_vm() const { return kind == VirtKind::VM; }
        bool is_container() const { return kind == VirtKind::Container; }
    };

    LinuxSafeVMHyperDetector() = default;
    ~LinuxSafeVMHyperDetector() = default;

    /**
     * @brief Backward-compatible entry point.
     * @return VM if a VM hypervisor is detected, else BAREMETAL.
     *
     * This does NOT report containers as VM.
     */
    int IsVM();

    /**
     * @brief Modern API returning a structured result.
     */
    DetectResult Detect_Modern();

    /**
     * @brief Convenience: last computed result (if Detect_Modern was called).
     */
    std::optional<DetectResult> LastResult() const { return last_result_; }

private:
    struct ExecResult
    {
        int exit_code = -1;
        std::string out;
        std::string err;
    };

    static bool FileExists(const std::string& path);
    static std::optional<std::string> ReadFirstLine(const std::string& path);
    static std::optional<std::string> ReadAll(const std::string& path);
    static std::string Trim(std::string s);
    static bool IContains(const std::string& haystack, const std::string& needle);

    /**
     * @brief Execute a program (no shell), capture stdout/stderr, wait to avoid zombies.
     *
     * @param argv  argv[0] must be executable name/path. argv must be non-empty.
     * @return ExecResult (exit_code == -1 on exec/fork error).
     */
    static ExecResult ExecCapture(const std::vector<std::string>& argv);

    static bool LooksLikeContainerVendor(const std::string& v);
    static bool LooksLikeVMVendor(const std::string& v);

    std::optional<DetectResult> last_result_;
};

#endif // LINUX_SAFE_VM_DETECTOR_H
