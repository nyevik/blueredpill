#include "LinuxSafeVMDetector.h"
#include <iostream>

static const char* KindToStr(LinuxSafeVMHyperDetector::VirtKind k)
{
    using K = LinuxSafeVMHyperDetector::VirtKind;
    switch (k)
    {
        case K::BareMetal: return "bare-metal";
        case K::VM:        return "vm";
        case K::Container: return "container";
        default:           return "unknown";
    }
}

int main(int argc, char** argv)
{
    bool show_evidence = false;
    for (int i = 1; i < argc; ++i)
    {
        std::string a = argv[i];
        if (a == "--evidence" || a == "-e") show_evidence = true;
    }

    LinuxSafeVMHyperDetector det;
    auto r = det.Detect_Modern();

    std::cout << "kind=" << KindToStr(r.kind)
              << " vendor=" << r.vendor
              << " confidence=" << r.confidence_percent << "%\n";

    if (show_evidence)
    {
        for (const auto& e : r.evidence)
            std::cout << "  - " << e << "\n";
    }

    return r.is_virtualized() ? 0 : 1;
}
