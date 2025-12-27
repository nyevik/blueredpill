/**
 * @author  Nikolay Yevik
 * @file    main.cpp
 * @brief   CLI wrapper around LinuxVMHyperDetector.
 */
#include "LinuxBlueRedPill.h"
#include <iostream>

int main(int argc, char** argv)
{
    const bool show_evidence = (argc > 1) && std::string(argv[1]) == "--evidence";

    LinuxVMHyperDetector d;
    const int is_vm = d.IsVM(); // modern by default
    const int is_vm_legacy = d.IsVM_Legacy(); // try legacy path
    
    std::cout << (is_vm ? "VM" : "BAREMETAL") << "\n";
    std::cout << d.GetHypervisorName() << "\n";

    std::cout << "Legacy path: " << (is_vm_legacy ? "VM" : "BAREMETAL") << "\n";

    if (show_evidence)
    {
        for (const auto &e : d.GetEvidence())
            std::cout << "- " << e << "\n";
    }
   
    return is_vm ? 0 : 1;
}
