/**
 * @file    windowsmain.cpp
 * @brief   CLI wrapper around WindowsVMHyperDetector.
 */
#include "WindowsVMDetector.h"

#include <iostream>

int main()
{
    WindowsVMHyperDetector d;
    const int is_vm = d.IsVM();

    std::cout << (is_vm ? "VM" : "BAREMETAL") << "\n";
    std::cout << d.GetHypervisorName() << "\n";

    return is_vm ? 0 : 1;
}
