/**
 * @file   WindowsVMHyperDetector.h
 * @author Nikolay Yevik
 * @date    
 */

#ifndef WINDOWSVMDETECTOR_H
#define WINDOWSVMDETECTOR_H

#include <string>

#define HV_BRAND_MAX_NAME_LEN 13

class IVMHyperDetector
{
	public:
        virtual std::string GetHypervisorName() = 0;
        virtual int IsVM() = 0;
        virtual ~IVMHyperDetector() { }
};


/**
 * @brief 
 * This class attempts to detect whether an agent runs on a VM.
 * The following VMs are supported:
 * Xen;
 * VMware;
 * KVM/QEMU;
 * MS HyperV.
 * Since I am not aware of any "red pill" or "silver bullet" approach that would definitively 
 * and universally determine whether program runs within any VM or not, detection 
 * has to be done for each specific VM.
 * If code fails to determine that this is a !*SUPPORTED*! VM, class returns that
 * agent runs on bare metal.
 * @see WindowsVMDetector.cpp for more info. 
 */
class WindowsVMHyperDetector : public IVMHyperDetector
{
	public:
        WindowsVMHyperDetector();

        virtual ~WindowsVMHyperDetector();
        
        int IsVM();

		std::string GetHypervisorName();
        
   private:
       void CPUID_Check(unsigned int opl, int * CPUInfo);

#ifdef _M_IX86
	   bool VMware_HV_Port_Check32bit(); // Checks for VMware hypervisor using 32-bit port I/O, RISKY! Requires inline assembly.
#endif

#ifdef _M_X64
	   bool VMware_HV_Port_Check64bit(); // Checks for VMware hypervisor using 64-bit port I/O, RISKY! Requires MASM64 external assembly.
#endif

	   char _HVID[HV_BRAND_MAX_NAME_LEN];
        
	   enum Box{BAREMETAL, VM};
        
       enum VMs {NOTFOUND, VMWARE, XEN, KVM, PAR, QEMU, HYPERV};//kept the same as Linux code for consistency  

    
};
#endif   /* WINDOWSVMDETECTOR_H */



