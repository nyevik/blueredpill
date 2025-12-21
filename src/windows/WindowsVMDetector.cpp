/** 
 * @file    WindowsVMHyperDetector.cpp
 * @author  Nikolay YEvik
 *
 */


#include <algorithm>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <bitset>
#include <cstring>
#include <cstddef>
#include <stdio.h>

// --- Portable strcpy_s compatibility ----------------------------------------
// MSVC provides strcpy_s plus an overload that deduces the destination size for
// fixed-size arrays. Many non-MSVC toolchains don't. Provide a minimal fallback
// that preserves the existing call sites in this file.
#if !defined(_MSC_VER) && !defined(__STDC_LIB_EXT1__)
	static inline int strcpy_s(char* dest, std::size_t destsz, const char* src)
	{
		if (!dest || destsz == 0) return 0;
		if (!src) { dest[0] = '\0'; return 0; }
		std::strncpy(dest, src, destsz - 1);
		dest[destsz - 1] = '\0';
		return 0;
	}

	template <std::size_t N>
	static inline int strcpy_s(char (&dest)[N], const char* src)
	{
		return strcpy_s(dest, N, src);
	}
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(_M_IX86) || defined(_M_X64)
#include <windows.h>
#include <eh.h>
#include <intrin.h>

// For non-MSVC toolchains, provide CPUID support.
// (e.g., MinGW/Clang/GCC may not expose MSVC's __cpuid intrinsic.)
#if defined(__GNUC__) || defined(__clang__)
	#include <cpuid.h>
#endif

#endif

#include "WindowsVMDetector.h"

// Small wrapper to make CPUID work across MSVC and GCC/Clang.
static inline void WVMD_cpuid(int out[4], unsigned int leaf)
{
#if defined(_MSC_VER)
	// MSVC intrinsic (declared in <intrin.h>) - only available on x86/x64.
	#if defined(_M_IX86) || defined(_M_X64)
		__cpuid(out, static_cast<int>(leaf));
	#else
		out[0] = out[1] = out[2] = out[3] = 0;
	#endif
#elif defined(__GNUC__) || defined(__clang__)
	// GCC/Clang: CPUID is only valid on x86/x64.
	#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
		unsigned int a = 0, b = 0, c = 0, d = 0;
		// Prefer <cpuid.h> helpers when present.
		#if defined(__cpuid_count)
			__cpuid_count(leaf, 0, a, b, c, d);
		#elif defined(__get_cpuid)
			// __get_cpuid uses subleaf 0 (which is what we need here).
			__get_cpuid(leaf, &a, &b, &c, &d);
		#elif (defined(_WIN32) || defined(_WIN64)) && defined(__cpuidex)
			// MinGW may provide __cpuidex via <intrin.h>.
			int regs[4] = {0, 0, 0, 0};
			__cpuidex(regs, static_cast<int>(leaf), 0);
			a = static_cast<unsigned int>(regs[0]);
			b = static_cast<unsigned int>(regs[1]);
			c = static_cast<unsigned int>(regs[2]);
			d = static_cast<unsigned int>(regs[3]);
		#else
			// Last-resort inline asm for toolchains without cpuid helpers.
			#if defined(__i386__) || defined(__x86_64__)
				__asm__ __volatile__(
					"cpuid"
					: "=a"(a), "=b"(b), "=c"(c), "=d"(d)
					: "a"(leaf), "c"(0)
				);
			#else
				a = b = c = d = 0;
			#endif
		#endif
		out[0] = static_cast<int>(a);
		out[1] = static_cast<int>(b);
		out[2] = static_cast<int>(c);
		out[3] = static_cast<int>(d);
	#else
		out[0] = out[1] = out[2] = out[3] = 0;
	#endif
#else
	// Unsupported compiler/toolchain for CPUID.
	out[0] = out[1] = out[2] = out[3] = 0;
#endif
}

// __FUNCSIG__ is MSVC-specific; provide a portable function signature macro.
#if !defined(WVMD_FUNC_SIG)
	#if defined(_MSC_VER)
		#define WVMD_FUNC_SIG __FUNCSIG__
	#elif defined(__GNUC__) || defined(__clang__)
		#define WVMD_FUNC_SIG __PRETTY_FUNCTION__
	#else
		#define WVMD_FUNC_SIG __func__
	#endif
#endif

#define VMWARE_SHORT_STR "VMware"
#define VMWARE_VMXNET "VMXNET"
#define HYPERV_MAGIC_STR "Microsoft Hv" //!*Xen might emulate HyperV*!
#define VMWARE_MAGIC_STR "VMwareVMware"
#define XEN_MAGIC_STR "XenVMMXenVMM"
#define KVM_MAGIC_STR "KVMKVMKVM"
#define NOTFOUND_STR "NOTFOUND"

#ifdef _M_X64
extern "C" { /** External code written in MASM64  AMD64 assembly, s
			 ince MS VS d not support 64-bit inline assembly, 
			 and MS provided intrinsics do no give needed results. */
bool asmvmwarepd(void);/**;---MASM 64bit native protected mode 
						VMware Port Checking Procedure (vmpd64.asm)*/
}
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(_M_IX86) || defined(_M_X64)
namespace WVMD
{
	struct SEHException {
	  SEHException(const EXCEPTION_RECORD & record) : record(record) {}
	  EXCEPTION_RECORD record;
	};

	void translator_function(unsigned int, EXCEPTION_POINTERS * eps) {
	  throw SEHException(*eps->ExceptionRecord);
	}
}
#endif

WindowsVMHyperDetector::WindowsVMHyperDetector()
{
    memset(_HVID,0,HV_BRAND_MAX_NAME_LEN);
	std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << std::endl;
}


WindowsVMHyperDetector::~WindowsVMHyperDetector()
{
	std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << std::endl;
}



#ifdef _M_X64
bool
WindowsVMHyperDetector::VMware_HV_Port_Check64bit()
{
	bool result = true;
	
	__try { result = asmvmwarepd(); }
	__except(EXCEPTION_EXECUTE_HANDLER){ result = false; }

	if (result)
		strcpy_s(_HVID, VMWARE_MAGIC_STR);
	else
		strcpy_s(_HVID, NOTFOUND_STR);


	return result;
}
#endif





#ifdef _M_IX86
bool 
WindowsVMHyperDetector::VMware_HV_Port_Check32bit()
{
  bool rc = true;

  __try
  {
    __asm
    {
      push   edx
      push   ecx
      push   ebx

      mov    eax, 'VMXh'
      mov    ebx, 0 // any value but not the MAGIC VALUE
      mov    ecx, 10 // get VMWare version(0xA)
      mov    edx, 'VX' // port number

      in     eax, dx // read port, on bare metal priviledged opcode exception
                     // on return EAX returns the VERSION
      cmp    ebx, 'VMXh' // is it a reply from VMWare?
      setz   [rc] // set return value

      pop    ebx
      pop    ecx
      pop    edx
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    rc = false;
  }
  if (rc)
	  strcpy_s(_HVID, VMWARE_MAGIC_STR);
  else
	  strcpy_s(_HVID, NOTFOUND_STR);

  return rc;
}
#endif




std::string
WindowsVMHyperDetector::GetHypervisorName()
{
	std::string vm_hv_name;
 
    vm_hv_name = _HVID;    
	std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Returning VM name:" << vm_hv_name << std::endl;
    return vm_hv_name;
}




void
WindowsVMHyperDetector::CPUID_Check(unsigned int opl, int CPUInfo[4])
{   
	WVMD_cpuid(CPUInfo, opl);
    memcpy(_HVID + 0, &CPUInfo[1], 4);
    memcpy(_HVID + 4, &CPUInfo[2], 4);
    memcpy(_HVID + 8, &CPUInfo[3], 4);
    _HVID[HV_BRAND_MAX_NAME_LEN -1] = '\0';
}


int
WindowsVMHyperDetector::IsVM()
{
	bool hyperv_detect = false; /** might be Xen emulation */
    unsigned int b_l = 0;
    int CPUInfo[4] = {-1};
	std::ostringstream oss;
	bool r_b = false;


	/**  1. See if there are VM known magic strings in register leaves, cpuid opcode having been issued. */
	memset (_HVID, 0, sizeof _HVID);   
    CPUID_Check(0x1, CPUInfo);
	for ( b_l = 0x40000000; b_l < 0x40010000; b_l += 0x100 )
	{ 
		CPUID_Check(b_l, CPUInfo);
		if (!strcmp(_HVID, VMWARE_MAGIC_STR))
		{
			std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Returning VMware." << std::endl;
			return VM;
		}
		if (!strcmp(_HVID, XEN_MAGIC_STR) && (CPUInfo[0] >= (long long)(b_l + 0x2)) )
		{
			std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Returning indigenous Xen." << std::endl;
			return VM;
		}
		if (!strcmp(_HVID, HYPERV_MAGIC_STR))
		{
			std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":HyperV detected." << std::endl;
			hyperv_detect = true;
		}
		if ( !strcmp(_HVID, XEN_MAGIC_STR) )
		{
			std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Returning Xen with Viridian extensions." << std::endl;
			return VM;
		}
		if (!strcmp(_HVID, KVM_MAGIC_STR ))//This could be Parallels, QEMU, or Xen, or KVM
        {              
			/*Xen already should be determined at this point, 
			the rest is hard to determine on Windows, and we do not really care.*/
			std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Returning KVM." << std::endl;
			return VM;
		}
	}//end for()

	if (hyperv_detect)
	{
		strcpy_s(_HVID, HYPERV_MAGIC_STR);
		std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Returning HyperV." << std::endl;
		return VM;
	}

	
	/** 2. VMware port check by "in" opcode. */

	/** 32-bit inline assembly. */
#ifdef _M_IX86
	r_b = false;
	try {
		_set_se_translator(& WVMD::translator_function);
		r_b = VMware_HV_Port_Check32bit();
	}
	catch(WVMD::SEHException & e)
	{
		std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Exception 0x"
			<< std::hex << e.record.ExceptionCode << std::dec << std::endl;
	}
	if (r_b)
	{
		strcpy_s(_HVID, VMWARE_MAGIC_STR); //JIC
		std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":In VMware." << std::endl;
		return VM;
	}
	else{
		strcpy_s(_HVID, NOTFOUND_STR); //JIC
		std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Exc. Not in VMware." << std::endl;
	}
#endif




	/** MASM64 external assembly.*/
#ifdef _M_X64
	r_b = false;
	try {
		_set_se_translator(& WVMD::translator_function);
		r_b = VMware_HV_Port_Check64bit();
	}
	catch (WVMD::SEHException & e)
	{
		std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Exception 0x"
			<< std::hex << e.record.ExceptionCode << std::dec << std::endl;
	}
	if (r_b)
	{
		strcpy_s(_HVID, VMWARE_MAGIC_STR); //JIC
		std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Returning VMware." << std::endl;
		return VM;
	}
	else {
		strcpy_s(_HVID, NOTFOUND_STR); //JIC
		std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":Exc. Not in VMware." << std::endl;
	}
#endif
	

	
    /* Could not determine it's a supported VM, assuming baremetal.*/
	strcpy_s(_HVID, NOTFOUND_STR); //JIC
	std::cout << WVMD_FUNC_SIG << ":" << __LINE__ << ":VM was NOT detected. Returning BAREMETAL." << std::endl;
	return BAREMETAL;

} // end isVM()
