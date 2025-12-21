cmake_minimum_required(VERSION 3.16)
project(linux_vm_detector CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(UNIX AND NOT APPLE)
    add_executable(linux-vm-detect
        src/linux/main.cpp
        src/linux/LinuxBlueRedPill.cpp
    )
    target_include_directories(linux-vm-detect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/linux)

    add_subdirectory(src/linux/safedetect/linux-vm-detector-safe)
    
endif()

if(WIN32)
    if(NOT MSVC)
        message(FATAL_ERROR "Windows build requires MSVC (Build Tools + Windows SDK).")
    endif()

    add_library(windows-vm-detector STATIC
        src/windows/WindowsVMDetector.cpp
        src/windows/WindowsVMDetector.h
    )
    target_include_directories(windows-vm-detector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/windows)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        enable_language(ASM_MASM)
        set_source_files_properties(
            src/windows/WindowsMASM64VmwarePortDetector.asm
            PROPERTIES LANGUAGE ASM_MASM
        )
        target_sources(windows-vm-detector PRIVATE
            src/windows/WindowsMASM64VmwarePortDetector.asm
        )
    endif()

    add_executable(windows-vm-detect
        src/windows/windowsmain.cpp
    )
    target_link_libraries(windows-vm-detect PRIVATE windows-vm-detector)
endif()
