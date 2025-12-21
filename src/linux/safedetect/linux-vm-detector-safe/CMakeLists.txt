add_executable(linux-safe-vm-detect
    main_safe.cpp
    LinuxSafeVMDetector.cpp
)

target_include_directories(linux-safe-vm-detect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
