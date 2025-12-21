
# MIT License

Copyright (c) 2025 blueredpill contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# BLUEREDPILL: HEURISTIC VM DETECTION (EXPERIMENTAL)
    TAKE THE RED PILL. BUT NOT A SILVER BULLET.

## Status and safety
- Experimental, work in progress. The code works in its current state, but interfaces and behavior may change.
- For safer usage, prefer the code under `src/linux/safedetect/` (documented host signals; no risky probes).
- The BlueRedPill detector in `src/linux/` is experimental. Use at your own risk; no responsibility is assumed for its use.
- This is a word play on the blue pill vs red pill in The Matrix: the "red pill" wakes you up, but there is no red pill or silver bullet that can identify all VMs/hypervisors.
- VM detection is heuristic in nature. Hypervisors can hide signals, nested VMs exist, and results should be treated as a probability or confidence level, not a guarantee.

## Build / run (CLI)
Linux (CMake):
- cmake -S . -B build
- cmake --build build -j
- ./build/linux-vm-detect --evidence
- ./build/src/linux/safedetect/linux-vm-detector-safe/linux-safe-vm-detect --evidence
- cmake --build build --target linux-safe-vm-detect -j

Windows (MSVC + ml64):
- cmake -S . -B build -G "Visual Studio 17 2022" -A x64
- cmake --build build --config Release
- .\\build\\Release\\windows-vm-detect.exe

## Direct compile
- g++ -std=c++23 -O2 -Wall -Wextra -Wpedantic -fPIC src/linux/LinuxBlueRedPill.cpp src/linux/main.cpp -o linux-vm-detect
- ./linux-vm-detect --evidence
- g++ -std=c++23 -O2 -Wall -Wextra -Wpedantic -fPIC src/linux/safedetect/linux-vm-detector-safe/LinuxSafeVMDetector.cpp src/linux/safedetect/linux-vm-detector-safe/main_safe.cpp -o linux-safe-vm-detect
- ./linux-safe-vm-detect --evidence

## Notes
Inline assembly works for some CPUID tricks, but it is brittle on modern GCC/toolchains (especially with -fPIC, register constraints, LTO, and different ABIs). Using CPUID intrinsics (<cpuid.h> / __cpuid_count) is safer, cleaner, more portable across GCC/Clang, and less likely to break under optimization. Inline assembly is kept only as legacy; the default path uses intrinsics.
