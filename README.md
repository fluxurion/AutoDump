# Reverse Engineering Toolkit

A comprehensive toolkit for process reverse engineering:
- **Stealth DLL Injector** - Reflective injection with thread hijacking
- **Helper DLL** - Dumps decrypted memory + extracts ALL offsets automatically

## Compilation

```bash
gcc -O2 -o injector.exe injector.c
gcc -O2 -shared -o helper.dll helper_dll.c
gcc -O2 -mwindows -o injector_gui.exe injector_gui.c -lcomctl32 -lcomdlg32
```

Or simply run the provided batch file:

```bash
compile.bat
```

### Output Files

| File | Description |
|------|-------------|
| `injector.exe` | CLI injector — run from command line |
| `helper.dll` | Stealth helper DLL — loaded reflectively |
| `injector_gui.exe` | Simple GUI launcher — browse for a target `.exe` and inject with one click |

## Usage

1. Place `injector.exe` and `helper.dll` in the same directory
2. Run as Administrator
3. Execute:
   ```
   .\injector.exe ourprocess.exe
   ```
4. Wait 2 minutes - the helper DLL will:
   - Track TLS callbacks
   - Decrypt and dump all memory
   - Extract ALL offsets (functions + globals)
   - Create output files in our target process directory

## Stealth & Anti-Detection Methods

### Injector (injector.c)

**Reflective DLL Injection:**
- Manual PE loading without `LoadLibrary`
- No entry in process module list
- PE sections written individually
- Relocations processed manually
- Imports resolved manually
- Memory zeroed after injection

**Thread Hijacking:**
- No new thread creation (avoids `CreateRemoteThread` detection)
- Selects existing worker thread with low CPU time
- Suspends thread, modifies RIP register, resumes
- Uses `NtAlertThread` to ensure execution

**Direct Syscalls:**
- `NtOpenProcess` - Bypasses `OpenProcess` hooks
- `NtAllocateVirtualMemory` - Direct memory allocation
- `NtWriteVirtualMemory` / `NtReadVirtualMemory` - Direct memory access
- `NtProtectVirtualMemory` - Memory protection changes
- `NtFreeVirtualMemory` - Memory cleanup
- `NtOpenThread` / `NtSuspendThread` / `NtResumeThread` - Thread manipulation
- `NtGetContextThread` / `NtSetContextThread` - Context manipulation
- `NtDelayExecution` - Stealth sleep (no `Sleep()` API calls)
- `NtAlertThread` - Thread wake-up

**Timing Obfuscation:**
- RDTSC-based random delays (no `GetTickCount`)
- Random timing between operations (50-100ms)
- Stealth sleep using `NtDelayExecution`

**Memory Security:**
- `StealthZeroMemory` - Volatile memory zeroing before free
- Secure cleanup of DLL buffer after injection

### Helper DLL (helper_dll.c)

**PEB Unlinking:**
- Removes DLL from `InLoadOrderModuleList`
- Removes from `InMemoryOrderModuleList`
- Removes from `InInitializationOrderModuleList`
- Invisible to all module enumeration APIs

**Direct Syscalls:**
- `NtDelayExecution` - Stealth sleep
- `NtAllocateVirtualMemory` / `NtFreeVirtualMemory` - Memory management
- `NtProtectVirtualMemory` - Protection changes
- `NtCreateFile` / `NtWriteFile` / `NtClose` - File operations
- `NtQueryVirtualMemory` - Memory queries
- `NtReadVirtualMemory` / `NtWriteVirtualMemory` - Memory access

**Spoofed Function Calls:**
- Uses process's own `memcpy`/`RtlMoveMemory` from IAT
- Triggers auto-decryption for some memory regions
- Avoids detection by using legitimate process functions

**Eidolon Bypass:**
- Decrypt gadget at RVA 0x1E7040 (pattern: `48 8B 01 C3`)
- Triggers Eidolon to decrypt `PAGE_NOACCESS` pages
- Page-by-page processing with forced decryption
- Vectored Exception Handler (VEH) for decryption capture

**Hidden File Operations:**
- `NtCreateFile` with HIDDEN + SYSTEM attributes
- Files invisible in Explorer by default
- NT path format (`\??\C:\...`)

**Memory Cleanup:**
- `SecureZeroBuffer` - Volatile writes prevent optimization
- Memory zeroed before `VirtualFree`
- `_ReadWriteBarrier()` to prevent compiler optimization

**Thread Pool Execution:**
- Uses Windows thread pool (`TrySubmitThreadpoolCallback`)
- Minimal detection footprint
- Asynchronous execution

**TLS Callback Tracking:**
- Continuous scanning every 10ms for 2 minutes
- Captures callbacks even if they get overwritten
- Tracks up to 64 unique callbacks
- All callbacks preserved in final dump

**Import Address Table (IAT) Reconstruction:**
- Reads original import descriptors
- Walks PEB module list (no `LoadLibrary`)
- Resolves function addresses dynamically
- Rebuilds IAT in dump for analysis tools

**PE Header Fixing:**
- `PointerToRawData` = `VirtualAddress`
- `SizeOfRawData` = `VirtualSize`
- `FileAlignment` = `SectionAlignment`
- Clears bound import and security directories
- Compatible with IDA Pro and Ghidra

## Requirements

- **Windows 10/11 x64** (x86/32-bit not supported)
- **Administrator privileges** (required to open target processes)
- **MinGW-w64 GCC** (the code uses GNU inline assembly — MSVC will **not** work)
- **Target process** must be running (injector will wait for it)

### Installing MinGW-w64

#### Option 1: MSYS2 (Recommended)

1. Download and run the installer from [msys2.org](https://www.msys2.org/)
2. Open **MSYS2 UCRT64** from the Start Menu
3. Update packages and install GCC:
   ```bash
   pacman -Syu
   pacman -S mingw-w64-ucrt-x86_64-gcc
   ```
4. Add `C:\msys64\ucrt64\bin` to your **System PATH** environment variable
5. Verify the installation:
   ```bash
   gcc --version
   ```

#### Option 2: MinGW-w64 standalone (winlibs.com)

1. Download the latest **UCRT** runtime GCC package from [winlibs.com](https://winlibs.com/)
2. Extract the archive (e.g. to `C:\mingw64`)
3. Add `C:\mingw64\bin` to your **System PATH** environment variable
4. Verify the installation:
   ```bash
   gcc --version
   ```

#### Option 3: winget (Windows built-in)

```bash
winget install --id BrechtSanders.WinLibs.POSIX.UCRT --accept-source-agreements
```

This installs WinLibs (POSIX threads, UCRT runtime) — no manual PATH setup needed.

#### Option 4: Chocolatey

```bash
choco install mingw
```

## Notes
- dont run this
- especially dont run this on an account you want to keep
- this is my first attempt at this, the methods used may be ultra detected. who knows.
- Process continues running normally during capture
- Game remains fully playable
- Dump happens silently in background
- Files created with HIDDEN + SYSTEM attributes
- 2-minute wait ensures complete capture
- this is a WIP, id like to eventually have it be more "fool proof"
- further reversal of the loader.dll


