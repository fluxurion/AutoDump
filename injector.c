#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <intrin.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0x00000000

/* Must match helper_dll.c MAGIC_OUTPUT_DIR */
#define MAGIC_OUTPUT_DIR 0x525449525450554fULL


#define SYS_NtAllocateVirtualMemory 0x0018
#define SYS_NtWriteVirtualMemory 0x003A
#define SYS_NtProtectVirtualMemory 0x0050
#define SYS_NtReadVirtualMemory 0x003F
#define SYS_NtFreeVirtualMemory 0x001F
#define SYS_NtOpenProcess 0x0026
#define SYS_NtOpenThread 0x00C5
#define SYS_NtSuspendThread 0x00C7
#define SYS_NtResumeThread 0x00C8
#define SYS_NtGetContextThread 0x00F7
#define SYS_NtSetContextThread 0x00F8

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *PFN_NtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *PFN_NtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *PFN_NtSuspendThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtGetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *PFN_NtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *PFN_NtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *PFN_NtAlertThread)(HANDLE);

static PFN_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static PFN_NtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
static PFN_NtReadVirtualMemory pNtReadVirtualMemory = NULL;
static PFN_NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
static PFN_NtFreeVirtualMemory pNtFreeVirtualMemory = NULL;
static PFN_NtOpenProcess pNtOpenProcess = NULL;
static PFN_NtOpenThread pNtOpenThread = NULL;
static PFN_NtSuspendThread pNtSuspendThread = NULL;
static PFN_NtResumeThread pNtResumeThread = NULL;
static PFN_NtGetContextThread pNtGetContextThread = NULL;
static PFN_NtSetContextThread pNtSetContextThread = NULL;
static PFN_NtDelayExecution pNtDelayExecution = NULL;
static PFN_NtAlertThread pNtAlertThread = NULL;

static BOOL InitNtdllFunctions(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    pNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtReadVirtualMemory = (PFN_NtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    pNtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtFreeVirtualMemory = (PFN_NtFreeVirtualMemory)GetProcAddress(hNtdll, "NtFreeVirtualMemory");
    pNtOpenProcess = (PFN_NtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    pNtOpenThread = (PFN_NtOpenThread)GetProcAddress(hNtdll, "NtOpenThread");
    pNtSuspendThread = (PFN_NtSuspendThread)GetProcAddress(hNtdll, "NtSuspendThread");
    pNtResumeThread = (PFN_NtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");
    pNtGetContextThread = (PFN_NtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
    pNtSetContextThread = (PFN_NtSetContextThread)GetProcAddress(hNtdll, "NtSetContextThread");
    pNtDelayExecution = (PFN_NtDelayExecution)GetProcAddress(hNtdll, "NtDelayExecution");
    pNtAlertThread = (PFN_NtAlertThread)GetProcAddress(hNtdll, "NtAlertThread");
    
    return (pNtAllocateVirtualMemory && pNtWriteVirtualMemory && pNtReadVirtualMemory &&
            pNtProtectVirtualMemory && pNtFreeVirtualMemory && pNtOpenProcess && pNtOpenThread && 
            pNtSuspendThread && pNtResumeThread && pNtGetContextThread &&
            pNtSetContextThread && pNtDelayExecution);
}

#ifdef _WIN64
static NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    return pNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

static NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten) {
    return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

static NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {
    return pNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

static NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    return pNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

static NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType) {
    return pNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

static NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    return pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

static NTSTATUS NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    return pNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}

static NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    return pNtSuspendThread(ThreadHandle, SuspendCount);
}

static NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount) {
    return pNtResumeThread(ThreadHandle, SuspendCount);
}

static NTSTATUS NtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    return pNtGetContextThread(ThreadHandle, Context);
}

static NTSTATUS NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context) {
    return pNtSetContextThread(ThreadHandle, Context);
}

static NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    return pNtDelayExecution(Alertable, DelayInterval);
}

static NTSTATUS NtAlertThread(HANDLE ThreadHandle) {
    if (pNtAlertThread) return pNtAlertThread(ThreadHandle);
    return 0;
}

static void StealthSleep(DWORD milliseconds) {
    LARGE_INTEGER delay;
    delay.QuadPart = -10000LL * milliseconds;
    NtDelayExecution(FALSE, &delay);
}
#endif

static DWORD GetProcessIdByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    DWORD processId = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                processId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return processId;
}

typedef struct _LAUNCHED_PROCESS {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD processId;
    DWORD threadId;
} LAUNCHED_PROCESS, *PLAUNCHED_PROCESS;

static BOOL LaunchProcessSuspended(const char* exePath, PLAUNCHED_PROCESS pLaunchedProc) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(STARTUPINFOA);
    
    BOOL result = CreateProcessA(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!result) return FALSE;
    
    pLaunchedProc->hProcess = pi.hProcess;
    pLaunchedProc->hThread = pi.hThread;
    pLaunchedProc->processId = pi.dwProcessId;
    pLaunchedProc->threadId = pi.dwThreadId;
    
    return TRUE;
}

static BOOL WaitForProcessInitialization(HANDLE hProcess) {
    StealthSleep(100);
    
    DWORD exitCode;
    if (!GetExitCodeProcess(hProcess, &exitCode) || exitCode != STILL_ACTIVE)
        return FALSE;
    
    return TRUE;
}

static BOOL GetDllPath(char* dllPath, SIZE_T pathSize) {
    char injectorPath[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, injectorPath, MAX_PATH) == 0) {
        return FALSE;
    }
    
    char* lastSlash = strrchr(injectorPath, '\\');
    if (!lastSlash) {
        return FALSE;
    }
    
    SIZE_T dirLen = lastSlash - injectorPath + 1;
    if (dirLen + 11 > pathSize) {
        return FALSE;
    }
    
    strncpy_s(dllPath, pathSize, injectorPath, dirLen);
    strcat_s(dllPath, pathSize, "helper.dll");
    
    return TRUE;
}

static DWORD GetMainThreadId(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    THREADENTRY32 te32 = {0};
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD mainThreadId = 0;
    ULONGLONG earliestTime = MAXULONGLONG;
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    FILETIME createTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &createTime, &exitTime, &kernelTime, &userTime)) {
                        ULARGE_INTEGER ul;
                        ul.LowPart = createTime.dwLowDateTime;
                        ul.HighPart = createTime.dwHighDateTime;
                        if (ul.QuadPart < earliestTime) {
                            earliestTime = ul.QuadPart;
                            mainThreadId = te32.th32ThreadID;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    return mainThreadId;
}

static DWORD GetWorkerThreadId(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    DWORD mainThreadId = GetMainThreadId(processId);
    
    THREADENTRY32 te32 = {0};
    te32.dwSize = sizeof(THREADENTRY32);
    
    DWORD candidates[64];
    ULONGLONG idleTimes[64];
    int candidateCount = 0;
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId && 
                te32.th32ThreadID != mainThreadId &&
                candidateCount < 64) {
                
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    FILETIME createTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &createTime, &exitTime, &kernelTime, &userTime)) {
                        ULARGE_INTEGER k, u;
                        k.LowPart = kernelTime.dwLowDateTime;
                        k.HighPart = kernelTime.dwHighDateTime;
                        u.LowPart = userTime.dwLowDateTime;
                        u.HighPart = userTime.dwHighDateTime;
                        
                        candidates[candidateCount] = te32.th32ThreadID;
                        idleTimes[candidateCount] = k.QuadPart + u.QuadPart;
                        candidateCount++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    
    if (candidateCount == 0) {
        return mainThreadId;
    }
    
    DWORD bestThread = 0;
    ULONGLONG bestTime = MAXULONGLONG;
    
    for (int i = 0; i < candidateCount; i++) {
        if (idleTimes[i] > 0 && idleTimes[i] < bestTime) {
            bestTime = idleTimes[i];
            bestThread = candidates[i];
        }
    }
    
    if (bestThread == 0 && candidateCount > 0) {
        bestThread = candidates[0];
        bestTime = idleTimes[0];
    }
    (void)bestTime;
    
    return bestThread;
}

static void StealthZeroMemory(PVOID ptr, SIZE_T size) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (size--) {
        *p++ = 0;
    }
}

static DWORD GetRandomDelay(DWORD min, DWORD max);

static PVOID ReadDLLFile(const char* dllPath, SIZE_T* pSize) {
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;
    
    *pSize = GetFileSize(hFile, NULL);
    if (*pSize == 0 || *pSize > 50 * 1024 * 1024) {
        CloseHandle(hFile);
        return NULL;
    }
    PVOID buffer = VirtualAlloc(NULL, *pSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        return NULL;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, (DWORD)*pSize, &bytesRead, NULL) || bytesRead != *pSize) {
        StealthZeroMemory(buffer, *pSize);
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }
    
    CloseHandle(hFile);
    return buffer;
}

static PVOID ReflectiveLoadDLL(HANDLE hProcess, PVOID dllBuffer, SIZE_T dllSize) {
    (void)dllSize;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)dllBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
    PVOID remoteBase = NULL;
    NTSTATUS allocStatus = NtAllocateVirtualMemory(hProcess, &remoteBase, 0, &imageSize, 
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocStatus != STATUS_SUCCESS) return NULL;
    
    SIZE_T headerSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
    SIZE_T bytesWritten = 0;
    NTSTATUS writeStatus = NtWriteVirtualMemory(hProcess, remoteBase, dllBuffer, headerSize, &bytesWritten);
    if (writeStatus != STATUS_SUCCESS) return NULL;
    
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSection[i].SizeOfRawData) {
            PVOID sectionDest = (LPBYTE)remoteBase + pSection[i].VirtualAddress;
            PVOID sectionSrc = (LPBYTE)dllBuffer + pSection[i].PointerToRawData;
            
            NTSTATUS sectionStatus = NtWriteVirtualMemory(hProcess, sectionDest, sectionSrc, 
                                   pSection[i].SizeOfRawData, &bytesWritten);
            if (sectionStatus != STATUS_SUCCESS) return NULL;
        }
    }
    
    DWORD_PTR delta = (DWORD_PTR)remoteBase - pNtHeaders->OptionalHeader.ImageBase;
    if (delta) {
        DWORD relocRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        
        if (relocSize && relocRva) {
            DWORD relocFileOffset = 0;
            PIMAGE_SECTION_HEADER pSectionSearch = IMAGE_FIRST_SECTION(pNtHeaders);
            for (WORD s = 0; s < pNtHeaders->FileHeader.NumberOfSections; s++) {
                DWORD sectionStart = pSectionSearch[s].VirtualAddress;
                DWORD sectionEnd = sectionStart + pSectionSearch[s].Misc.VirtualSize;
                if (relocRva >= sectionStart && relocRva < sectionEnd) {
                    relocFileOffset = pSectionSearch[s].PointerToRawData + (relocRva - sectionStart);
                    break;
                }
            }
            
            if (relocFileOffset) {
                PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)dllBuffer + relocFileOffset);
                
                DWORD blocksProcessed = 0;
                while (relocSize > 0 && blocksProcessed < 1000) {
                    blocksProcessed++;
                    if (pReloc->SizeOfBlock == 0 || 
                        pReloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                        pReloc->SizeOfBlock > relocSize) break;
                    
                    DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    PWORD pRelocData = (PWORD)(pReloc + 1);
                    
                    for (DWORD i = 0; i < count; i++) {
                        WORD type = pRelocData[i] >> 12;
                        WORD offset = pRelocData[i] & 0xFFF;
                        
                        if (type == IMAGE_REL_BASED_DIR64) {
                            PVOID patchAddr = (LPBYTE)remoteBase + pReloc->VirtualAddress + offset;
                            DWORD_PTR value = 0;
                            SIZE_T bytesRead = 0;
                            
                            if (NtReadVirtualMemory(hProcess, patchAddr, &value, sizeof(value), &bytesRead) == STATUS_SUCCESS) {
                                value += delta;
                                NtWriteVirtualMemory(hProcess, patchAddr, &value, sizeof(value), &bytesWritten);
                            }
                        }
                    }
                    
                    relocSize -= pReloc->SizeOfBlock;
                    pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloc + pReloc->SizeOfBlock);
                }
            }
        }
    }
    
    DWORD importRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    
    if (importRva && importSize) {
        DWORD importFileOffset = 0;
        PIMAGE_SECTION_HEADER pSectionSearch = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD s = 0; s < pNtHeaders->FileHeader.NumberOfSections; s++) {
            DWORD sectionStart = pSectionSearch[s].VirtualAddress;
            DWORD sectionEnd = sectionStart + pSectionSearch[s].Misc.VirtualSize;
            if (importRva >= sectionStart && importRva < sectionEnd) {
                importFileOffset = pSectionSearch[s].PointerToRawData + (importRva - sectionStart);
                break;
            }
        }
        
        if (importFileOffset) {
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)dllBuffer + importFileOffset);
            
            while (pImportDesc->Name) {
                DWORD nameRva = pImportDesc->Name;
                DWORD nameFileOffset = 0;
                for (WORD s = 0; s < pNtHeaders->FileHeader.NumberOfSections; s++) {
                    DWORD sectionStart = pSectionSearch[s].VirtualAddress;
                    DWORD sectionEnd = sectionStart + pSectionSearch[s].Misc.VirtualSize;
                    if (nameRva >= sectionStart && nameRva < sectionEnd) {
                        nameFileOffset = pSectionSearch[s].PointerToRawData + (nameRva - sectionStart);
                        break;
                    }
                }
                
                if (!nameFileOffset) { pImportDesc++; continue; }
                
                char* dllName = (char*)((LPBYTE)dllBuffer + nameFileOffset);
                HMODULE hModule = GetModuleHandleA(dllName);
                if (!hModule) hModule = LoadLibraryA(dllName);
                if (!hModule) { pImportDesc++; continue; }
                
                DWORD origThunkRva = pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk;
                DWORD thunkRva = pImportDesc->FirstThunk;
                DWORD origThunkFileOffset = 0;
                for (WORD s = 0; s < pNtHeaders->FileHeader.NumberOfSections; s++) {
                    DWORD sectionStart = pSectionSearch[s].VirtualAddress;
                    DWORD sectionEnd = sectionStart + pSectionSearch[s].Misc.VirtualSize;
                    if (origThunkRva >= sectionStart && origThunkRva < sectionEnd) {
                        origThunkFileOffset = pSectionSearch[s].PointerToRawData + (origThunkRva - sectionStart);
                        break;
                    }
                }
                
                if (!origThunkFileOffset) { pImportDesc++; continue; }
                
                PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((LPBYTE)dllBuffer + origThunkFileOffset);
                PVOID pIatEntry = (LPBYTE)remoteBase + thunkRva;
                
                while (pOrigThunk->u1.AddressOfData) {
                    FARPROC funcAddr = NULL;
                    
                    if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        WORD ordinal = (WORD)(pOrigThunk->u1.Ordinal & 0xFFFF);
                        funcAddr = GetProcAddress(hModule, (LPCSTR)(ULONG_PTR)ordinal);
                    } else {
                        DWORD importByNameRva = (DWORD)pOrigThunk->u1.AddressOfData;
                        DWORD importByNameFileOffset = 0;
                        for (WORD s = 0; s < pNtHeaders->FileHeader.NumberOfSections; s++) {
                            DWORD sectionStart = pSectionSearch[s].VirtualAddress;
                            DWORD sectionEnd = sectionStart + pSectionSearch[s].Misc.VirtualSize;
                            if (importByNameRva >= sectionStart && importByNameRva < sectionEnd) {
                                importByNameFileOffset = pSectionSearch[s].PointerToRawData + (importByNameRva - sectionStart);
                                break;
                            }
                        }
                        
                        if (importByNameFileOffset) {
                            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)dllBuffer + importByNameFileOffset);
                            funcAddr = GetProcAddress(hModule, (char*)pImportByName->Name);
                        }
                    }
                    
                    if (funcAddr) {
                        DWORD64 funcAddr64 = (DWORD64)funcAddr;
                        NtWriteVirtualMemory(hProcess, pIatEntry, &funcAddr64, sizeof(funcAddr64), &bytesWritten);
                    }
                    
                    pOrigThunk++;
                    pIatEntry = (LPBYTE)pIatEntry + sizeof(DWORD64);
                }
                
                pImportDesc++;
            }
        }
    }
    
    pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD protect = 0;
        DWORD characteristics = pSection[i].Characteristics;
        
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = (characteristics & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
        } else {
            protect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }
        
        if (protect) {
            PVOID sectionAddr = (LPBYTE)remoteBase + pSection[i].VirtualAddress;
            SIZE_T sectionSize = pSection[i].Misc.VirtualSize;
            ULONG oldProtect = 0;
            NtProtectVirtualMemory(hProcess, &sectionAddr, &sectionSize, protect, &oldProtect);
        }
    }
    
    PVOID headerAddr = remoteBase;
    SIZE_T headerProtectSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
    ULONG oldProtect = 0;
    NtProtectVirtualMemory(hProcess, &headerAddr, &headerProtectSize, PAGE_EXECUTE_READ, &oldProtect);
    
    return remoteBase;
}

static BOOL CallDllEntryPoint(HANDLE hProcess, DWORD processId, PVOID dllBase) {
    IMAGE_DOS_HEADER dosHeader = {0};
    SIZE_T bytesRead = 0;
    
    if (NtReadVirtualMemory(hProcess, dllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead) != STATUS_SUCCESS)
        return FALSE;
    
    IMAGE_NT_HEADERS ntHeaders = {0};
    PVOID ntHeadersAddr = (LPBYTE)dllBase + dosHeader.e_lfanew;
    if (NtReadVirtualMemory(hProcess, ntHeadersAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead) != STATUS_SUCCESS)
        return FALSE;
    
    PVOID entryPoint = (LPBYTE)dllBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;
    
    DWORD threadId = GetWorkerThreadId(processId);
    if (threadId == 0) return FALSE;
    
    CLIENT_ID clientId = {0};
    clientId.UniqueProcess = (PVOID)(ULONG_PTR)processId;
    clientId.UniqueThread = (PVOID)(ULONG_PTR)threadId;
    
    OBJECT_ATTRIBUTES objAttr = {0};
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    
    HANDLE hThread = NULL;
    if (NtOpenThread(&hThread, THREAD_ALL_ACCESS, &objAttr, &clientId) != STATUS_SUCCESS)
        return FALSE;
    
    if (NtSuspendThread(hThread, NULL) != STATUS_SUCCESS) {
        CloseHandle(hThread);
        return FALSE;
    }
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (NtGetContextThread(hThread, &ctx) != STATUS_SUCCESS) {
        NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        return FALSE;
    }
    
    #ifdef _WIN64
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
        0x4D, 0x31, 0xC0,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        0xEB, 0xFE
    };
    
    DWORD64 dllBaseAddr = (DWORD64)dllBase;
    DWORD64 entryPointAddr = (DWORD64)entryPoint;
    (void)ctx.Rip;
    
    memcpy(&shellcode[6], &dllBaseAddr, sizeof(DWORD64));
    memcpy(&shellcode[26], &entryPointAddr, sizeof(DWORD64));
    
    PVOID shellcodeAddr = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);
    NTSTATUS allocStatus = NtAllocateVirtualMemory(hProcess, &shellcodeAddr, 0, &shellcodeSize, 
                                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocStatus != STATUS_SUCCESS) {
        NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        return FALSE;
    }
    
    SIZE_T bytesWritten = 0;
    NTSTATUS writeStatus = NtWriteVirtualMemory(hProcess, shellcodeAddr, shellcode, sizeof(shellcode), &bytesWritten);
    if (writeStatus != STATUS_SUCCESS) {
        SIZE_T freeSize = shellcodeSize;
        NtFreeVirtualMemory(hProcess, &shellcodeAddr, &freeSize, MEM_RELEASE);
        NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        return FALSE;
    }
    
    PVOID protectAddr = shellcodeAddr;
    SIZE_T protectSize = shellcodeSize;
    ULONG oldProtect = 0;
    NTSTATUS protStatus = NtProtectVirtualMemory(hProcess, &protectAddr, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
    if (protStatus != STATUS_SUCCESS) {
        SIZE_T freeSize = shellcodeSize;
        NtFreeVirtualMemory(hProcess, &shellcodeAddr, &freeSize, MEM_RELEASE);
        NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        return FALSE;
    }
    
    ctx.Rip = (DWORD64)shellcodeAddr;
    
    NTSTATUS setStatus = NtSetContextThread(hThread, &ctx);
    if (setStatus != STATUS_SUCCESS) {
        SIZE_T freeSize = shellcodeSize;
        NtFreeVirtualMemory(hProcess, &shellcodeAddr, &freeSize, MEM_RELEASE);
        NtResumeThread(hThread, NULL);
        CloseHandle(hThread);
        return FALSE;
    }
    
    NtResumeThread(hThread, NULL);
    NtAlertThread(hThread);
    #endif
    
    CloseHandle(hThread);
    return TRUE;
}

static DWORD GetRandomDelay(DWORD min, DWORD max) {
    ULONGLONG tsc = __rdtsc();
    
    DWORD tick = GetTickCount();
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    LARGE_INTEGER perfCounter;
    QueryPerformanceCounter(&perfCounter);
    
    DWORD_PTR stackPtr = (DWORD_PTR)&tick;
    
    DWORD entropy = (DWORD)(tsc & 0xFFFFFFFF);
    entropy ^= (DWORD)(tsc >> 32);
    entropy ^= tick;
    entropy ^= pid;
    entropy ^= tid;
    entropy ^= (DWORD)(perfCounter.QuadPart & 0xFFFFFFFF);
    entropy ^= (DWORD)(perfCounter.QuadPart >> 32);
    entropy ^= (DWORD)(stackPtr & 0xFFFFFFFF);
    
    entropy = (entropy << 7) ^ (entropy >> 25);
    entropy ^= (entropy << 13);
    entropy ^= (entropy >> 19);
    entropy = (entropy << 5) ^ (entropy >> 27);
    
    entropy = entropy * 0x9E3779B9;
    entropy ^= (entropy >> 16);
    
    return min + (entropy % (max - min + 1));
}

/* Forward declarations for output directory helpers */
static DWORD FindOutputDirRva(PVOID dllBuffer, SIZE_T dllSize);
static void GetMyDir(char* out, SIZE_T outSize);

static int EarlyInjectSuspended(PLAUNCHED_PROCESS pLaunchedProc, const char* dllPath) {
    HANDLE hProcess = pLaunchedProc->hProcess;
    
    SIZE_T dllSize;
    PVOID dllBuffer = ReadDLLFile(dllPath, &dllSize);
    if (!dllBuffer) return 2;
    
    /* Scan for output directory marker BEFORE zeroing the buffer */
    DWORD outputPathRva = FindOutputDirRva(dllBuffer, dllSize);
    
    PVOID dllBase = ReflectiveLoadDLL(hProcess, dllBuffer, dllSize);
    
    /* If marker found, write the injector's directory into the remote DLL */
    if (dllBase && outputPathRva) {
        char myDir[MAX_PATH];
        GetMyDir(myDir, sizeof(myDir));
        if (myDir[0]) {
            PVOID remotePath = (LPBYTE)dllBase + outputPathRva;
            SIZE_T written = 0;
            NtWriteVirtualMemory(hProcess, remotePath, myDir,
                                 (SIZE_T)strlen(myDir) + 1, &written);
        }
    }
    
    StealthZeroMemory(dllBuffer, dllSize);
    VirtualFree(dllBuffer, 0, MEM_RELEASE);
    
    if (!dllBase) return 3;
    
    IMAGE_DOS_HEADER dosHeader = {0};
    SIZE_T bytesRead = 0;
    
    if (NtReadVirtualMemory(hProcess, dllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead) != STATUS_SUCCESS)
        return 4;
    
    IMAGE_NT_HEADERS ntHeaders = {0};
    PVOID ntHeadersAddr = (LPBYTE)dllBase + dosHeader.e_lfanew;
    if (NtReadVirtualMemory(hProcess, ntHeadersAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead) != STATUS_SUCCESS)
        return 4;
    
    PVOID entryPoint = (LPBYTE)dllBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;
    
    HANDLE hThread = pLaunchedProc->hThread;
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (NtGetContextThread(hThread, &ctx) != STATUS_SUCCESS) return 4;
    
    DWORD64 originalRip = ctx.Rip;
    
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x53,
        0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
        0x4D, 0x31, 0xC0,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        0x5B,
        0x48, 0x83, 0xC4, 0x28,
        0xFF, 0xE3
    };
    
    DWORD64 dllBaseAddr = (DWORD64)dllBase;
    DWORD64 entryPointAddr = (DWORD64)entryPoint;
    
    memcpy(&shellcode[7], &originalRip, sizeof(DWORD64));
    memcpy(&shellcode[17], &dllBaseAddr, sizeof(DWORD64));
    memcpy(&shellcode[37], &entryPointAddr, sizeof(DWORD64));
    
    PVOID shellcodeAddr = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);
    
    if (NtAllocateVirtualMemory(hProcess, &shellcodeAddr, 0, &shellcodeSize, 
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != STATUS_SUCCESS)
        return 4;
    
    SIZE_T bytesWritten = 0;
    if (NtWriteVirtualMemory(hProcess, shellcodeAddr, shellcode, sizeof(shellcode), &bytesWritten) != STATUS_SUCCESS)
        return 4;
    
    PVOID protectAddr = shellcodeAddr;
    SIZE_T protectSize = shellcodeSize;
    ULONG oldProtect = 0;
    NtProtectVirtualMemory(hProcess, &protectAddr, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
    
    ctx.Rip = (DWORD64)shellcodeAddr;
    
    if (NtSetContextThread(hThread, &ctx) != STATUS_SUCCESS) return 4;
    
    DWORD suspendCount = 0;
    NtResumeThread(hThread, &suspendCount);
    
    return 0;
}

/*
 * Convert a file offset (raw byte position in the DLL file) to an RVA
 * (relative virtual address) using the PE section headers.
 * The .data section's file offset and virtual address often differ,
 * so this conversion is critical for correct memory addressing.
 */
static DWORD FileOffsetToRva(PVOID dllBuffer, DWORD fileOffset) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dllBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((LPBYTE)dllBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD numSections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        DWORD secFileStart = sections[i].PointerToRawData;
        DWORD secFileEnd   = secFileStart + sections[i].SizeOfRawData;

        if (fileOffset >= secFileStart && fileOffset < secFileEnd) {
            /* RVA = section's VA + (file offset - section's file offset) */
            return sections[i].VirtualAddress + (fileOffset - secFileStart);
        }
    }
    return 0; /* Not found in any loaded section */
}

/*
 * Scan the DLL image buffer for MAGIC_OUTPUT_DIR marker.
 * If found, returns the RVA of g_outputPath[] (right after the 8-byte
 * marker), properly converted from file-offset to RVA. Returns 0 if
 * the marker is not found or conversion fails.
 */
static DWORD FindOutputDirRva(PVOID dllBuffer, SIZE_T dllSize) {
    LPBYTE p = (LPBYTE)dllBuffer;
    for (SIZE_T i = 0; i < dllSize - sizeof(UINT64) - MAX_PATH; i += 1) {
        if (*(UINT64*)(p + i) == MAGIC_OUTPUT_DIR) {
            /* The marker was found at file offset i; g_outputPath is right after it */
            DWORD fileOffset = (DWORD)(i + sizeof(UINT64));
            return FileOffsetToRva(dllBuffer, fileOffset);
        }
    }
    return 0;
}

/* Get the directory containing injector.exe (with trailing backslash) */
static void GetMyDir(char* out, SIZE_T outSize) {
    char mod[MAX_PATH];
    GetModuleFileNameA(NULL, mod, sizeof(mod));
    char* slash = strrchr(mod, '\\');
    if (slash) {
        SIZE_T len = (slash - mod) + 1;
        if (len < outSize) {
            memcpy(out, mod, len);
            out[len] = 0;
        }
    } else {
        out[0] = 0;
    }
}

static int MaximumStealthInject(DWORD processId, const char* dllPath) {
    StealthSleep(GetRandomDelay(50, 100));
    
    CLIENT_ID clientId = {0};
    clientId.UniqueProcess = (PVOID)(ULONG_PTR)processId;
    
    OBJECT_ATTRIBUTES objAttr = {0};
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    
    HANDLE hProcess = NULL;
    ACCESS_MASK desiredAccess = PROCESS_QUERY_INFORMATION |
                                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    
    if (NtOpenProcess(&hProcess, desiredAccess, &objAttr, &clientId) != STATUS_SUCCESS) {
        printf("[-] Failed to open process (run as admin?)\n");
        return 1;
    }
    
    SIZE_T dllSize;
    PVOID dllBuffer = ReadDLLFile(dllPath, &dllSize);
    if (!dllBuffer) {
        CloseHandle(hProcess);
        return 2;
    }
    
    /* Scan the DLL buffer for the output-directory marker BEFORE zeroing */
    DWORD outputPathRva = FindOutputDirRva(dllBuffer, dllSize);
    if (outputPathRva) {
        printf("[*] Found output directory marker at RVA 0x%X\n", outputPathRva);
    } else {
        printf("[*] Output directory marker not found (files will be in target CWD)\n");
    }
    
    PVOID dllBase = ReflectiveLoadDLL(hProcess, dllBuffer, dllSize);
    
    /* If marker was found, write the injector's directory into the remote DLL */
    if (dllBase && outputPathRva) {
        char myDir[MAX_PATH];
        GetMyDir(myDir, sizeof(myDir));
        if (myDir[0]) {
            PVOID remotePath = (LPBYTE)dllBase + outputPathRva;
            SIZE_T written = 0;
            NTSTATUS ws = NtWriteVirtualMemory(hProcess, remotePath, myDir,
                                                (SIZE_T)strlen(myDir) + 1, &written);
            if (ws == STATUS_SUCCESS) {
                printf("[*] Output directory set: %s\n", myDir);
            } else {
                printf("[-] Failed to write output directory to remote process\n");
            }
        }
    }
    
    StealthZeroMemory(dllBuffer, dllSize);
    VirtualFree(dllBuffer, 0, MEM_RELEASE);
    
    if (!dllBase) {
        CloseHandle(hProcess);
        return 3;
    }
    
    printf("[+] Injected at 0x%p\n", dllBase);
    
    BOOL entryResult = CallDllEntryPoint(hProcess, processId, dllBase);
    CloseHandle(hProcess);
    
    return entryResult ? 0 : 4;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target.exe>\n", argv[0] ? argv[0] : "injector.exe");
        return 1;
    }
    
    if (!InitNtdllFunctions()) {
        printf("[-] ntdll init failed\n");
        return 1;
    }
    
    char dllPath[MAX_PATH] = {0};
    if (!GetDllPath(dllPath, sizeof(dllPath))) {
        printf("[-] DLL path error\n");
        return 1;
    }
    
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] helper.dll not found\n");
        return 1;
    }
    CloseHandle(hFile);
    
    const char* targetProcess = argv[1];
    DWORD processId = GetProcessIdByName(targetProcess);
    
    if (processId == 0) {
        printf("[*] Waiting for %s...\n", targetProcess);
        fflush(stdout);
        
        while (processId == 0) {
            processId = GetProcessIdByName(targetProcess);
            if (processId == 0) StealthSleep(10);
        }
    }
    
    printf("[*] %s (PID %lu)\n", targetProcess, processId);
    
    int result = MaximumStealthInject(processId, dllPath);
    
    if (result == 0) {
        printf("[+] Done. Dump starts in 2 min.\n");
    } else {
        printf("[-] Failed (err %d)\n", result);
    }
    
    return result;
}
