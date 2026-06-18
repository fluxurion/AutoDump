#include <windows.h>
#include <stdint.h>
#include <stdarg.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>
#include <intrin.h>
#include <ctype.h>

#define MAX_OFFSETS 32000
#define MAX_NAME_LEN 128

/*
 * Output directory config block.
 * The injector scans the DLL image for MAGIC_OUTPUT_DIR, then writes
 * the absolute path (with trailing backslash) into g_outputPath.
 * The helper DLL uses this path as the base for all output files.
 */
#define MAGIC_OUTPUT_DIR 0x525449525450554fULL /* "OUTPUTDIR" */

/*
 * Output config block — MUST be in the .data section (not .bss)!
 * Zero-initialized globals go to .bss which has no file data,
 * so the injector's marker scan can't find them.
 * Initializing g_outputPath[0]=1 forces it into .data alongside
 * the magic marker, keeping both at known file-to-VA offsets.
 */
__attribute__((aligned(32))) volatile UINT64 g_outputDirMagic  = MAGIC_OUTPUT_DIR;
/* First byte = 1, rest = 0 — keeps this in .data, not .bss */
__attribute__((aligned(32))) volatile char    g_outputPath[MAX_PATH] = {1};

/*
 * Build a full output path by prepending g_outputPath (if set) to filename.
 * Returns pointer to static buffer — valid until next call.
 */
static const char* OutputPath(const char* filename) {
    static char buf[MAX_PATH * 2];
    /* Check if a real output path was set by the injector.
     * The sentinel value g_outputPath[0]==1 means "not yet set"
     * (we initialize to {1} to keep the variable in .data, not .bss). */
    if (g_outputPath[0] > 1) {
        size_t plen = strnlen((const char*)g_outputPath, MAX_PATH);
        if (plen > 0 && g_outputPath[plen-1] == '\\')
            snprintf(buf, sizeof(buf), "%s%s", (const char*)g_outputPath, filename);
        else
            snprintf(buf, sizeof(buf), "%s\\%s", (const char*)g_outputPath, filename);
    } else {
        /* No directory path set — use filename as-is (relative = target CWD) */
        snprintf(buf, sizeof(buf), "%s", filename);
    }
    return buf;
}

typedef enum {
    OFFSET_LUA_FUNCTION,
    OFFSET_BINDING_COMMAND,
    OFFSET_GLOBAL_POINTER,
    OFFSET_STATIC_DATA
} OffsetType;

typedef struct {
    char name[MAX_NAME_LEN];
    uint64_t rva;
    OffsetType type;
} OffsetEntry;

static OffsetEntry* g_offsets = NULL;
static int g_offsetCount = 0;
static CRITICAL_SECTION g_offsetLock;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _UNICODE_STRING_PEB {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_PEB, *PUNICODE_STRING_PEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_PEB FullDllName;
    UNICODE_STRING_PEB BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

#ifdef _WIN64
#define GET_PEB() ((PPEB)__readgsqword(0x60))
#else
#define GET_PEB() ((PPEB)__readfsdword(0x30))
#endif

static void UnlinkFromPEB(HMODULE hModule) {
    PPEB peb = GET_PEB();
    if (!peb || !peb->Ldr) return;
    
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY entry = NULL;
    
    PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    
    while (current != head) {
        entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        if (entry->DllBase == hModule) {
            entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
            entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
            entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
            entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;
            entry->InInitializationOrderLinks.Blink->Flink = entry->InInitializationOrderLinks.Flink;
            entry->InInitializationOrderLinks.Flink->Blink = entry->InInitializationOrderLinks.Blink;
            entry->InLoadOrderLinks.Flink = entry->InLoadOrderLinks.Blink = &entry->InLoadOrderLinks;
            entry->InMemoryOrderLinks.Flink = entry->InMemoryOrderLinks.Blink = &entry->InMemoryOrderLinks;
            entry->InInitializationOrderLinks.Flink = entry->InInitializationOrderLinks.Blink = &entry->InInitializationOrderLinks;
            
            break;
        }
        current = current->Flink;
    }
}

/* Forward declarations for logging helpers used throughout this file */
static void DebugLog(const char* msg);
static void DebugLogFmt(const char* fmt, ...) __attribute__((format(printf,1,2)));

#define DECRYPT_GADGET_RVA 0x1E7040

typedef UINT64 (__fastcall *DecryptGadgetFunc)(PVOID address);
static DecryptGadgetFunc g_decryptGadget = NULL;

/* Global XOR key discovered at runtime (0 = none detected) */
static UINT64 g_xorKey   = 0;
static BOOL   g_xorReady = FALSE;

static volatile BOOL g_pageCopyFailed = FALSE;

static LONG CALLBACK PageCopyVEH(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        g_pageCopyFailed = TRUE;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL DecryptPageWithGadget(PVOID srcPage, PVOID dstBuffer) {
    if (!g_decryptGadget) return FALSE;
    UINT64* src = (UINT64*)srcPage;
    UINT64* dst = (UINT64*)dstBuffer;
    for (int i = 0; i < 512; i++)
        dst[i] = g_decryptGadget(&src[i]);
    return TRUE;
}

static BOOL CopyPageAfterTouch(PVOID srcPage, PVOID dstBuffer) {
    if (!g_decryptGadget) {
        memcpy(dstBuffer, srcPage, 4096);
        return TRUE;
    }
    UINT64* src = (UINT64*)srcPage;
    UINT64* dst = (UINT64*)dstBuffer;
    for (int i = 0; i < 512; i++)
        dst[i] = g_decryptGadget(&src[i]);
    return TRUE;
}

/*
 * XOR key detection: sample accessible code pages looking for a repeating
 * 8-byte XOR key. A valid key is one where XORing a readable page produces
 * output that looks like x86-64 code (high density of common instruction
 * prefixes: 0x48/0x4C/0x41/0x45/0x40, 0xE8, 0xFF, 0x8B, 0x89, 0x0F).
 */
static int ScoreAsCode(const uint8_t* buf, DWORD len) {
    int score = 0;
    for (DWORD i = 0; i < len && i < 256; i++) {
        uint8_t b = buf[i];
        if (b == 0x48 || b == 0x4C || b == 0x41 || b == 0x45 || b == 0x40 ||
            b == 0xE8 || b == 0xFF || b == 0x8B || b == 0x89 || b == 0x0F ||
            b == 0x55 || b == 0x53 || b == 0x56 || b == 0x57 || b == 0xC3)
            score++;
    }
    return score;
}

/*
 * Try to derive the XOR key by looking at a readable code page that is
 * immediately adjacent to a PAGE_NOACCESS page. We XOR candidate 8-byte
 * keys (sampled from the readable page itself at aligned offsets) against
 * the first 256 bytes of the protected page and score the result.
 */
static BOOL DetectXorKey(PVOID moduleBase, DWORD imageSize) {
    if (g_xorReady) return g_xorKey != 0;
    g_xorReady = TRUE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)moduleBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    /* Find first readable code section page to use as plaintext reference */
    uint8_t* plainPage = NULL;
    uint8_t* encPage   = NULL;

    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections && !encPage; s++) {
        if (!(pSec[s].Characteristics & IMAGE_SCN_CNT_CODE)) continue;
        DWORD secRVA  = pSec[s].VirtualAddress;
        DWORD secSize = pSec[s].Misc.VirtualSize;
        if (!secSize) secSize = pSec[s].SizeOfRawData;

        for (DWORD off = 0; off + 8192 < secSize; off += 4096) {
            uint8_t* pg1 = (uint8_t*)moduleBase + secRVA + off;
            uint8_t* pg2 = (uint8_t*)moduleBase + secRVA + off + 4096;
            MEMORY_BASIC_INFORMATION m1, m2;
            if (!VirtualQuery(pg1, &m1, sizeof(m1))) continue;
            if (!VirtualQuery(pg2, &m2, sizeof(m2))) continue;
            BOOL r1 = (m1.Protect & PAGE_EXECUTE_READ) || (m1.Protect & PAGE_EXECUTE_READWRITE) ||
                      (m1.Protect & PAGE_READONLY)     || (m1.Protect & PAGE_READWRITE);
            BOOL r2 = (m2.Protect == PAGE_NOACCESS || m2.Protect == 0);
            if (r1 && r2) { plainPage = pg1; encPage = pg2; break; }
        }
    }

    if (!plainPage || !encPage) return FALSE;

    /* Score the encrypted page raw (should be low for truly encrypted data).
     * Use VirtualQuery to confirm the page is accessible before reading. */
    MEMORY_BASIC_INFORMATION encMbi;
    if (!VirtualQuery(encPage, &encMbi, sizeof(encMbi))) return FALSE;
    if (encMbi.Protect == PAGE_NOACCESS || encMbi.Protect == 0) {
        DWORD oldProt;
        if (!VirtualProtect(encPage, 256, PAGE_EXECUTE_READ, &oldProt)) return FALSE;
        VirtualProtect(encPage, 256, oldProt, &oldProt);
        if (!VirtualQuery(encPage, &encMbi, sizeof(encMbi))) return FALSE;
    }
    uint8_t tmp[256];
    memcpy(tmp, encPage, 256);
    if (ScoreAsCode(tmp, 256) > 40) {
        /* Page looks like code already — no XOR needed */
        return FALSE;
    }

    /* Try each 8-byte aligned chunk of the readable page as a candidate key */
    int bestScore = 0;
    UINT64 bestKey = 0;
    int k;
    for (k = 0; k < 64; k++) {
        UINT64 candidate;
        memcpy(&candidate, plainPage + k * 8, 8);
        if (!candidate) continue;
        uint8_t decoded[256];
        int i;
        for (i = 0; i < 32; i++) {
            UINT64 enc;
            memcpy(&enc, tmp + i * 8, 8);
            UINT64 dec = enc ^ candidate;
            memcpy(decoded + i * 8, &dec, 8);
        }
        int sc = ScoreAsCode(decoded, 256);
        if (sc > bestScore) { bestScore = sc; bestKey = candidate; }
    }

    if (bestScore >= 20 && bestKey) {
        g_xorKey = bestKey;
        DebugLogFmt("XOR key detected: 0x%016llX (score=%d)", (unsigned long long)bestKey, bestScore);
        return TRUE;
    }
    return FALSE;
}

static BOOL TryXorDecryptPage(PVOID srcPage, PVOID dstBuffer) {
    if (!g_xorKey) return FALSE;
    UINT64* src = (UINT64*)srcPage;
    UINT64* dst = (UINT64*)dstBuffer;
    for (int i = 0; i < 512; i++)
        dst[i] = src[i] ^ g_xorKey;
    return TRUE;
}

#define SYS_NtOpenThread 0x00C5
#define SYS_NtSuspendThread 0x00C7
#define SYS_NtResumeThread 0x00C8
#define SYS_NtGetContextThread 0x00F7
#define SYS_NtSetContextThread 0x00F8
#define SYS_NtAllocateVirtualMemory 0x0018
#define SYS_NtWriteVirtualMemory 0x003A
#define SYS_NtReadVirtualMemory 0x003F
#define SYS_NtProtectVirtualMemory 0x0050
#define SYS_NtFreeVirtualMemory 0x001F
#define SYS_NtCreateFile 0x0055
#define SYS_NtWriteFile 0x0008
#define SYS_NtClose 0x000F
#define SYS_NtDelayExecution 0x0034
#define SYS_NtQueryVirtualMemory 0x0023

typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0x00000000

#define OBJ_CASE_INSENSITIVE 0x00000040L

#define FILE_GENERIC_WRITE (STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE)

#define FILE_OVERWRITE_IF 0x00000005

#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_WRITE_THROUGH 0x00000002

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

#ifdef _WIN64
NTSTATUS NtOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    register NTSTATUS status asm("rax");
    register PHANDLE rcx_val asm("rcx") = ThreadHandle;
    register ACCESS_MASK rdx_val asm("rdx") = DesiredAccess;
    register POBJECT_ATTRIBUTES r8_val asm("r8") = ObjectAttributes;
    register PCLIENT_ID r9_val asm("r9") = ClientId;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x00C5, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtSuspendThread(
    HANDLE ThreadHandle,
    PULONG SuspendCount
) {
    register NTSTATUS status asm("rax");
    __asm__ __volatile__ (
        "movq %%rcx, %%r10\n\t"
        "movl $0x00C7, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "c" (ThreadHandle), "d" (SuspendCount)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtResumeThread(
    HANDLE ThreadHandle,
    PULONG SuspendCount
) {
    register NTSTATUS status asm("rax");
    __asm__ __volatile__ (
        "movq %%rcx, %%r10\n\t"
        "movl $0x00C8, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "c" (ThreadHandle), "d" (SuspendCount)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT Context
) {
    register NTSTATUS status asm("rax");
    __asm__ __volatile__ (
        "movq %%rcx, %%r10\n\t"
        "movl $0x00F7, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "c" (ThreadHandle), "d" (Context)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT Context
) {
    register NTSTATUS status asm("rax");
    __asm__ __volatile__ (
        "movq %%rcx, %%r10\n\t"
        "movl $0x00F8, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "c" (ThreadHandle), "d" (Context)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    (void)AllocationType; (void)Protect;
    register NTSTATUS status asm("rax");
    register HANDLE rcx_val asm("rcx") = ProcessHandle;
    register PVOID* rdx_val asm("rdx") = BaseAddress;
    register ULONG_PTR r8_val asm("r8") = ZeroBits;
    register PSIZE_T r9_val asm("r9") = RegionSize;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x0018, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
) {
    (void)NumberOfBytesWritten;
    register NTSTATUS status asm("rax");
    register HANDLE rcx_val asm("rcx") = ProcessHandle;
    register PVOID rdx_val asm("rdx") = BaseAddress;
    register PVOID r8_val asm("r8") = Buffer;
    register SIZE_T r9_val asm("r9") = BufferSize;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x003A, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
) {
    (void)NumberOfBytesRead;
    register NTSTATUS status asm("rax");
    register HANDLE rcx_val asm("rcx") = ProcessHandle;
    register PVOID rdx_val asm("rdx") = BaseAddress;
    register PVOID r8_val asm("r8") = Buffer;
    register SIZE_T r9_val asm("r9") = BufferSize;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x003F, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    (void)OldProtect;
    register NTSTATUS status asm("rax");
    register HANDLE rcx_val asm("rcx") = ProcessHandle;
    register PVOID* rdx_val asm("rdx") = BaseAddress;
    register PSIZE_T r8_val asm("r8") = RegionSize;
    register ULONG r9_val asm("r9") = NewProtect;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x0050, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) {
    register NTSTATUS status asm("rax");
    register HANDLE rcx_val asm("rcx") = ProcessHandle;
    register PVOID* rdx_val asm("rdx") = BaseAddress;
    register PSIZE_T r8_val asm("r8") = RegionSize;
    register ULONG r9_val asm("r9") = FreeType;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x001F, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

NTSTATUS NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    (void)AllocationSize; (void)FileAttributes; (void)ShareAccess;
    (void)CreateDisposition; (void)CreateOptions; (void)EaBuffer; (void)EaLength;
    register NTSTATUS status asm("rax");
    register PHANDLE rcx_val asm("rcx") = FileHandle;
    register ACCESS_MASK rdx_val asm("rdx") = DesiredAccess;
    register POBJECT_ATTRIBUTES r8_val asm("r8") = ObjectAttributes;
    register PIO_STATUS_BLOCK r9_val asm("r9") = IoStatusBlock;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x0055, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    (void)ApcContext; (void)IoStatusBlock; (void)Buffer; (void)Length; (void)ByteOffset; (void)Key;
    register NTSTATUS status asm("rax");
    register HANDLE rcx_val asm("rcx") = FileHandle;
    register HANDLE rdx_val asm("rdx") = Event;
    register PVOID r8_val asm("r8") = ApcRoutine;
    register PVOID r9_val asm("r9") = ApcContext;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x0008, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtClose(
    HANDLE Handle
) {
    register NTSTATUS status asm("rax");
    __asm__ __volatile__ (
        "movq %%rcx, %%r10\n\t"
        "movl $0x000F, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "c" (Handle)
        : "r10", "r11", "memory"
    );
    return status;
}

NTSTATUS NtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
) {
    register NTSTATUS status asm("rax");
    __asm__ __volatile__ (
        "movq %%rcx, %%r10\n\t"
        "movl $0x0034, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "c" (Alertable), "d" (DelayInterval)
        : "r10", "r11", "memory"
    );
    return status;
}

typedef enum _MEMORY_INFO_CLASS {
    MemInfoBasic = 0,
    MemInfoWorkingSet = 1,
    MemInfoMappedFilename = 2,
    MemInfoRegion = 3
} MEMORY_INFO_CLASS;

NTSTATUS NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFO_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
) {
    (void)MemoryInformationLength; (void)ReturnLength;
    register NTSTATUS status asm("rax");
    register HANDLE rcx_val asm("rcx") = ProcessHandle;
    register PVOID rdx_val asm("rdx") = BaseAddress;
    register MEMORY_INFO_CLASS r8_val asm("r8") = MemoryInformationClass;
    register PVOID r9_val asm("r9") = MemoryInformation;
    __asm__ __volatile__ (
        "movq %1, %%r10\n\t"
        "movl $0x0023, %%eax\n\t"
        "syscall\n\t"
        : "=a" (status)
        : "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val)
        : "r10", "r11", "memory"
    );
    return status;
}
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

static void StealthSleep(DWORD milliseconds) {
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)milliseconds * 10000LL;
    NtDelayExecution(FALSE, &interval);
}

static DWORD GetRandomDelay(DWORD minMs, DWORD maxMs) {
    ULONGLONG tsc = __rdtsc();
    
    DWORD_PTR stackPtr = (DWORD_PTR)&tsc;
    
    DWORD entropy = (DWORD)(tsc & 0xFFFFFFFF);
    entropy ^= (DWORD)(tsc >> 32);
    entropy ^= (DWORD)(stackPtr & 0xFFFFFFFF);
    entropy ^= (DWORD)(stackPtr >> 32);
    
    entropy = (entropy << 7) ^ (entropy >> 25);
    entropy ^= (entropy << 13);
    entropy ^= (entropy >> 19);
    entropy = entropy * 0x9E3779B9;
    entropy ^= (entropy >> 16);
    
    return minMs + (entropy % (maxMs - minMs + 1));
}

static void RandomStealthSleep(DWORD minMs, DWORD maxMs) {
    DWORD delay = GetRandomDelay(minMs, maxMs);
    StealthSleep(delay);
}

static void SecureZeroBuffer(volatile PVOID ptr, SIZE_T size) {
    volatile BYTE* p = (volatile BYTE*)ptr;
    while (size--) {
        *p++ = 0;
    }
    _ReadWriteBarrier();
}

static CRITICAL_SECTION g_tlsLock;

typedef struct {
    PVOID targetPage;
    PVOID destBuffer;
    DWORD64 originalRip;
    DWORD64 originalRsp;
    DWORD64 originalRflags;
    HANDLE completionEvent;
    volatile BOOL decrypted;
    volatile BOOL inProgress;
    DWORD pageSize;
} FORCED_DECRYPT_STATE;

static FORCED_DECRYPT_STATE g_forceDecrypt = {0};
static PVOID g_vehHandle = NULL;
static CRITICAL_SECTION g_decryptLock;

static volatile BOOL g_execDecryptInProgress = FALSE;
static volatile PVOID g_execDecryptTarget = NULL;
static volatile PVOID g_execDecryptDest = NULL;
static volatile BOOL g_execDecryptSuccess = FALSE;
static HANDLE g_execDecryptEvent = NULL;
static volatile DWORD g_decryptedPages = 0;

static LONG CALLBACK DecryptCaptureVEH(PEXCEPTION_POINTERS ep) {
    if (!g_execDecryptInProgress) return EXCEPTION_CONTINUE_SEARCH;
    
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    DWORD64 addr = (DWORD64)ep->ExceptionRecord->ExceptionAddress;
    DWORD64 target = (DWORD64)g_execDecryptTarget;
    
    if (code == EXCEPTION_SINGLE_STEP) {
        if (addr >= target && addr < target + 4096) {
            memcpy(g_execDecryptDest, g_execDecryptTarget, 4096);
            g_execDecryptSuccess = TRUE;
            g_decryptedPages++;
            g_execDecryptInProgress = FALSE;
            if (g_execDecryptEvent) SetEvent(g_execDecryptEvent);
            
            ep->ContextRecord->Rip = (DWORD64)ExitThread;
            ep->ContextRecord->Rcx = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    if (code == EXCEPTION_BREAKPOINT) {
        if (addr >= target && addr < target + 4096) {
            memcpy(g_execDecryptDest, g_execDecryptTarget, 4096);
            g_execDecryptSuccess = TRUE;
            g_decryptedPages++;
            g_execDecryptInProgress = FALSE;
            if (g_execDecryptEvent) SetEvent(g_execDecryptEvent);
            ep->ContextRecord->Rip = (DWORD64)ExitThread;
            ep->ContextRecord->Rcx = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL InitForcedDecryption(void) {
    InitializeCriticalSection(&g_decryptLock);
    
    g_forceDecrypt.completionEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_forceDecrypt.completionEvent) return FALSE;
    
    g_forceDecrypt.pageSize = 4096;
    g_forceDecrypt.inProgress = FALSE;
    
    g_vehHandle = AddVectoredExceptionHandler(0, DecryptCaptureVEH);
    if (!g_vehHandle) {
        CloseHandle(g_forceDecrypt.completionEvent);
        return FALSE;
    }
    
    return TRUE;
}

static void CleanupForcedDecryption(void) {
    if (g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = NULL;
    }
    if (g_forceDecrypt.completionEvent) {
        CloseHandle(g_forceDecrypt.completionEvent);
        g_forceDecrypt.completionEvent = NULL;
    }
    DeleteCriticalSection(&g_decryptLock);
}

static void* g_wowMemcpy = NULL;

static void* FindImportedFunction(PVOID moduleBase, const char* dllName, const char* funcName) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)moduleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    DWORD importRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) return NULL;
    
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)moduleBase + importRva);
    
    while (pImport->Name) {
        char* importDllName = (char*)((LPBYTE)moduleBase + pImport->Name);
        
        if (_stricmp(importDllName, dllName) == 0) {
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((LPBYTE)moduleBase + 
                (pImport->OriginalFirstThunk ? pImport->OriginalFirstThunk : pImport->FirstThunk));
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)moduleBase + pImport->FirstThunk);
            
            while (pOrigThunk->u1.AddressOfData) {
                if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)moduleBase + pOrigThunk->u1.AddressOfData);
                    if (strcmp((char*)pName->Name, funcName) == 0) {
                        return (void*)pThunk->u1.Function;
                    }
                }
                pOrigThunk++;
                pThunk++;
            }
        }
        pImport++;
    }
    
    return NULL;
}

static void* FindWowMemcpyFromIAT(PVOID wowBase) {
    void* func = NULL;
    
    const char* dllNames[] = {
        "VCRUNTIME140.dll",
        "vcruntime140.dll", 
        "msvcrt.dll",
        "MSVCRT.dll",
        "ucrtbase.dll",
        "UCRTBASE.dll",
        "api-ms-win-crt-string-l1-1-0.dll",
        "ntdll.dll",
        "NTDLL.dll",
        NULL
    };
    
    const char* funcNames[] = {
        "memcpy",
        "memmove", 
        "RtlMoveMemory",
        "RtlCopyMemory",
        NULL
    };
    
    for (int i = 0; dllNames[i]; i++) {
        for (int j = 0; funcNames[j]; j++) {
            func = FindImportedFunction(wowBase, dllNames[i], funcNames[j]);
            if (func) {
                return func;
            }
        }
    }
    
    return NULL;
}

static void* FindMemcpyFromLoadedModules(void) {
    HMODULE hVcrt = GetModuleHandleA("VCRUNTIME140.dll");
    if (hVcrt) {
        void* func = GetProcAddress(hVcrt, "memcpy");
        if (func) return func;
        func = GetProcAddress(hVcrt, "memmove");
        if (func) return func;
    }
    
    HMODULE hUcrt = GetModuleHandleA("ucrtbase.dll");
    if (hUcrt) {
        void* func = GetProcAddress(hUcrt, "memcpy");
        if (func) return func;
        func = GetProcAddress(hUcrt, "memmove");
        if (func) return func;
    }
    
    HMODULE hMsvcrt = GetModuleHandleA("msvcrt.dll");
    if (hMsvcrt) {
        void* func = GetProcAddress(hMsvcrt, "memcpy");
        if (func) return func;
        func = GetProcAddress(hMsvcrt, "memmove");
        if (func) return func;
    }
    
    return NULL;
}

static void* FindWowMemcpy(PVOID wowBase) {
    void* func = FindWowMemcpyFromIAT(wowBase);
    if (func) return func;
    
    return FindMemcpyFromLoadedModules();
}

static void* GetWowMemcpy(void) {
    if (g_wowMemcpy) return g_wowMemcpy;
    
    PPEB peb = GET_PEB();
    if (peb && peb->ImageBaseAddress) {
        g_wowMemcpy = FindWowMemcpy(peb->ImageBaseAddress);
    }
    
    return g_wowMemcpy;
}

static void* GetFallbackMemcpy(void) {
    HMODULE hMsvcrt = GetModuleHandleA("msvcrt.dll");
    if (hMsvcrt) {
        void* func = GetProcAddress(hMsvcrt, "memcpy");
        if (func) return func;
    }
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        void* func = GetProcAddress(hNtdll, "RtlMoveMemory");
        if (func) return func;
    }
    
    return NULL;
}

typedef void* (*memcpy_t)(void* dest, const void* src, size_t count);
static void* SpoofedMemcpy(void* dest, const void* src, size_t count) {
    memcpy_t wow_memcpy = (memcpy_t)GetWowMemcpy();
    if (wow_memcpy) {
        return wow_memcpy(dest, src, count);
    }
    
    memcpy_t fallback = (memcpy_t)GetFallbackMemcpy();
    if (fallback) {
        return fallback(dest, src, count);
    }
    
    return memcpy(dest, src, count);
}

static void InitSpoofedCall(PVOID wowBase) {
    void* iatFunc = FindWowMemcpyFromIAT(wowBase);
    if (iatFunc) {
        g_wowMemcpy = iatFunc;
        return;
    }
    
    void* modFunc = FindMemcpyFromLoadedModules();
    if (modFunc) {
        g_wowMemcpy = modFunc;
        return;
    }
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        g_wowMemcpy = GetProcAddress(hNtdll, "RtlMoveMemory");
    }
}

#define MAX_TLS_CALLBACKS 64

typedef struct _TLS_CALLBACK_TRACKER {
    PVOID callbacks[MAX_TLS_CALLBACKS];
    int count;
    BOOL initialized;
    PVOID originalCallbackArray;
    DWORD originalCallbackArrayRva;
} TLS_CALLBACK_TRACKER;

static TLS_CALLBACK_TRACKER g_tlsTracker = {0};

static BOOL IsTlsCallbackTracked(PVOID callback) {
    if (!callback) return TRUE;
    for (int i = 0; i < g_tlsTracker.count; i++) {
        if (g_tlsTracker.callbacks[i] == callback) return TRUE;
    }
    return FALSE;
}

static void TrackTlsCallback(PVOID callback) {
    if (!callback) return;
    if (IsTlsCallbackTracked(callback)) return;
    if (g_tlsTracker.count >= MAX_TLS_CALLBACKS) return;
    
    EnterCriticalSection(&g_tlsLock);
    if (!IsTlsCallbackTracked(callback) && g_tlsTracker.count < MAX_TLS_CALLBACKS) {
        g_tlsTracker.callbacks[g_tlsTracker.count++] = callback;
    }
    LeaveCriticalSection(&g_tlsLock);
}

static void ScanAndTrackTlsCallbacks(PVOID imageBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return;
    
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)imageBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return;
    
    DWORD tlsRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (!tlsRva) return;
    
    PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)((LPBYTE)imageBase + tlsRva);
    if (!pTls->AddressOfCallBacks) return;
    
    g_tlsTracker.originalCallbackArray = (PVOID)pTls->AddressOfCallBacks;
    DWORD_PTR imageStart = (DWORD_PTR)imageBase;
    g_tlsTracker.originalCallbackArrayRva = (DWORD)((DWORD_PTR)pTls->AddressOfCallBacks - imageStart);
    
    PVOID* callbackArray = (PVOID*)pTls->AddressOfCallBacks;
    for (int i = 0; i < MAX_TLS_CALLBACKS; i++) {
        PVOID cb = NULL;
        SpoofedMemcpy(&cb, &callbackArray[i], sizeof(PVOID));
        if (!cb) break;
        TrackTlsCallback(cb);
    }
}

static void InitTlsCallbackTracking(PVOID imageBase) {
    if (g_tlsTracker.initialized) return;
    
    EnterCriticalSection(&g_tlsLock);
    if (!g_tlsTracker.initialized) {
        g_tlsTracker.initialized = TRUE;
        g_tlsTracker.count = 0;
        ScanAndTrackTlsCallbacks(imageBase);
    }
    LeaveCriticalSection(&g_tlsLock);
}

static PIMAGE_TLS_DIRECTORY GetTlsDirectory(PVOID imageBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)imageBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    DWORD tlsRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (!tlsRva) return NULL;
    
    return (PIMAGE_TLS_DIRECTORY)((LPBYTE)imageBase + tlsRva);
}

static void ReconstructTlsCallbacks(PVOID imageBase, PVOID dumpBuffer, SIZE_T imageSize) {
    PIMAGE_DOS_HEADER pDumpDos = (PIMAGE_DOS_HEADER)dumpBuffer;
    PIMAGE_NT_HEADERS pDumpNt = (PIMAGE_NT_HEADERS)((LPBYTE)dumpBuffer + pDumpDos->e_lfanew);
    
    DWORD tlsRva = pDumpNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (!tlsRva) return;
    
    PIMAGE_TLS_DIRECTORY pDumpTls = (PIMAGE_TLS_DIRECTORY)((LPBYTE)dumpBuffer + tlsRva);
    PIMAGE_TLS_DIRECTORY pOrigTls = (PIMAGE_TLS_DIRECTORY)((LPBYTE)imageBase + tlsRva);
    
    SpoofedMemcpy(pDumpTls, pOrigTls, sizeof(IMAGE_TLS_DIRECTORY));
    
    if (g_tlsTracker.count > 0 && g_tlsTracker.originalCallbackArrayRva > 0) {
        DWORD_PTR callbackRva = g_tlsTracker.originalCallbackArrayRva;
        
        if (callbackRva < imageSize) {
            PVOID* dumpCallbacks = (PVOID*)((LPBYTE)dumpBuffer + callbackRva);
            
            for (int i = 0; i < g_tlsTracker.count && i < MAX_TLS_CALLBACKS; i++) {
                dumpCallbacks[i] = g_tlsTracker.callbacks[i];
            }
            if (g_tlsTracker.count < MAX_TLS_CALLBACKS) {
                dumpCallbacks[g_tlsTracker.count] = NULL;
            }
            
            return;
        }
    }
    
    if (pOrigTls->AddressOfCallBacks) {
        DWORD_PTR imageStart = (DWORD_PTR)imageBase;
        DWORD_PTR callbackAddr = (DWORD_PTR)pOrigTls->AddressOfCallBacks;
        
        if (callbackAddr >= imageStart && callbackAddr < imageStart + imageSize) {
            DWORD_PTR callbackRva = callbackAddr - imageStart;
            PVOID* origCallbacks = (PVOID*)pOrigTls->AddressOfCallBacks;
            PVOID* dumpCallbacks = (PVOID*)((LPBYTE)dumpBuffer + callbackRva);
            
            for (int i = 0; i < 32; i++) {
                PVOID cb = NULL;
                SpoofedMemcpy(&cb, &origCallbacks[i], sizeof(PVOID));
                dumpCallbacks[i] = cb;
                if (!cb) break;
            }
        }
    }
}

static BOOL ReconstructIAT(PVOID imageBase, PVOID dumpBuffer, SIZE_T imageSize) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)imageBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)imageBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    
    DWORD importRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) return FALSE;
    
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)imageBase + importRva);
    
    IMAGE_IMPORT_DESCRIPTOR importDesc;
    int dllCount = 0;
    int funcCount = 0;
    
    while (TRUE) {
        SpoofedMemcpy(&importDesc, pImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!importDesc.Name) break;
        
        char dllName[256] = {0};
        char* dllNamePtr = (char*)((LPBYTE)imageBase + importDesc.Name);
        SpoofedMemcpy(dllName, dllNamePtr, sizeof(dllName) - 1);
        
        HMODULE hModule = NULL;
        PPEB peb = GET_PEB();
        if (peb && peb->Ldr) {
            PLIST_ENTRY entry = peb->Ldr->InLoadOrderModuleList.Flink;
            while (entry != &peb->Ldr->InLoadOrderModuleList) {
                PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (ldrEntry->BaseDllName.Buffer) {
                    char entryName[256] = {0};
                    WideCharToMultiByte(CP_ACP, 0, ldrEntry->BaseDllName.Buffer,
                                       ldrEntry->BaseDllName.Length / sizeof(WCHAR),
                                       entryName, sizeof(entryName) - 1, NULL, NULL);
                    if (_stricmp(entryName, dllName) == 0) {
                        hModule = (HMODULE)ldrEntry->DllBase;
                        break;
                    }
                }
                entry = entry->Flink;
            }
        }
        
        if (!hModule) {
            pImport++;
            continue;
        }
        
        dllCount++;
        
        if (importDesc.OriginalFirstThunk) {
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((LPBYTE)imageBase + importDesc.OriginalFirstThunk);
            PIMAGE_THUNK_DATA pDumpThunk = (PIMAGE_THUNK_DATA)((LPBYTE)dumpBuffer + importDesc.FirstThunk);
            
            IMAGE_THUNK_DATA thunk;
            int idx = 0;
            
            while (idx < 10000) {
                SpoofedMemcpy(&thunk, &pOrigThunk[idx], sizeof(IMAGE_THUNK_DATA));
                if (!thunk.u1.AddressOfData) break;
                
                FARPROC proc = NULL;
                
                if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    WORD ordinal = (WORD)(thunk.u1.Ordinal & 0xFFFF);
                    proc = GetProcAddress(hModule, (LPCSTR)(ULONG_PTR)ordinal);
                } else {
                    DWORD_PTR hintNameRva = thunk.u1.AddressOfData;
                    if (hintNameRva < imageSize) {
                        PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)imageBase + hintNameRva);
                        char funcName[256] = {0};
                        SpoofedMemcpy(funcName, pName->Name, sizeof(funcName) - 1);
                        if (funcName[0]) {
                            proc = GetProcAddress(hModule, funcName);
                        }
                    }
                }
                
                if (proc) {
                    pDumpThunk[idx].u1.Function = (ULONG_PTR)proc;
                    funcCount++;
                }
                idx++;
            }
        }
        
        pImport++;
    }
    
    return (dllCount > 0);
}

static void MakeNtPath(const char* ansiPath, WCHAR* ntPath, SIZE_T ntPathSize) {
    char fullPath[MAX_PATH];
    GetFullPathNameA(ansiPath, MAX_PATH, fullPath, NULL);
    
    ntPath[0] = L'\\';
    ntPath[1] = L'?';
    ntPath[2] = L'?';
    ntPath[3] = L'\\';
    MultiByteToWideChar(CP_ACP, 0, fullPath, -1, ntPath + 4, (int)(ntPathSize - 4));
}

static HANDLE StealthCreateFile(const char* filename) {
    WCHAR ntPath[MAX_PATH + 8];
    MakeNtPath(filename, ntPath, MAX_PATH + 8);
    
    UNICODE_STRING uniPath;
    uniPath.Length = (USHORT)(wcslen(ntPath) * sizeof(WCHAR));
    uniPath.MaximumLength = uniPath.Length + sizeof(WCHAR);
    uniPath.Buffer = ntPath;
    
    OBJECT_ATTRIBUTES objAttr;
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    objAttr.RootDirectory = NULL;
    objAttr.ObjectName = &uniPath;
    objAttr.Attributes = OBJ_CASE_INSENSITIVE;
    objAttr.SecurityDescriptor = NULL;
    objAttr.SecurityQualityOfService = NULL;
    
    IO_STATUS_BLOCK ioStatus;
    HANDLE hFile = NULL;
    
    ULONG fileAttributes = 0x06;
    
    NTSTATUS status = NtCreateFile(
        &hFile,
        FILE_GENERIC_WRITE,
        &objAttr,
        &ioStatus,
        NULL,
        fileAttributes,
        0,
        FILE_OVERWRITE_IF,
        FILE_SEQUENTIAL_ONLY | FILE_WRITE_THROUGH,
        NULL,
        0
    );
    
    if (status != STATUS_SUCCESS) {
        return INVALID_HANDLE_VALUE;
    }
    
    return hFile;
}

static BOOL StealthWriteFile(HANDLE hFile, PVOID buffer, ULONG length, PULONG bytesWritten) {
    IO_STATUS_BLOCK ioStatus;
    
    NTSTATUS status = NtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        buffer,
        length,
        NULL,
        NULL
    );
    
    if (status == STATUS_SUCCESS) {
        if (bytesWritten) *bytesWritten = (ULONG)ioStatus.Information;
        return TRUE;
    }
    return FALSE;
}

static void StealthCloseFile(HANDLE hFile) {
    NtClose(hFile);
}

static void DebugLog(const char* msg) {
    HANDLE hFile = CreateFileA(OutputPath("autodump.log"), FILE_APPEND_DATA,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
        WriteFile(hFile, "\r\n", 2, &written, NULL);
        CloseHandle(hFile);
    }
}

static void DebugLogFmt(const char* fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    DebugLog(buf);
}

static void DebugLogSessionHeader(void) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[128];
    snprintf(buf, sizeof(buf),
             "\r\n=== AutoDump session %04d-%02d-%02d %02d:%02d:%02d ===",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    DebugLog(buf);
    DebugLogFmt("OutputPath: %s",
                (g_outputPath[0] > 1) ? (const char*)g_outputPath : "(not set, using target CWD)");
}

static int IsValidFuncName(const char* str, int maxLen) {
    if (!str || !isalpha(str[0]) && str[0] != '_') return 0;
    int len = 0;
    for (int i = 0; i < maxLen && str[i]; i++) {
        char c = str[i];
        if (!isalnum(c) && c != '_') return 0;
        len++;
    }
    return (len >= 2 && len < MAX_NAME_LEN - 1) ? len : 0;
}

static int IsValidCodeRVA(uint64_t rva, uint64_t textStart, uint64_t textEnd, uint8_t* mem) {
    if (rva < textStart || rva >= textEnd) return 0;
    uint8_t* p = mem + rva;
    if (p[0] == 0x55) return 1;
    if (p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57) return 1;
    if (p[0] == 0x41 && (p[1] >= 0x54 && p[1] <= 0x57)) return 1;
    if (p[0] == 0x40 && (p[1] >= 0x50 && p[1] <= 0x57)) return 1;
    if (p[0] == 0x48 && p[1] == 0x89) return 1;
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return 1;
    if (p[0] == 0x48 && p[1] == 0x8B) return 1;
    if (p[0] == 0x4C && p[1] == 0x89) return 1;
    if (p[0] == 0x4C && p[1] == 0x8B) return 1;
    if (p[0] == 0x33 || p[0] == 0x31) return 1;
    if (p[0] == 0xB8 || p[0] == 0xE9 || p[0] == 0xE8) return 1;
    if (p[0] == 0x44 || p[0] == 0x45 || p[0] == 0x49) return 1;
    return 0;
}

static void AddOffset(const char* name, int nameLen, uint64_t rva, OffsetType type) {
    if (!g_offsets || g_offsetCount >= MAX_OFFSETS) return;
    
    for (int i = 0; i < g_offsetCount; i++) {
        if (strncmp(g_offsets[i].name, name, nameLen) == 0 && g_offsets[i].name[nameLen] == 0) {
            return;
        }
    }
    
    EnterCriticalSection(&g_offsetLock);
    if (g_offsetCount < MAX_OFFSETS) {
        strncpy(g_offsets[g_offsetCount].name, name, nameLen);
        g_offsets[g_offsetCount].name[nameLen] = 0;
        g_offsets[g_offsetCount].rva = rva;
        g_offsets[g_offsetCount].type = type;
        g_offsetCount++;
    }
    LeaveCriticalSection(&g_offsetLock);
}

static void ExtractLuaFunctions(PVOID moduleBase, uint8_t* dumpBuffer, DWORD imageSize,
                                 uint64_t textStart, uint64_t textEnd,
                                 uint64_t rdataStart, uint64_t rdataEnd,
                                 uint64_t dataStart, uint64_t dataEnd) {
    char logBuf[128];
    uint64_t imageBaseVA = (uint64_t)moduleBase;
    int luaFuncs = 0, bindings = 0, leaRefs = 0;
    
    for (uint64_t addr = rdataStart; addr < rdataEnd - 16 && addr < imageSize - 16; addr += 8) {
        uint64_t ptr1 = *(uint64_t*)(dumpBuffer + addr);
        uint64_t ptr2 = *(uint64_t*)(dumpBuffer + addr + 8);
        
        if (ptr1 < imageBaseVA || ptr2 < imageBaseVA) continue;
        
        uint64_t strRva = ptr1 - imageBaseVA;
        uint64_t codeRva = ptr2 - imageBaseVA;
        
        if (strRva < rdataStart || strRva >= rdataEnd) continue;
        if (codeRva < textStart || codeRva >= textEnd) continue;
        if (strRva >= imageSize || codeRva >= imageSize) continue;
        
        char* str = (char*)(dumpBuffer + strRva);
        int nameLen = IsValidFuncName(str, 100);
        if (!nameLen) continue;
        
        if (IsValidCodeRVA(codeRva, textStart, textEnd, dumpBuffer)) {
            AddOffset(str, nameLen, codeRva, OFFSET_LUA_FUNCTION);
            luaFuncs++;
        }
    }
    
    for (uint64_t addr = dataStart; addr < dataEnd - 16 && addr < imageSize - 16; addr += 8) {
        uint64_t ptr1 = *(uint64_t*)(dumpBuffer + addr);
        uint64_t ptr2 = *(uint64_t*)(dumpBuffer + addr + 8);
        
        if (ptr1 < imageBaseVA || ptr2 < imageBaseVA) continue;
        
        uint64_t strRva = ptr1 - imageBaseVA;
        uint64_t codeRva = ptr2 - imageBaseVA;
        
        if (strRva < rdataStart || strRva >= rdataEnd) continue;
        if (codeRva < textStart || codeRva >= textEnd) continue;
        if (strRva >= imageSize || codeRva >= imageSize) continue;
        
        char* str = (char*)(dumpBuffer + strRva);
        int nameLen = IsValidFuncName(str, 100);
        if (!nameLen) continue;
        
        AddOffset(str, nameLen, codeRva, OFFSET_BINDING_COMMAND);
        bindings++;
    }
    
    for (uint64_t addr = textStart; addr < textEnd - 7 && addr < imageSize - 7; addr++) {
        uint8_t* p = dumpBuffer + addr;
        
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8D) {
            uint8_t modrm = p[2];
            if ((modrm & 0xC7) == 0x05) {
                int32_t disp = *(int32_t*)(p + 3);
                uint64_t targetRva = addr + 7 + disp;
                
                if (targetRva >= rdataStart && targetRva < rdataEnd && targetRva < imageSize) {
                    char* str = (char*)(dumpBuffer + targetRva);
                    int nameLen = IsValidFuncName(str, 100);
                    
                    if (nameLen) {
                        uint64_t funcStart = 0;
                        for (int back = 0; back < 256; back++) {
                            uint64_t check = addr - back;
                            if (check <= textStart) break;
                            
                            if (back > 0) {
                                uint8_t prev = dumpBuffer[check - 1];
                                if (prev == 0xCC || prev == 0xC3 || prev == 0xC2) {
                                    if (IsValidCodeRVA(check, textStart, textEnd, dumpBuffer)) {
                                        funcStart = check;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if (funcStart) {
                            AddOffset(str, nameLen, funcStart, OFFSET_LUA_FUNCTION);
                            leaRefs++;
                        }
                    }
                }
            }
        }
    }
    
    snprintf(logBuf, sizeof(logBuf), "Lua: %d funcs, %d bindings, %d LEA refs", luaFuncs, bindings, leaRefs);
    DebugLog(logBuf);
}

static void ExtractGlobalOffsets(PVOID moduleBase, uint8_t* dumpBuffer, DWORD imageSize,
                                  uint64_t textStart, uint64_t textEnd,
                                  uint64_t dataStart, uint64_t dataEnd) {
    char logBuf[128];
    uint64_t imageBaseVA = (uint64_t)moduleBase;
    int globals = 0;
    
    typedef struct {
        uint64_t rva;
        int refCount;
        int accessOffsets[8];
        int accessCount;
    } GlobalCandidate;
    
    #define MAX_CANDIDATES 1024
    GlobalCandidate* candidates = VirtualAlloc(NULL, MAX_CANDIDATES * sizeof(GlobalCandidate), 
                                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!candidates) return;
    int candidateCount = 0;
    
    for (uint64_t addr = textStart; addr < textEnd - 14 && addr < imageSize - 14; addr++) {
        uint8_t* p = dumpBuffer + addr;
        
        if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x05) {
            int32_t disp = *(int32_t*)(p + 3);
            uint64_t globalRva = addr + 7 + disp;
            
            if (globalRva >= dataStart && globalRva < dataEnd && globalRva < imageSize) {
                int accessOffset = -1;
                
                if (p[7] == 0x48 && p[8] == 0x8B) {
                    uint8_t modrm = p[9];
                    if ((modrm & 0xC0) == 0x40) {
                        accessOffset = (int8_t)p[10];
                    } else if ((modrm & 0xC0) == 0x80) {
                        accessOffset = *(int32_t*)(p + 10);
                    } else if ((modrm & 0xC0) == 0x00) {
                        accessOffset = 0;
                    }
                }
                
                int found = -1;
                for (int i = 0; i < candidateCount; i++) {
                    if (candidates[i].rva == globalRva) {
                        found = i;
                        break;
                    }
                }
                
                if (found >= 0) {
                    candidates[found].refCount++;
                    if (accessOffset >= 0 && candidates[found].accessCount < 8) {
                        int alreadyHas = 0;
                        for (int j = 0; j < candidates[found].accessCount; j++) {
                            if (candidates[found].accessOffsets[j] == accessOffset) {
                                alreadyHas = 1;
                                break;
                            }
                        }
                        if (!alreadyHas) {
                            candidates[found].accessOffsets[candidates[found].accessCount++] = accessOffset;
                        }
                    }
                } else if (candidateCount < MAX_CANDIDATES) {
                    candidates[candidateCount].rva = globalRva;
                    candidates[candidateCount].refCount = 1;
                    candidates[candidateCount].accessCount = 0;
                    if (accessOffset >= 0) {
                        candidates[candidateCount].accessOffsets[0] = accessOffset;
                        candidates[candidateCount].accessCount = 1;
                    }
                    candidateCount++;
                }
            }
        }
        
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8D && (p[2] & 0xC7) == 0x05) {
            int32_t disp = *(int32_t*)(p + 3);
            uint64_t targetRva = addr + 7 + disp;
            
            if (targetRva >= dataStart && targetRva < dataEnd && targetRva < imageSize) {
                int found = -1;
                for (int i = 0; i < candidateCount; i++) {
                    if (candidates[i].rva == targetRva) {
                        found = i;
                        break;
                    }
                }
                
                if (found >= 0) {
                    candidates[found].refCount++;
                } else if (candidateCount < MAX_CANDIDATES) {
                    candidates[candidateCount].rva = targetRva;
                    candidates[candidateCount].refCount = 1;
                    candidates[candidateCount].accessCount = 0;
                    candidateCount++;
                }
            }
        }
    }
    
    for (int i = 0; i < candidateCount; i++) {
        if (candidates[i].refCount >= 5) {
            uint64_t rva = candidates[i].rva;
            uint64_t value = 0;
            if (rva + 8 <= imageSize) {
                value = *(uint64_t*)(dumpBuffer + rva);
            }
            
            char name[64];
            if (candidates[i].accessCount > 0 && 
                (candidates[i].accessOffsets[0] == 0x8 || candidates[i].accessOffsets[0] == 0x10)) {
                snprintf(name, sizeof(name), "g_Manager_%llX", (unsigned long long)rva);
            } else if (value >= imageBaseVA && value < imageBaseVA + imageSize) {
                snprintf(name, sizeof(name), "g_Ptr_%llX", (unsigned long long)rva);
            } else {
                snprintf(name, sizeof(name), "g_Data_%llX", (unsigned long long)rva);
            }
            
            AddOffset(name, (int)strlen(name), rva, OFFSET_GLOBAL_POINTER);
            globals++;
        }
    }
    
    const char* knownPatterns[] = {"Camera", "Player", "Object", "Entity", "Unit", "Spell", NULL};
    
    for (uint64_t addr = dataStart; addr < dataEnd - 8 && addr < imageSize - 8; addr += 8) {
        uint64_t ptr = *(uint64_t*)(dumpBuffer + addr);
        
        if (ptr >= imageBaseVA && ptr < imageBaseVA + imageSize) {
            uint64_t targetRva = ptr - imageBaseVA;
            
            if (targetRva >= 0x335A000 && targetRva < 0x3C8CAF8 && targetRva < imageSize) {
                char* str = (char*)(dumpBuffer + targetRva);
                
                for (int k = 0; knownPatterns[k]; k++) {
                    if (strncmp(str, knownPatterns[k], strlen(knownPatterns[k])) == 0) {
                        int nameLen = IsValidFuncName(str, 64);
                        if (nameLen) {
                            char fullName[80];
                            snprintf(fullName, sizeof(fullName), "g_%s", str);
                            AddOffset(fullName, (int)strlen(fullName), addr, OFFSET_STATIC_DATA);
                            globals++;
                        }
                        break;
                    }
                }
            }
        }
    }
    
    VirtualFree(candidates, 0, MEM_RELEASE);
    snprintf(logBuf, sizeof(logBuf), "Globals: %d offsets", globals);
    DebugLog(logBuf);
}

static void WriteOffsetsFile(PVOID moduleBase) {
    char logBuf[128];
    
    HANDLE hFile = CreateFileA(OutputPath("wow_offsets.txt"), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLog("Failed to create wow_offsets.txt");
        return;
    }
    
    char header[512];
    int headerLen = snprintf(header, sizeof(header),
        "// WoW Offsets - Auto-extracted\r\n"
        "// Image Base: 0x%llX\r\n"
        "// Total: %d offsets\r\n\r\n",
        (unsigned long long)moduleBase, g_offsetCount);
    
    DWORD written;
    WriteFile(hFile, header, headerLen, &written, NULL);
    
    int luaCount = 0, bindCount = 0, globalCount = 0, staticCount = 0;
    for (int i = 0; i < g_offsetCount; i++) {
        switch (g_offsets[i].type) {
            case OFFSET_LUA_FUNCTION: luaCount++; break;
            case OFFSET_BINDING_COMMAND: bindCount++; break;
            case OFFSET_GLOBAL_POINTER: globalCount++; break;
            case OFFSET_STATIC_DATA: staticCount++; break;
        }
    }
    
    const char* sections[] = {
        "\r\n// === LUA FUNCTIONS ===\r\n\r\n",
        "\r\n// === BINDING COMMANDS ===\r\n\r\n",
        "\r\n// === GLOBAL POINTERS ===\r\n\r\n",
        "\r\n// === STATIC DATA ===\r\n\r\n"
    };
    
    for (int t = 0; t < 4; t++) {
        WriteFile(hFile, sections[t], (DWORD)strlen(sections[t]), &written, NULL);
        
        for (int i = 0; i < g_offsetCount; i++) {
            if (g_offsets[i].type == t) {
                char line[256];
                int lineLen = snprintf(line, sizeof(line), "%s = 0x%llX\r\n",
                                       g_offsets[i].name, (unsigned long long)g_offsets[i].rva);
                WriteFile(hFile, line, lineLen, &written, NULL);
            }
        }
    }
    
    CloseHandle(hFile);
    
    snprintf(logBuf, sizeof(logBuf), "wow_offsets.txt: %d lua, %d bind, %d global, %d static",
             luaCount, bindCount, globalCount, staticCount);
    DebugLog(logBuf);
}

static PVOID FindModuleByName(const wchar_t* moduleName) {
    PPEB peb = GET_PEB();
    if (!peb || !peb->Ldr) return NULL;
    
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    
    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        if (entry->BaseDllName.Buffer) {
            BOOL match = TRUE;
            for (USHORT i = 0; i < entry->BaseDllName.Length / sizeof(wchar_t); i++) {
                wchar_t c1 = entry->BaseDllName.Buffer[i];
                wchar_t c2 = moduleName[i];
                
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                
                if (c1 != c2) {
                    match = FALSE;
                    break;
                }
                if (c2 == 0) break;
            }
            
            if (match && moduleName[entry->BaseDllName.Length / sizeof(wchar_t)] == 0) {
                return entry->DllBase;
            }
        }
        current = current->Flink;
    }
    
    return NULL;
}

static DecryptGadgetFunc FindLoaderDecryptGadget(PVOID loaderBase, DWORD imageSize) {
    LPBYTE p = (LPBYTE)loaderBase;
    
    for (DWORD offset = 0x1000; offset < imageSize - 4; offset++) {
        if (p[offset] == 0x48 && p[offset+1] == 0x8B && 
            p[offset+2] == 0x01 && p[offset+3] == 0xC3) {
            if (offset > 0 && (p[offset-1] == 0xCC || p[offset-1] == 0xC3 || p[offset-1] == 0x90)) {
                return (DecryptGadgetFunc)(p + offset);
            }
        }
    }
    
    for (DWORD offset = 0x1000; offset < imageSize - 8; offset++) {
        if (p[offset] == 0x48 && p[offset+1] == 0x8B && p[offset+2] == 0x01 &&
            p[offset+3] == 0x48 && p[offset+4] == 0x31 && p[offset+7] == 0xC3) {
            return (DecryptGadgetFunc)(p + offset);
        }
    }
    
    return NULL;
}

static void DumpLoaderExports(PVOID loaderBase, PIMAGE_NT_HEADERS pNt) {
    DWORD exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    
    if (!exportRva || !exportSize) {
        DebugLog("Loader: No exports");
        return;
    }
    
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)loaderBase + exportRva);
    
    DWORD* nameRvas = (DWORD*)((LPBYTE)loaderBase + pExport->AddressOfNames);
    DWORD* funcRvas = (DWORD*)((LPBYTE)loaderBase + pExport->AddressOfFunctions);
    WORD* ordinals = (WORD*)((LPBYTE)loaderBase + pExport->AddressOfNameOrdinals);
    
    HANDLE hFile = CreateFileA(OutputPath("wow_loader_exports.txt"), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    char header[128];
    int headerLen = snprintf(header, sizeof(header), 
        "// Wow_loader.dll Exports\r\n// Base: 0x%p\r\n// Count: %lu\r\n\r\n",
        loaderBase, pExport->NumberOfNames);
    DWORD written;
    WriteFile(hFile, header, headerLen, &written, NULL);
    
    for (DWORD i = 0; i < pExport->NumberOfNames && i < 1000; i++) {
        char* funcName = (char*)((LPBYTE)loaderBase + nameRvas[i]);
        DWORD funcRva = funcRvas[ordinals[i]];
        
        char line[256];
        int lineLen = snprintf(line, sizeof(line), "%s = 0x%lX\r\n", funcName, funcRva);
        WriteFile(hFile, line, lineLen, &written, NULL);
    }
    
    CloseHandle(hFile);
    
    char logBuf[64];
    snprintf(logBuf, sizeof(logBuf), "Loader exports: %lu", pExport->NumberOfNames);
    DebugLog(logBuf);
}

static int IsLoaderFuncPrologue(uint8_t* p) {
    if (p[0] == 0x55) return 1;
    if (p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57) return 1;
    if (p[0] == 0x41 && (p[1] >= 0x54 && p[1] <= 0x57)) return 1;
    if (p[0] == 0x40 && (p[1] >= 0x53 && p[1] <= 0x57)) return 1;
    if (p[0] == 0x48 && p[1] == 0x89) return 1;
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return 1;
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return 1;
    if (p[0] == 0x4C && p[1] == 0x89) return 1;
    if (p[0] == 0x4C && p[1] == 0x8B) return 1;
    return 0;
}

static void ExtractLoaderFunctions(uint8_t* dumpBuffer, DWORD imageSize, PIMAGE_NT_HEADERS pNt, PVOID loaderBase) {
    char logBuf[128];
    
    uint64_t textStart = 0, textEnd = 0;
    PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNt);
    
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        char secName[9] = {0};
        memcpy(secName, pSections[i].Name, 8);
        if (strcmp(secName, ".text") == 0) {
            textStart = pSections[i].VirtualAddress;
            textEnd = textStart + pSections[i].Misc.VirtualSize;
            break;
        }
    }
    
    if (!textStart || !textEnd) {
        DebugLog("Loader: No .text section");
        return;
    }
    
    HANDLE hFile = CreateFileA(OutputPath("wow_loader_functions.txt"), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD written;
    int funcCount = 0;
    
    char header[512];
    int headerLen = snprintf(header, sizeof(header),
        "// Wow_loader.dll Internal Functions\r\n"
        "// Base: 0x%p\r\n"
        "// .text: 0x%llX - 0x%llX\r\n"
        "// Auto-extracted with forced decryption\r\n\r\n"
        "// === EXPORTS ===\r\n"
        "eidolon_run = 0x3B91D0\r\n"
        "eidolon_run_real = 0x3B91E0\r\n"
        "g_warden_aegis_crash_callback = 0x641BC8\r\n\r\n"
        "// === CRYPTO CONSTANTS ===\r\n"
        "eidolon_key1 = 0xFD07B4FF3A00D412\r\n"
        "eidolon_key2 = 0x028BF84B00C5FF2B\r\n\r\n"
        "// === INTERNAL FUNCTIONS ===\r\n",
        loaderBase, (unsigned long long)textStart, (unsigned long long)textEnd);
    WriteFile(hFile, header, headerLen, &written, NULL);
    
    for (uint64_t addr = textStart + 1; addr < textEnd - 16 && addr < imageSize - 16; addr++) {
        uint8_t prev = dumpBuffer[addr - 1];
        if (prev == 0xCC || prev == 0xC3) {
            uint8_t* p = dumpBuffer + addr;
            if (IsLoaderFuncPrologue(p)) {
                char line[64];
                int lineLen = snprintf(line, sizeof(line), "sub_%llX = 0x%llX\r\n", 
                                       (unsigned long long)addr, (unsigned long long)addr);
                WriteFile(hFile, line, lineLen, &written, NULL);
                funcCount++;
            }
        }
    }
    
    CloseHandle(hFile);
    
    snprintf(logBuf, sizeof(logBuf), "Loader functions: %d", funcCount);
    DebugLog(logBuf);
}

static void ExtractLoaderCrypto(uint8_t* dumpBuffer, DWORD imageSize) {
    char logBuf[256];
    
    HANDLE hFile = CreateFileA(OutputPath("wow_loader_crypto.txt"), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD written;
    char header[] = "// Wow_loader.dll Crypto Analysis\r\n"
                    "// Auto-extracted encryption keys and constants\r\n\r\n";
    WriteFile(hFile, header, sizeof(header) - 1, &written, NULL);
    
    uint64_t eidolonRunReal = 0x3B91E0;
    if (eidolonRunReal + 64 < imageSize) {
        char section[] = "// === EIDOLON_RUN CONSTANTS ===\r\n";
        WriteFile(hFile, section, sizeof(section) - 1, &written, NULL);
        
        uint8_t* p = dumpBuffer + eidolonRunReal;
        int keyCount = 0;
        
        for (int i = 0; i < 200 && keyCount < 10; i++) {
            if (p[i] == 0x48 && (p[i+1] == 0xBE || p[i+1] == 0xBF || p[i+1] == 0xB8)) {
                uint64_t key = *(uint64_t*)(p + i + 2);
                if (key > 0x1000000000000000ULL) {
                    char line[128];
                    int lineLen = snprintf(line, sizeof(line), 
                        "key_%d = 0x%016llX  // at offset +0x%X\r\n",
                        keyCount, (unsigned long long)key, i);
                    WriteFile(hFile, line, lineLen, &written, NULL);
                    keyCount++;
                }
                i += 9;
            }
        }
        
        snprintf(logBuf, sizeof(logBuf), "Loader crypto: %d keys found", keyCount);
        DebugLog(logBuf);
    }
    
    char cryptoSection[] = "\r\n// === CRYPTO ALGORITHM SIGNATURES ===\r\n";
    WriteFile(hFile, cryptoSection, sizeof(cryptoSection) - 1, &written, NULL);
    
    uint8_t aesBox[] = {0x63, 0x7C, 0x77, 0x7B};
    uint8_t sha256Init[] = {0x67, 0xE6, 0x09, 0x6A};
    
    for (DWORD i = 0; i < imageSize - 4; i++) {
        if (memcmp(dumpBuffer + i, aesBox, 4) == 0) {
            char line[64];
            int lineLen = snprintf(line, sizeof(line), "AES_SBOX = 0x%lX\r\n", i);
            WriteFile(hFile, line, lineLen, &written, NULL);
            break;
        }
    }
    
    for (DWORD i = 0; i < imageSize - 4; i++) {
        if (memcmp(dumpBuffer + i, sha256Init, 4) == 0) {
            char line[64];
            int lineLen = snprintf(line, sizeof(line), "SHA256_INIT = 0x%lX\r\n", i);
            WriteFile(hFile, line, lineLen, &written, NULL);
            break;
        }
    }
    
    CloseHandle(hFile);
}

static void DumpWowLoader(void) {
    char logBuf[256];
    
    PVOID loaderBase = FindModuleByName(L"Wow_loader.dll");
    if (!loaderBase) {
        loaderBase = FindModuleByName(L"WowT_loader.dll");
        if (!loaderBase) return;
    }
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)loaderBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return;
    
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)loaderBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return;
    
    DWORD imageSize = pNt->OptionalHeader.SizeOfImage;
    
    DecryptGadgetFunc loaderGadget = FindLoaderDecryptGadget(loaderBase, imageSize);
    if (loaderGadget) {
        snprintf(logBuf, sizeof(logBuf), "Loader gadget: %p", (void*)loaderGadget);
        DebugLog(logBuf);
    }
    
    DecryptGadgetFunc useGadget = loaderGadget ? loaderGadget : g_decryptGadget;
    
    PVOID dumpBuffer = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!dumpBuffer) return;
    
    memcpy(dumpBuffer, loaderBase, pNt->OptionalHeader.SizeOfHeaders);
    
    PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNt);
    DWORD pageSize = 4096;
    DWORD pagesDecrypted = 0, pagesCopied = 0;
    
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSec = &pSections[i];
        char secName[9] = {0};
        memcpy(secName, pSec->Name, 8);
        
        DWORD secRVA = pSec->VirtualAddress;
        DWORD secSize = pSec->Misc.VirtualSize;
        if (secSize == 0) secSize = pSec->SizeOfRawData;
        if (secRVA + secSize > imageSize) continue;
        
        BOOL isCodeSection = (pSec->Characteristics & IMAGE_SCN_CNT_CODE) ||
                             (secName[0] == '.' && secName[1] == 't' && secName[2] == 'e');
        
        for (DWORD offset = 0; offset < secSize; offset += pageSize) {
            DWORD copySize = (offset + pageSize > secSize) ? (secSize - offset) : pageSize;
            PVOID srcPage = (LPBYTE)loaderBase + secRVA + offset;
            PVOID dstPage = (LPBYTE)dumpBuffer + secRVA + offset;
            
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(srcPage, &mbi, sizeof(mbi)) == 0) continue;
            
            BOOL decrypted = FALSE;
            
            if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == 0) {
                if (isCodeSection && useGadget && copySize == pageSize) {
                    DWORD oldProt;
                    if (VirtualProtect(srcPage, copySize, PAGE_EXECUTE_READ, &oldProt)) {
                        UINT64* src = (UINT64*)srcPage;
                        UINT64* dst = (UINT64*)dstPage;
                        for (int q = 0; q < 512; q++) {
                            dst[q] = useGadget(&src[q]);
                        }
                        VirtualProtect(srcPage, copySize, oldProt, &oldProt);
                        decrypted = TRUE;
                        pagesDecrypted++;
                        pagesCopied++;
                    }
                }
                
                if (!decrypted) {
                    DWORD oldProt;
                    if (VirtualProtect(srcPage, copySize, PAGE_READONLY, &oldProt)) {
                        memcpy(dstPage, srcPage, copySize);
                        VirtualProtect(srcPage, copySize, oldProt, &oldProt);
                        pagesCopied++;
                    }
                }
            } else if (!(mbi.Protect & PAGE_GUARD)) {
                if (isCodeSection && useGadget && copySize == pageSize) {
                    UINT64* src = (UINT64*)srcPage;
                    UINT64* dst = (UINT64*)dstPage;
                    for (int q = 0; q < 512; q++) {
                        dst[q] = useGadget(&src[q]);
                    }
                    pagesDecrypted++;
                    pagesCopied++;
                } else {
                    memcpy(dstPage, srcPage, copySize);
                    pagesCopied++;
                }
            }
        }
    }
    
    PIMAGE_DOS_HEADER pDumpDos = (PIMAGE_DOS_HEADER)dumpBuffer;
    PIMAGE_NT_HEADERS pDumpNt = (PIMAGE_NT_HEADERS)((LPBYTE)dumpBuffer + pDumpDos->e_lfanew);
    PIMAGE_SECTION_HEADER pDumpSections = IMAGE_FIRST_SECTION(pDumpNt);
    
    for (WORD i = 0; i < pDumpNt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSec = &pDumpSections[i];
        pSec->PointerToRawData = pSec->VirtualAddress;
        pSec->SizeOfRawData = pSec->Misc.VirtualSize;
    }
    pDumpNt->OptionalHeader.FileAlignment = pDumpNt->OptionalHeader.SectionAlignment;
    
    HANDLE hFile = CreateFileA(OutputPath("wow_loader_dump.bin"), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(hFile, dumpBuffer, imageSize, &bytesWritten, NULL);
        CloseHandle(hFile);
        snprintf(logBuf, sizeof(logBuf), "Loader: %lu bytes (%lu pages decrypted)", 
                 bytesWritten, pagesDecrypted);
        DebugLog(logBuf);
    }
    
    DumpLoaderExports(loaderBase, pNt);
    ExtractLoaderFunctions(dumpBuffer, imageSize, pNt, loaderBase);
    ExtractLoaderCrypto(dumpBuffer, imageSize);
    
    SecureZeroBuffer(dumpBuffer, imageSize);
    VirtualFree(dumpBuffer, 0, MEM_RELEASE);
}

static DWORD WINAPI DumpWorkerThread(LPVOID lpParam) {
    (void)lpParam;
    char logBuf[256];
    
    StealthSleep(50);
    InitForcedDecryption();
    RandomStealthSleep(50, 150);
    
    PPEB peb = GET_PEB();
    if (!peb || !peb->ImageBaseAddress) {
        DebugLog("ERR: PEB or ImageBaseAddress is NULL — cannot dump");
        return 0;
    }
    
    PVOID moduleBase = peb->ImageBaseAddress;
    InitSpoofedCall(moduleBase);
    
    /*
     * Gadget scan: try hardcoded RVA first, then scan .text for known
     * WoW encryption gadget byte patterns:
     *   48 8B 01 C3          -- mov rax,[rcx]; ret   (classic)
     *   48 8B 01 48 31 ?? C3 -- mov rax,[rcx]; xor ..; ret  (XOR variant)
     *   48 8B 09 C3          -- mov rcx,[rcx]; ret   (alternate reg)
     *   48 8B 41 ?? C3       -- mov rax,[rcx+N]; ret (offset variant)
     */
    /* Read imageSize from PE headers before using it in the gadget scan */
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)moduleBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD imageSize = pNt->OptionalHeader.SizeOfImage;
    snprintf(logBuf, sizeof(logBuf), "Size: %.1f MB", imageSize / 1048576.0);
    DebugLog(logBuf);

    g_decryptGadget = NULL;
    LPBYTE base = (LPBYTE)moduleBase;

    /* 1. Try hardcoded RVA for the known build */
    {
        LPBYTE p = base + DECRYPT_GADGET_RVA;
        if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x01 && p[3] == 0xC3)
            g_decryptGadget = (DecryptGadgetFunc)p;
    }

    /* 2. Scan up to 16 MB for any matching gadget pattern */
    DWORD scanLimit = imageSize < 0x1000000 ? imageSize : 0x1000000;
    for (DWORD offset = 0x1000; offset < scanLimit - 8 && !g_decryptGadget; offset++) {
        LPBYTE p = base + offset;
        MEMORY_BASIC_INFORMATION _mbi;
        /* Only scan readable pages */
        if ((offset & 0xFFF) == 0) {
            if (!VirtualQuery(p, &_mbi, sizeof(_mbi))) { offset += 0xFFF; continue; }
            if (!(_mbi.Protect & (PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_READONLY|PAGE_READWRITE)))
                { offset += 0xFFF; continue; }
        }
        /* Pattern A: 48 8B 01 C3 */
        if (p[0]==0x48 && p[1]==0x8B && p[2]==0x01 && p[3]==0xC3)
            if (p[-1]==0xCC || p[-1]==0xC3 || p[-1]==0x90 || p[4]==0xCC)
                { g_decryptGadget = (DecryptGadgetFunc)p; break; }
        /* Pattern B: 48 8B 01 48 31 ?? C3 (XOR variant) */
        if (p[0]==0x48 && p[1]==0x8B && p[2]==0x01 &&
            p[3]==0x48 && p[4]==0x31 && p[6]==0xC3)
            { g_decryptGadget = (DecryptGadgetFunc)p; break; }
        /* Pattern C: 48 8B 09 C3 */
        if (p[0]==0x48 && p[1]==0x8B && p[2]==0x09 && p[3]==0xC3)
            if (p[-1]==0xCC || p[-1]==0xC3 || p[4]==0xCC)
                { g_decryptGadget = (DecryptGadgetFunc)p; break; }
        /* Pattern D: 48 8B 41 ?? C3 */
        if (p[0]==0x48 && p[1]==0x8B && p[2]==0x41 && p[4]==0xC3)
            if (p[-1]==0xCC || p[-1]==0xC3 || p[5]==0xCC)
                { g_decryptGadget = (DecryptGadgetFunc)p; break; }
    }

    /* 3. If no gadget found, attempt XOR key detection */
    if (!g_decryptGadget) {
        DetectXorKey(moduleBase, imageSize);
    }
    
    if (g_decryptGadget)
        DebugLogFmt("Base: %p | Gadget: %p", moduleBase, (void*)g_decryptGadget);
    else
        DebugLogFmt("Base: %p | Gadget: NOT FOUND - trying XOR detection", moduleBase);
    
    PVOID dumpBuffer = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!dumpBuffer) {
        DebugLogFmt("ERR: VirtualAlloc failed for dump buffer (%.1f MB) — out of memory?",
                    imageSize / 1048576.0);
        return 0;
    }
    
    SpoofedMemcpy(dumpBuffer, moduleBase, pNt->OptionalHeader.SizeOfHeaders);
    
    PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNt);
    WORD numSections = pNt->FileHeader.NumberOfSections;
    DWORD pageSize = 4096;
    DWORD totalDecrypted = 0, totalCopied = 0;
    
    for (WORD i = 0; i < numSections; i++) {
        PIMAGE_SECTION_HEADER pSec = &pSections[i];
        char secName[9] = {0};
        memcpy(secName, pSec->Name, 8);
        
        DWORD secRVA = pSec->VirtualAddress;
        DWORD secSize = pSec->Misc.VirtualSize;
        if (secSize == 0) secSize = pSec->SizeOfRawData;
        if (secSize == 0 || secRVA + secSize > imageSize) continue;
        
        DWORD pagesCopied = 0, pagesForceDecrypted = 0;
        BOOL isCodeSection = (pSec->Characteristics & IMAGE_SCN_CNT_CODE) || 
                             (secName[0] == '.' && secName[1] == 't' && secName[2] == 'e');
        
        DWORD pagesGadget = 0, pagesXor = 0, pagesPlain = 0;

        for (DWORD offset = 0; offset < secSize; offset += pageSize) {
            DWORD copySize = (offset + pageSize > secSize) ? (secSize - offset) : pageSize;
            PVOID srcPage = (LPBYTE)moduleBase + secRVA + offset;
            PVOID dstPage = (LPBYTE)dumpBuffer + secRVA + offset;

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(srcPage, &mbi, sizeof(mbi)) == 0) continue;

            BOOL needsDecrypt = (mbi.Protect == PAGE_NOACCESS || mbi.Protect == 0);
            BOOL accessible   = !needsDecrypt && !(mbi.Protect & PAGE_GUARD);
            BOOL done = FALSE;

            if (needsDecrypt && isCodeSection && copySize == pageSize) {
                /* Strategy 1: gadget-based decryption */
                if (!done && g_decryptGadget) {
                    DWORD oldProt;
                    if (VirtualProtect(srcPage, copySize, PAGE_EXECUTE_READ, &oldProt)) {
                        if (DecryptPageWithGadget(srcPage, dstPage)) {
                            pagesGadget++; pagesForceDecrypted++; pagesCopied++; done = TRUE;
                        }
                        VirtualProtect(srcPage, copySize, oldProt, &oldProt);
                    }
                }
                /* Strategy 2: XOR key decryption */
                if (!done && g_xorKey) {
                    DWORD oldProt;
                    if (VirtualProtect(srcPage, copySize, PAGE_EXECUTE_READ, &oldProt)) {
                        if (TryXorDecryptPage(srcPage, dstPage)) {
                            pagesXor++; pagesForceDecrypted++; pagesCopied++; done = TRUE;
                        }
                        VirtualProtect(srcPage, copySize, oldProt, &oldProt);
                    }
                }
                /* Strategy 3: force-touch then copy */
                if (!done && CopyPageAfterTouch(srcPage, dstPage)) {
                    pagesPlain++; pagesForceDecrypted++; pagesCopied++; done = TRUE;
                }
                /* Last resort: force page readable and raw copy */
                if (!done) {
                    DWORD oldProt;
                    if (VirtualProtect(srcPage, copySize, PAGE_EXECUTE_READ, &oldProt)) {
                        SpoofedMemcpy(dstPage, srcPage, copySize);
                        VirtualProtect(srcPage, copySize, oldProt, &oldProt);
                        pagesPlain++; pagesCopied++;
                    }
                }
            } else if (accessible) {
                /* Page is already readable */
                if (isCodeSection && copySize == pageSize && g_decryptGadget) {
                    if (DecryptPageWithGadget(srcPage, dstPage))
                        { pagesGadget++; pagesForceDecrypted++; pagesCopied++; }
                    else
                        { SpoofedMemcpy(dstPage, srcPage, copySize); pagesPlain++; pagesCopied++; }
                } else if (isCodeSection && copySize == pageSize && g_xorKey) {
                    if (TryXorDecryptPage(srcPage, dstPage))
                        { pagesXor++; pagesForceDecrypted++; pagesCopied++; }
                    else
                        { SpoofedMemcpy(dstPage, srcPage, copySize); pagesPlain++; pagesCopied++; }
                } else {
                    SpoofedMemcpy(dstPage, srcPage, copySize);
                    pagesPlain++; pagesCopied++;
                }
            }

            if ((offset / pageSize) % 100 == 0) StealthSleep(0);
        }

        if (isCodeSection && (pagesGadget || pagesXor || pagesForceDecrypted))
            DebugLogFmt("  Section %s: gadget=%lu xor=%lu plain=%lu",
                        secName, pagesGadget, pagesXor, pagesPlain);

        totalDecrypted += pagesForceDecrypted;
        totalCopied += pagesCopied;
    }

    DebugLogFmt("Sections: %d | Pages: %lu copied, %lu decrypted | Method: %s",
                numSections, totalCopied, totalDecrypted,
                g_decryptGadget ? "gadget" : (g_xorKey ? "xor" : "plain"));
    
    CleanupForcedDecryption();
    
    PIMAGE_DOS_HEADER pDumpDos = (PIMAGE_DOS_HEADER)dumpBuffer;
    PIMAGE_NT_HEADERS pDumpNt = (PIMAGE_NT_HEADERS)((LPBYTE)dumpBuffer + pDumpDos->e_lfanew);
    PIMAGE_SECTION_HEADER pDumpSections = IMAGE_FIRST_SECTION(pDumpNt);
    
    for (WORD i = 0; i < pDumpNt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSec = &pDumpSections[i];
        pSec->PointerToRawData = pSec->VirtualAddress;
        pSec->SizeOfRawData = pSec->Misc.VirtualSize;
    }
    pDumpNt->OptionalHeader.FileAlignment = pDumpNt->OptionalHeader.SectionAlignment;
    
    if (pDumpNt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
        pDumpNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
        pDumpNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    }
    if (pDumpNt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
        pDumpNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
        pDumpNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
    }
    
    ScanAndTrackTlsCallbacks(moduleBase);
    snprintf(logBuf, sizeof(logBuf), "TLS callbacks: %d", g_tlsTracker.count);
    DebugLog(logBuf);
    
    ReconstructTlsCallbacks(moduleBase, dumpBuffer, imageSize);
    ReconstructIAT(moduleBase, dumpBuffer, imageSize);
    
    DebugLog("Extracting offsets...");
    
    uint64_t textStart = 0, textEnd = 0;
    uint64_t rdataStart = 0, rdataEnd = 0;
    uint64_t dataStart = 0, dataEnd = 0;
    
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < numSections; i++) {
        char secName[9] = {0};
        memcpy(secName, pSection[i].Name, 8);
        uint32_t virtualSize = pSection[i].Misc.VirtualSize;
        uint32_t virtualAddr = pSection[i].VirtualAddress;
        
        if (strcmp(secName, ".text") == 0) {
            textStart = virtualAddr;
            textEnd = virtualAddr + virtualSize;
        } else if (strcmp(secName, ".rdata") == 0) {
            rdataStart = virtualAddr;
            rdataEnd = virtualAddr + virtualSize;
        } else if (strcmp(secName, ".data") == 0) {
            dataStart = virtualAddr;
            dataEnd = virtualAddr + virtualSize;
        }
    }
    
    if (textStart && rdataStart && dataStart) {
        g_offsets = VirtualAlloc(NULL, MAX_OFFSETS * sizeof(OffsetEntry), 
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (g_offsets) {
            g_offsetCount = 0;
            
            ExtractLuaFunctions(moduleBase, dumpBuffer, imageSize,
                               textStart, textEnd, rdataStart, rdataEnd, dataStart, dataEnd);
            
            ExtractGlobalOffsets(moduleBase, dumpBuffer, imageSize,
                                textStart, textEnd, dataStart, dataEnd);
            
            WriteOffsetsFile(moduleBase);
            
            snprintf(logBuf, sizeof(logBuf), "Total offsets: %d", g_offsetCount);
            DebugLog(logBuf);
            
            VirtualFree(g_offsets, 0, MEM_RELEASE);
            g_offsets = NULL;
        }
    } else {
        DebugLog("Could not parse sections for offset extraction");
    }
    
    HANDLE hFile = StealthCreateFile(OutputPath("wow_dump.bin"));
    BOOL useStealth = (hFile != INVALID_HANDLE_VALUE);

    if (!useStealth) {
        hFile = CreateFileA(OutputPath("wow_dump.bin"), GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        DebugLogFmt("ERR: Failed to create wow_dump.bin at '%s' (WinError %lu)",
                    OutputPath("wow_dump.bin"), GetLastError());
        DebugLog("ERR: Possible causes: path does not exist, access denied, or disk full");
        SecureZeroBuffer(dumpBuffer, imageSize);
        VirtualFree(dumpBuffer, 0, MEM_RELEASE);
        return 0;
    }
    DebugLogFmt("wow_dump.bin opened OK (stealth=%d) at: %s", useStealth, OutputPath("wow_dump.bin"));
    
    DWORD written = 0;
    BOOL ok = useStealth ? 
        StealthWriteFile(hFile, dumpBuffer, imageSize, &written) :
        WriteFile(hFile, dumpBuffer, imageSize, &written, NULL);
    
    useStealth ? StealthCloseFile(hFile) : CloseHandle(hFile);
    
    snprintf(logBuf, sizeof(logBuf), "wow_dump.bin: %lu bytes %s", written, ok ? "OK" : "FAIL");
    DebugLog(logBuf);
    
    SecureZeroBuffer(dumpBuffer, imageSize);
    VirtualFree(dumpBuffer, 0, MEM_RELEASE);
    
    DumpWowLoader();
    DebugLog("Done");
    return 0;
}

static HMODULE g_ourModule = NULL;

static void CALLBACK DeferredDumpCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context) {
    (void)Instance;
    (void)Context;
    
    PPEB peb = GET_PEB();
    PVOID moduleBase = peb ? peb->ImageBaseAddress : NULL;
    if (!moduleBase) return;
    
    DebugLog("TLS scan: 2 min");
    
    const int TOTAL_WAIT_MS = 120000;
    const int SCAN_INTERVAL_MS = 10;
    const int TOTAL_ITERATIONS = TOTAL_WAIT_MS / SCAN_INTERVAL_MS;
    
    int lastCallbackCount = 0;
    int lastLogSecond = -1;
    
    for (int i = 0; i < TOTAL_ITERATIONS; i++) {
        ScanAndTrackTlsCallbacks(moduleBase);
        
        int currentSecond = (i * SCAN_INTERVAL_MS) / 1000;
        
        if (g_tlsTracker.count != lastCallbackCount) {
            char logBuf[64];
            snprintf(logBuf, sizeof(logBuf), "[%ds] TLS +1 = %d", currentSecond, g_tlsTracker.count);
            DebugLog(logBuf);
            lastCallbackCount = g_tlsTracker.count;
        } else if (currentSecond != lastLogSecond && currentSecond % 30 == 0 && currentSecond > 0) {
            char logBuf[32];
            snprintf(logBuf, sizeof(logBuf), "[%ds] ...", currentSecond);
            DebugLog(logBuf);
            lastLogSecond = currentSecond;
        }
        
        StealthSleep(SCAN_INTERVAL_MS);
    }
    
    DumpWorkerThread(NULL);
}

static BOOL ScheduleDeferredDump(void) {
    return TrySubmitThreadpoolCallback(DeferredDumpCallback, NULL, NULL);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    (void)lpReserved;
    
    if (dwReason == DLL_PROCESS_ATTACH) {
        g_ourModule = hModule;
        InitializeCriticalSection(&g_tlsLock);
        InitializeCriticalSection(&g_offsetLock);
        DisableThreadLibraryCalls(hModule);
        
        PPEB peb = GET_PEB();
        if (peb && peb->ImageBaseAddress) {
            InitTlsCallbackTracking(peb->ImageBaseAddress);
        }
        
        UnlinkFromPEB(hModule);
        
        char logBuf[64];
        DebugLogSessionHeader();
        snprintf(logBuf, sizeof(logBuf), "Init: TLS=%d, hidden", g_tlsTracker.count);
        DebugLog(logBuf);

        if (!ScheduleDeferredDump()) {
            DebugLog("ScheduleDeferredDump failed, falling back to inline wait");
            StealthSleep(120000);
            DumpWorkerThread(NULL);
        } else {
            DebugLog("ScheduleDeferredDump OK");
        }

        return TRUE;
    }
    
    return TRUE;
}
