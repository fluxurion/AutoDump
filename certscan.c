// certscan.c — locate the WoW cert store in a running client's memory.
//
// The cert store is a heap array of 40-byte records:
//     { u32 group_id (ascending), u8 pubkey[32], u8 flag, u8 pad[3] }
// Same shape the launcher's heap scan looks for — this tool prints every
// candidate run so the real keys can be fed back into BETA_CERT_KEYS.
//
// Usage: certscan.exe            (auto-finds WowB.exe / WowClassic.exe)
//        certscan.exe <pid>
//
// Build: "%VCToolsInstallDir%..\LLVM\bin\clang.exe" certscan.c -o certscan.exe -O2

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define REC_SIZE 40
#define MIN_RUN  6

static int key_entropy(const uint8_t *k) {
    int seen[256] = {0}, d = 0;
    for (int i = 0; i < 32; i++)
        if (!seen[k[i]]) { seen[k[i]] = 1; d++; }
    return d;
}

// Length of the record run starting at buf+off (0 if not a cert store).
static int run_len(const uint8_t *buf, size_t off, size_t len) {
    const uint8_t *pad = buf + off + 37;
    uint32_t prev = 0;
    int n = 0;
    while (off + (size_t)(n + 1) * REC_SIZE <= len) {
        const uint8_t *rec = buf + off + (size_t)n * REC_SIZE;
        uint32_t g;
        memcpy(&g, rec, 4);
        if (g == 0 || g > 0x10000 || g <= prev) break;
        if (key_entropy(rec + 4) < 20) break;
        if (rec[36] > 4) break;
        if (memcmp(rec + 37, pad, 3) != 0) break;
        prev = g;
        n++;
    }
    return n;
}

static DWORD find_wow_pid(void) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"WowB.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"WowClassic.exe") == 0) {
                pid = pe.th32ProcessID;
                wprintf(L"found %s pid %lu\n", pe.szExeFile, pid);
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main(int argc, char **argv) {
    DWORD pid = (argc > 1) ? strtoul(argv[1], NULL, 0) : find_wow_pid();
    if (!pid) {
        fprintf(stderr, "no pid / WoW process not running\n");
        return 1;
    }
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) {
        fprintf(stderr, "OpenProcess(%lu) failed: %lu (run as admin)\n", pid, GetLastError());
        return 1;
    }

    uint8_t *addr = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    int found = 0;
    const size_t CHUNK = 8 * 1024 * 1024;
    const size_t OVERLAP = REC_SIZE * 32;
    uint8_t *buf = malloc(CHUNK + OVERLAP);

    while (VirtualQueryEx(h, addr, &mbi, sizeof(mbi))) {
        uint8_t *next = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        int scannable = mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE) &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE);
        if (scannable && next > addr) {
            size_t off = 0;
            while (off < mbi.RegionSize) {
                size_t want = mbi.RegionSize - off;
                if (want > CHUNK) want = CHUNK;
                size_t extra = (off + want < mbi.RegionSize) ? OVERLAP : 0;
                SIZE_T rd = 0;
                if (ReadProcessMemory(h, (uint8_t *)mbi.BaseAddress + off, buf,
                                      want + extra, &rd) && rd > 2 * REC_SIZE) {
                    for (size_t pos = 0; pos + 2 * REC_SIZE <= rd; pos += 4) {
                        int n = run_len(buf, pos, rd);
                        if (n >= MIN_RUN) {
                            uintptr_t va =
                                (uintptr_t)mbi.BaseAddress + off + pos;
                            printf("candidate @ %p : %d records\n",
                                   (void *)va, n);
                            for (int i = 0; i < n && i < 24; i++) {
                                const uint8_t *rec = buf + pos + (size_t)i * REC_SIZE;
                                uint32_t g;
                                memcpy(&g, rec, 4);
                                printf("  group=%-3u flag=%02x pad=%02x%02x%02x key=",
                                       g, rec[36], rec[37], rec[38], rec[39]);
                                for (int k = 0; k < 32; k++)
                                    printf("%02x", rec[4 + k]);
                                printf("\n");
                            }
                            found++;
                            pos += (size_t)n * REC_SIZE;
                        }
                    }
                }
                off += want;
            }
        }
        if (next <= addr) break;
        addr = next;
    }
    free(buf);
    CloseHandle(h);
    if (!found)
        printf("no cert-store candidates found (store may not be built yet)\n");
    return 0;
}
