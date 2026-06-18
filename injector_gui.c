#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <process.h>
#include <stdarg.h>
#include <tlhelp32.h>

#define ID_BTN_BROWSE         1001
#define ID_BTN_INJECT_RUN     1002
#define ID_BTN_INJECT_LAUNCH  1003
#define ID_EDIT_PROCESS       1004
#define ID_LIST_LOG           1005
#define ID_STATIC_STATUS      1006
#define ID_PROGRESS           1007
#define ID_BTN_OPEN_FOLDER    1008
#define ID_STATIC_HINT        1009
#define ID_STATIC_WARN        1010

/* ── Layout constants ── */
#define WIN_W     640
#define WIN_H     500
#define MARGIN    12
#define HDR_H     52   /* painted header bar height */
#define ROW1_Y    (HDR_H + 14)   /* target path row */
#define ROW2_Y    (ROW1_Y + 36)  /* buttons row */
#define SEP1_Y    (ROW2_Y + 40)  /* separator after buttons */
#define HINT_Y    (SEP1_Y + 8)   /* hint / warn banner */
#define PROG_Y    (HINT_Y + 38)  /* progress bar */
#define SEP2_Y    (PROG_Y + 22)  /* separator before log */
#define LOG_Y     (SEP2_Y + 8)   /* log listbox */
#define STAT_H    22             /* status strip height */
#define LOG_H     (WIN_H - LOG_Y - STAT_H - 28) /* listbox height */
#define STAT_Y    (LOG_Y + LOG_H + 6)

/* ── Accent palette ── */
#define COL_BG        RGB(22,  22,  30 )  /* main background   */
#define COL_HDR       RGB(15,  15,  22 )  /* header background */
#define COL_PANEL     RGB(30,  30,  42 )  /* panel / edit bg   */
#define COL_BORDER    RGB(55,  55,  75 )  /* subtle border     */
#define COL_ACCENT    RGB(80,  140, 255)  /* blue accent       */
#define COL_BTN_RUN   RGB(50,  120, 220)  /* inject-run button */
#define COL_BTN_LAUNCH RGB(60, 160, 90 )  /* launch button     */
#define COL_BTN_FOLD  RGB(70,  70,  100)  /* folder button     */
#define COL_BTN_BROW  RGB(55,  55,  80 )  /* browse button     */
#define COL_TXT       RGB(220, 220, 235)  /* primary text      */
#define COL_TXT_DIM   RGB(140, 140, 165)  /* dim text          */
#define COL_WARN_BG   RGB(160, 60,  0  )  /* warning bg        */
#define COL_WARN_FG   RGB(255, 220, 160)  /* warning text      */
#define COL_LOG_BG    RGB(14,  14,  20 )  /* log background    */
#define COL_SEL_BG    RGB(40,  50,  80 )  /* selected row bg   */

/* ── Button state tracking for owner-draw ── */
#define BTN_COUNT 4
static HWND  g_btns[BTN_COUNT];          /* ordered: run, launch, folder, browse */
static BOOL  g_btnHover[BTN_COUNT];      /* mouse is over button i */
static BOOL  g_btnPress[BTN_COUNT];      /* button i is being pressed */
static COLORREF g_btnColor[BTN_COUNT];   /* base color per button */

static HWND g_hWnd           = NULL;
static HWND g_hEditProcess;
static HWND g_hListLog;
static HWND g_hBtnInjectRun;
static HWND g_hBtnInjectLaunch;
static HWND g_hBtnBrowse;
static HWND g_hBtnOpenFolder;
static HWND g_hStaticStatus;
static HWND g_hProgress;
static HWND g_hStaticHint;
static HWND g_hStaticWarn;
static HBRUSH g_hBrushWarn    = NULL;
static HBRUSH g_hBrushBg      = NULL;
static HBRUSH g_hBrushPanel   = NULL;
static HBRUSH g_hBrushLogBg   = NULL;
static HFONT  g_hFontUI       = NULL;  /* 13pt Segoe UI — labels, buttons */
static HFONT  g_hFontMono     = NULL;  /* 12pt Consolas  — log, edit      */
static HFONT  g_hFontTitle    = NULL;  /* 16pt Segoe UI Bold — header     */
static char   g_selectedExe[MAX_PATH] = {0};
static volatile int g_injectRunning = 0;
static HANDLE g_injectorProcess = NULL;

/* Custom messages from worker -> main thread */
#define WM_INJECT_LOG      (WM_APP + 1)
#define WM_INJECT_START    (WM_APP + 2)
#define WM_INJECT_DONE     (WM_APP + 3)
#define WM_INJECT_PROGRESS (WM_APP + 4)  /* wParam = 0-100 */

/* ── Log a message (thread-safe, posts to main thread) ── */
static void LogMessage(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    size_t len = strlen(buf) + 1;
    char* msg = (char*)malloc(len);
    if (msg) {
        memcpy(msg, buf, len);
        /* Post to main window so WndProc handles WM_INJECT_LOG */
        PostMessageA(g_hWnd, WM_INJECT_LOG, 0, (LPARAM)msg);
    }
}

/* ── Update the progress bar (thread-safe) ── */
static void SetProgress(int pct) {
    PostMessageA(g_hWnd, WM_INJECT_PROGRESS, (WPARAM)pct, 0);
}

/* ── Get the directory containing our executable ── */
static void GetMyDir(char* out, SIZE_T outSize) {
    char mod[MAX_PATH];
    GetModuleFileNameA(NULL, mod, sizeof(mod));
    char* slash = strrchr(mod, '\\');
    if (slash) {
        SIZE_T len = slash - mod + 1;
        if (len < outSize) {
            memcpy(out, mod, len);
            out[len] = 0;
        }
    } else {
        out[0] = 0;
    }
}

/* ── Get the directory of a running process by its name (with trailing backslash) ── */
static void GetTargetProcessDir(const char* processName, char* out, SIZE_T outSize) {
    out[0] = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    if (!pid) return;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return;
    char exePath[MAX_PATH];
    DWORD len = sizeof(exePath);
    if (QueryFullProcessImageNameA(hProc, 0, exePath, &len)) {
        char* slash = strrchr(exePath, '\\');
        if (slash) {
            SIZE_T dirLen = (slash - exePath) + 1;
            if (dirLen < outSize) {
                memcpy(out, exePath, dirLen);
                out[dirLen] = 0;
            }
        }
    }
    CloseHandle(hProc);
}

/* ── Check if a file exists ── */
static int FileExists(const char* path) {
    WIN32_FIND_DATAA ffd;
    HANDLE h = FindFirstFileA(path, &ffd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    FindClose(h);
    return 1;
}

/* ── Worker thread for injection ── */
static DWORD WINAPI WorkerThread(LPVOID lpParam) {
    int mode = (int)(INT_PTR)lpParam; /* 0 = running process, 1 = launch */

    /* Tell main thread to disable controls and show progress */
    PostMessageA(g_hWnd, WM_INJECT_START, 0, 0);
    SetProgress(0);

    char processName[MAX_PATH] = {0};
    GetWindowTextA(g_hEditProcess, processName, sizeof(processName));

    if (processName[0] == 0) {
        LogMessage("[-] No target specified.");
        PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
        return 0;
    }

    SetProgress(5);

    char myDir[MAX_PATH];
    GetMyDir(myDir, sizeof(myDir));

    /* Verify helper.dll exists */
    char dllPath[MAX_PATH];
    snprintf(dllPath, sizeof(dllPath), "%shelper.dll", myDir);
    if (!FileExists(dllPath)) {
        LogMessage("[-] helper.dll not found in %s", myDir);
        PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
        return 0;
    }

    /* Build the command line */
    char cmd[MAX_PATH * 2];
    if (mode == 0) {
        /* Inject into a running process */
        LogMessage("[*] Looking for process '%s' ...", processName);
        DWORD pid = 0;
        for (int tries = 0; tries < 300 && pid == 0; tries++) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe = {0};
                pe.dwSize = sizeof(pe);
                if (Process32First(snap, &pe)) {
                    do {
                        if (_stricmp(pe.szExeFile, processName) == 0) {
                            pid = pe.th32ProcessID;
                            break;
                        }
                    } while (Process32Next(snap, &pe));
                }
                CloseHandle(snap);
            }
            if (pid == 0) Sleep(10);
        }
        if (pid == 0) {
            LogMessage("[-] Process '%s' not found.", processName);
            PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
            return 0;
        }
        LogMessage("[*] Found PID %lu", pid);
        SetProgress(20);
        snprintf(cmd, sizeof(cmd), "%sinjector.exe %s", myDir, processName);
    } else {
        /* Launch & Inject mode: GUI launches the target, injector just injects */
        LogMessage("[*] Launching '%s' ...", processName);

        STARTUPINFOA siTarget = {0};
        siTarget.cb = sizeof(siTarget);
        PROCESS_INFORMATION piTarget = {0};

        if (!CreateProcessA(NULL, processName, NULL, NULL, FALSE,
                            0, NULL, NULL, &siTarget, &piTarget)) {
            LogMessage("[-] Failed to launch target (error %lu)", GetLastError());
            PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
            return 0;
        }
        CloseHandle(piTarget.hThread);
        CloseHandle(piTarget.hProcess);

        /* Extract just the filename so injector.exe can find it by name */
        const char* justName = strrchr(processName, '\\');
        if (justName)
            justName++; /* skip the backslash */
        else
            justName = processName;

        LogMessage("[*] Target launched, injecting into '%s' ...", justName);
        SetProgress(20);
        snprintf(cmd, sizeof(cmd), "%sinjector.exe %s", myDir, justName);
    }

    LogMessage("[*] Running: %s", cmd);

    /* ── Create pipe to capture injector.exe stdout ── */
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 4096)) {
        LogMessage("[-] Failed to create pipe (error %lu)", GetLastError());
        PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
        return 0;
    }

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        LogMessage("[-] Failed to launch injector (error %lu)", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
        return 0;
    }

    CloseHandle(pi.hThread);
    CloseHandle(hWritePipe); /* close our copy — injector.exe owns the write end */

    /* Store the handle so the main thread can kill it on close */
    g_injectorProcess = pi.hProcess;

    /* ── Read pipe + pump messages + wait for injector to exit ── */
    char  pipeBuf[4096];
    DWORD pipeLen = 0;

    while (1) {
        DWORD r = MsgWaitForMultipleObjects(1, &pi.hProcess, FALSE, 50, QS_ALLINPUT);

        /* Read any available output from the pipe */
        DWORD avail = 0;
        if (PeekNamedPipe(hReadPipe, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD read = 0;
            if (ReadFile(hReadPipe, pipeBuf + pipeLen,
                         sizeof(pipeBuf) - pipeLen - 1, &read, NULL)) {
                pipeLen += read;
                pipeBuf[pipeLen] = 0;

                /* Extract and log complete lines */
                char* nl;
                while ((nl = (char*)memchr(pipeBuf, '\n', pipeLen)) != NULL) {
                    *nl = 0;
                    /* Strip trailing \r if present */
                    size_t lineLen = nl - pipeBuf;
                    if (lineLen > 0 && pipeBuf[lineLen - 1] == '\r')
                        pipeBuf[lineLen - 1] = 0;
                    if (pipeBuf[0])
                        LogMessage("[injector] %s", pipeBuf);
                    /* Move remaining data to front of buffer */
                    DWORD remaining = pipeLen - (nl - pipeBuf) - 1;
                    memmove(pipeBuf, nl + 1, remaining);
                    pipeLen = remaining;
                }
            }
        }

        if (r == WAIT_OBJECT_0) break; /* injector process exited */

        /* Pump queued messages for the main thread */
        MSG m;
        while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageA(&m);
        }
    }

    /* Read any remaining output after process exit */
    {
        DWORD read = 0;
        if (ReadFile(hReadPipe, pipeBuf + pipeLen,
                     sizeof(pipeBuf) - pipeLen - 1, &read, NULL)) {
            pipeLen += read;
            pipeBuf[pipeLen] = 0;
            if (pipeBuf[0]) {
                /* Trim trailing newlines */
                char* end = pipeBuf + pipeLen - 1;
                while (end >= pipeBuf && (*end == '\n' || *end == '\r'))
                    *end-- = 0;
                if (pipeBuf[0])
                    LogMessage("[injector] %s", pipeBuf);
            }
        }
    }
    CloseHandle(hReadPipe);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    g_injectorProcess = NULL;

    LogMessage("[*] Injector exited with code %lu", exitCode);
    if (exitCode == 0) {
        LogMessage("[+] Injection complete. Dump running in target process (~2 min).");
        SetProgress(50);
    } else {
        LogMessage("[-] Injection failed (exit code %lu) — cannot dump.", exitCode);
        SetProgress(0);
        PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
        return 0;
    }

    LogMessage("[*] Waiting for dump output files ...");

    /* Poll for dump files up to ~3 minutes.
       The helper DLL writes output files to <target dir>\AutoDumped\. */
    char pollDirs[2][MAX_PATH];
    int numPollDirs = 0;

    {
        char targetDir[MAX_PATH] = {0};
        if (mode == 1) {
            /* Launch mode: processName may be a full path — extract the directory */
            const char* slash = strrchr(processName, '\\');
            if (slash) {
                SIZE_T dirLen = (slash - processName) + 1;
                if (dirLen < MAX_PATH) {
                    memcpy(targetDir, processName, dirLen);
                    targetDir[dirLen] = 0;
                }
            } else {
                GetTargetProcessDir(processName, targetDir, sizeof(targetDir));
            }
        } else {
            GetTargetProcessDir(processName, targetDir, sizeof(targetDir));
        }
        if (targetDir[0]) {
            snprintf(pollDirs[0], sizeof(pollDirs[0]), "%sAutoDumped\\", targetDir);
            numPollDirs = 1;
        }
    }

    /* Fallback: also check CWD\AutoDumped\ in case process dir lookup failed */
    {
        char cwd[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, cwd) > 0) {
            int idx = numPollDirs > 0 ? 1 : 0;
            snprintf(pollDirs[idx], sizeof(pollDirs[idx]), "%s\\AutoDumped\\", cwd);
            if (numPollDirs == 0 || _stricmp(pollDirs[0], pollDirs[idx]) != 0)
                numPollDirs = idx + 1;
        }
    }

    int pollCount = 0;
    int maxPolls  = 360; /* 360 * 500ms = 180s = 3 min */
    int lastFileCount = 0;
    int stableCount  = 0; /* consecutive polls with same count */

    /* Resolve the target process name for liveness checks */
    const char* justName = strrchr(processName, '\\');
    if (justName) justName++; else justName = processName;

    while (pollCount < maxPolls) {
        int count = 0;

        /* Advance progress bar gradually from 50 toward 95 while waiting */
        {
            int p = 50 + (pollCount * 45) / maxPolls;
            if (p > 95) p = 95;
            SetProgress(p);
        }

        /* Check if target process is still alive */
        DWORD targetPid = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = {0};
            pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) {
                do {
                    if (_stricmp(pe.szExeFile, justName) == 0) {
                        targetPid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }
        if (!targetPid) {
            if (lastFileCount > 0) {
                LogMessage("[*] Target process exited. Dump files: %d", lastFileCount);
            } else {
                LogMessage("[-] Target process terminated before dump completed.");
                LogMessage("[-] Check helper_debug.txt in the AutoDumped folder for details.");
            }
            break;
        }

        /* Search all poll directories for .bin and .dmp files */
        for (int d = 0; d < numPollDirs; d++) {
            const char* dir = pollDirs[d];

            /* Check .bin files */
            char pattern[MAX_PATH];
            snprintf(pattern, sizeof(pattern), "%s*.bin", dir);
            WIN32_FIND_DATAA ffd;
            HANDLE hFind = FindFirstFileA(pattern, &ffd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do { count++; } while (FindNextFileA(hFind, &ffd));
                FindClose(hFind);
            }

            /* Check .dmp files */
            snprintf(pattern, sizeof(pattern), "%s*.dmp", dir);
            hFind = FindFirstFileA(pattern, &ffd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do { count++; } while (FindNextFileA(hFind, &ffd));
                FindClose(hFind);
            }
        }

        if (count > lastFileCount) {
            LogMessage("[*] Dump files found: %d so far...", count);
            lastFileCount = count;
            stableCount = 0;
        } else if (count > 0 && count == lastFileCount) {
            stableCount++;
            if (stableCount >= 6) {  /* 6 * 500ms = 3 seconds stable = complete */
                LogMessage("[+] Dump complete! (%d files)", count);
                SetProgress(100);
                break;
            }
        }

        /* Update status with elapsed time */
        int elapsedSec = (pollCount * 500) / 1000;
        if (count > 0) {
            char status[128];
            snprintf(status, sizeof(status),
                     "Dumping ... %ds elapsed, %d files (%d stable)",
                     elapsedSec, count, stableCount);
            PostMessageA(g_hWnd, WM_INJECT_LOG, 0, (LPARAM)_strdup(status));
        } else if (elapsedSec % 30 == 0) {
            char status[128];
            int remainSec = 120 - elapsedSec;
            if (remainSec < 0) remainSec = 0;
            snprintf(status, sizeof(status),
                     "Waiting for dump ... %ds remaining (~2 min total)",
                     remainSec);
            PostMessageA(g_hWnd, WM_INJECT_LOG, 0, (LPARAM)_strdup(status));
        }

        /* Pump messages */
        MSG m;
        while (PeekMessageA(&m, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageA(&m);
        }
        Sleep(500);
        pollCount++;
    }

    if (pollCount >= maxPolls) {
        if (lastFileCount > 0) {
            LogMessage("[+] Dump polling ended. %d file(s) written to: %s",
                       lastFileCount, numPollDirs > 0 ? pollDirs[0] : "unknown");
            SetProgress(100);
        } else {
            LogMessage("[-] Dump timed out after %d min — no files found.",
                       maxPolls * 500 / 60000);
            LogMessage("[-] Possible causes: anti-cheat blocked injection, insufficient"
                       " privileges, or the dump logic crashed.");
            LogMessage("[-] Check helper_debug.txt in the AutoDumped folder for details.");
            SetProgress(0);
        }
    }

    PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
    return 0;
}

/* ── Enable/disable controls (main thread only!) ── */
static void SetUIControls(BOOL enable) {
    EnableWindow(g_hBtnInjectRun,    enable);
    EnableWindow(g_hBtnInjectLaunch, enable);
    EnableWindow(g_hBtnBrowse,       enable);
    EnableWindow(g_hBtnOpenFolder,   enable);
    ShowWindow(g_hProgress,   enable ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hStaticHint, enable ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hStaticWarn, enable ? SW_HIDE : SW_SHOW);
    InvalidateRect(g_hWnd, NULL, FALSE);
}

/* ── Button handlers ── */
static void OnBrowse(HWND hWnd) {
    OPENFILENAMEA ofn = {0};
    char buf[MAX_PATH] = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = sizeof(buf);
    ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameA(&ofn)) {
        strncpy(g_selectedExe, buf, sizeof(g_selectedExe) - 1);
        SetWindowTextA(g_hEditProcess, buf);
        LogMessage("[*] Selected: %s", buf);
    }
}

static void StartInjection(int mode) {
    if (g_injectRunning) return;
    char buf[MAX_PATH] = {0};
    GetWindowTextA(g_hEditProcess, buf, sizeof(buf));
    if (buf[0] == 0) {
        LogMessage("[-] Enter a process name or select an .exe first.");
        return;
    }
    g_injectRunning = 1;
    CloseHandle(CreateThread(NULL, 0, WorkerThread, (LPVOID)(INT_PTR)mode, 0, NULL));
}

/* ── Owner-draw button helper ── */
static void DrawOwnedButton(DRAWITEMSTRUCT* dis, int idx) {
    BOOL pressed = (dis->itemState & ODS_SELECTED) || g_btnPress[idx];
    BOOL hover   = g_btnHover[idx];
    BOOL enabled = !(dis->itemState & ODS_DISABLED);

    COLORREF base = g_btnColor[idx];
    COLORREF bg;
    if (!enabled)  bg = RGB(45, 45, 60);
    else if (pressed) bg = RGB(GetRValue(base)*6/10, GetGValue(base)*6/10, GetBValue(base)*6/10);
    else if (hover)   bg = RGB(min(GetRValue(base)+30,255), min(GetGValue(base)+30,255), min(GetBValue(base)+30,255));
    else              bg = base;

    HBRUSH hbr = CreateSolidBrush(bg);
    HPEN   hpen = CreatePen(PS_SOLID, 1, hover && enabled ? COL_ACCENT : COL_BORDER);
    HBRUSH oldBr = (HBRUSH)SelectObject(dis->hDC, hbr);
    HPEN   oldPen = (HPEN)SelectObject(dis->hDC, hpen);
    RoundRect(dis->hDC, dis->rcItem.left, dis->rcItem.top,
              dis->rcItem.right, dis->rcItem.bottom, 6, 6);
    SelectObject(dis->hDC, oldBr);
    SelectObject(dis->hDC, oldPen);
    DeleteObject(hbr);
    DeleteObject(hpen);

    char text[128] = {0};
    GetWindowTextA(dis->hwndItem, text, sizeof(text));
    SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, enabled ? COL_TXT : COL_TXT_DIM);
    if (g_hFontUI) SelectObject(dis->hDC, g_hFontUI);
    DrawTextA(dis->hDC, text, -1, &dis->rcItem,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}

/* ── Subclass proc to track hover/press per owner-draw button ── */
static WNDPROC g_btnOrigProc[BTN_COUNT];
static LRESULT CALLBACK BtnSubclassProc(HWND hBtn, UINT msg, WPARAM wP, LPARAM lP) {
    int idx = -1;
    for (int i = 0; i < BTN_COUNT; i++)
        if (g_btns[i] == hBtn) { idx = i; break; }
    if (idx < 0) return DefWindowProcA(hBtn, msg, wP, lP);

    switch (msg) {
        case WM_MOUSEMOVE:
            if (!g_btnHover[idx]) {
                g_btnHover[idx] = TRUE;
                TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hBtn, 0 };
                TrackMouseEvent(&tme);
                InvalidateRect(hBtn, NULL, FALSE);
            }
            break;
        case WM_MOUSELEAVE:
            g_btnHover[idx] = FALSE;
            g_btnPress[idx] = FALSE;
            InvalidateRect(hBtn, NULL, FALSE);
            break;
        case WM_LBUTTONDOWN:
            g_btnPress[idx] = TRUE;
            InvalidateRect(hBtn, NULL, FALSE);
            break;
        case WM_LBUTTONUP:
            g_btnPress[idx] = FALSE;
            InvalidateRect(hBtn, NULL, FALSE);
            break;
    }
    return CallWindowProcA(g_btnOrigProc[idx], hBtn, msg, wP, lP);
}

/* ── Window procedure ── */
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = ((CREATESTRUCTA*)lParam)->hInstance;

            /* Brushes */
            g_hBrushBg    = CreateSolidBrush(COL_BG);
            g_hBrushPanel = CreateSolidBrush(COL_PANEL);
            g_hBrushLogBg = CreateSolidBrush(COL_LOG_BG);
            g_hBrushWarn  = CreateSolidBrush(COL_WARN_BG);

            /* Fonts */
            g_hFontUI = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
            g_hFontMono = CreateFontA(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, FIXED_PITCH | FF_DONTCARE, "Consolas");
            g_hFontTitle = CreateFontA(-16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

            /* Dark title bar */
            HMODULE hDwm = LoadLibraryA("dwmapi.dll");
            if (hDwm) {
                typedef HRESULT (WINAPI *PFN_DWM)(HWND, DWORD, LPCVOID, DWORD);
                PFN_DWM fn = (PFN_DWM)GetProcAddress(hDwm, "DwmSetWindowAttribute");
                if (fn) { BOOL dark = TRUE; fn(hWnd, 20, &dark, sizeof(dark)); }
                FreeLibrary(hDwm);
            }

            /* ── Target path row ── */
            HWND hLbl = CreateWindowA("STATIC", "Target:",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                MARGIN, ROW1_Y + 3, 52, 22, hWnd, NULL, hInst, NULL);
            if (g_hFontUI) SendMessage(hLbl, WM_SETFONT, (WPARAM)g_hFontUI, 0);

            g_hEditProcess = CreateWindowExA(0, "EDIT", "",
                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                MARGIN + 56, ROW1_Y, WIN_W - MARGIN*2 - 56 - 90, 26,
                hWnd, (HMENU)ID_EDIT_PROCESS, hInst, NULL);
            if (g_hFontMono) SendMessage(g_hEditProcess, WM_SETFONT, (WPARAM)g_hFontMono, 0);

            g_hBtnBrowse = CreateWindowA("BUTTON", "Browse...",
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                WIN_W - MARGIN - 86, ROW1_Y - 1, 86, 28,
                hWnd, (HMENU)ID_BTN_BROWSE, hInst, NULL);

            /* ── Action buttons row ── */
            int bw = 150, bh = 32, bx = MARGIN;
            g_hBtnInjectRun = CreateWindowA("BUTTON", "Inject into Running",
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                bx, ROW2_Y, bw, bh, hWnd, (HMENU)ID_BTN_INJECT_RUN, hInst, NULL);
            bx += bw + 8;
            g_hBtnInjectLaunch = CreateWindowA("BUTTON", "Launch && Inject",
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                bx, ROW2_Y, bw, bh, hWnd, (HMENU)ID_BTN_INJECT_LAUNCH, hInst, NULL);
            bx += bw + 8;
            g_hBtnOpenFolder = CreateWindowA("BUTTON", "Open Dump Folder",
                WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                bx, ROW2_Y, bw, bh, hWnd, (HMENU)ID_BTN_OPEN_FOLDER, hInst, NULL);

            /* Register buttons for subclassing + set colors */
            g_btns[0] = g_hBtnInjectRun;    g_btnColor[0] = COL_BTN_RUN;
            g_btns[1] = g_hBtnInjectLaunch; g_btnColor[1] = COL_BTN_LAUNCH;
            g_btns[2] = g_hBtnOpenFolder;   g_btnColor[2] = COL_BTN_FOLD;
            g_btns[3] = g_hBtnBrowse;       g_btnColor[3] = COL_BTN_BROW;
            for (int i = 0; i < BTN_COUNT; i++) {
                g_btnHover[i] = FALSE; g_btnPress[i] = FALSE;
                g_btnOrigProc[i] = (WNDPROC)SetWindowLongPtrA(
                    g_btns[i], GWLP_WNDPROC, (LONG_PTR)BtnSubclassProc);
            }

            /* ── Hint / Warning banner ── */
            g_hStaticHint = CreateWindowA("STATIC",
                "Steps:  1. Browse for the target .exe    "
                "2. Click Launch & Inject (or Inject into Running)    "
                "3. Wait for dump to finish    "
                "4. Open Dump Folder to view results",
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
                MARGIN, HINT_Y, WIN_W - MARGIN*2, 30,
                hWnd, (HMENU)ID_STATIC_HINT, hInst, NULL);
            if (g_hFontUI) SendMessage(g_hStaticHint, WM_SETFONT, (WPARAM)g_hFontUI, 0);

            g_hStaticWarn = CreateWindowA("STATIC",
                "  (!!)  Do NOT close the target process until the dump is complete!",
                WS_CHILD | SS_CENTER | SS_CENTERIMAGE,
                MARGIN, HINT_Y, WIN_W - MARGIN*2, 30,
                hWnd, (HMENU)ID_STATIC_WARN, hInst, NULL);
            if (g_hFontUI) SendMessage(g_hStaticWarn, WM_SETFONT, (WPARAM)g_hFontUI, 0);

            /* ── Progress bar ── */
            g_hProgress = CreateWindowExA(0, PROGRESS_CLASSA, "",
                WS_CHILD | PBS_SMOOTH,
                MARGIN, PROG_Y, WIN_W - MARGIN*2, 14,
                hWnd, (HMENU)ID_PROGRESS, hInst, NULL);
            SendMessage(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
            SendMessage(g_hProgress, PBM_SETPOS, 0, 0);
            SendMessage(g_hProgress, PBM_SETBARCOLOR, 0, (LPARAM)COL_ACCENT);
            SendMessage(g_hProgress, PBM_SETBKCOLOR,  0, (LPARAM)COL_PANEL);
            ShowWindow(g_hProgress, SW_HIDE);

            /* ── Log listbox ── */
            g_hListLog = CreateWindowExA(0, "LISTBOX", "",
                WS_CHILD | WS_VISIBLE | LBS_NOINTEGRALHEIGHT |
                LBS_OWNERDRAWFIXED | LBS_HASSTRINGS | WS_VSCROLL,
                MARGIN, LOG_Y, WIN_W - MARGIN*2, LOG_H,
                hWnd, (HMENU)ID_LIST_LOG, hInst, NULL);
            if (g_hFontMono) SendMessage(g_hListLog, WM_SETFONT, (WPARAM)g_hFontMono, 0);
            SendMessageA(g_hListLog, LB_SETITEMHEIGHT, 0, 17);

            /* ── Status strip ── */
            g_hStaticStatus = CreateWindowA("STATIC", "Ready.",
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
                MARGIN + 4, STAT_Y, WIN_W - MARGIN*2 - 4, STAT_H,
                hWnd, (HMENU)ID_STATIC_STATUS, hInst, NULL);
            if (g_hFontUI) SendMessage(g_hStaticStatus, WM_SETFONT, (WPARAM)g_hFontUI, 0);

            LogMessage("[*] Ready. Enter a process name or browse for an .exe.");
            return 0;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);

            RECT rc;
            GetClientRect(hWnd, &rc);

            /* Main background */
            FillRect(hdc, &rc, g_hBrushBg);

            /* Header bar */
            RECT hdr = { 0, 0, rc.right, HDR_H };
            HBRUSH hbrHdr = CreateSolidBrush(COL_HDR);
            FillRect(hdc, &hdr, hbrHdr);
            DeleteObject(hbrHdr);

            /* Accent line under header */
            HPEN hpen = CreatePen(PS_SOLID, 2, COL_ACCENT);
            HPEN oldPen = (HPEN)SelectObject(hdc, hpen);
            MoveToEx(hdc, 0, HDR_H, NULL);
            LineTo(hdc, rc.right, HDR_H);
            SelectObject(hdc, oldPen);
            DeleteObject(hpen);

            /* Header title */
            SetBkMode(hdc, TRANSPARENT);
            if (g_hFontTitle) SelectObject(hdc, g_hFontTitle);
            SetTextColor(hdc, COL_TXT);
            RECT titleRc = { MARGIN, 10, 400, HDR_H };
            DrawTextA(hdc, "AutoDump", -1, &titleRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            /* Header subtitle */
            if (g_hFontUI) SelectObject(hdc, g_hFontUI);
            SetTextColor(hdc, COL_TXT_DIM);
            RECT subRc = { MARGIN + 108, 14, 500, HDR_H };
            DrawTextA(hdc, "Stealth Memory Dumper", -1, &subRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

            /* Separator above log */
            HPEN hpen2 = CreatePen(PS_SOLID, 1, COL_BORDER);
            HPEN oldPen2 = (HPEN)SelectObject(hdc, hpen2);
            MoveToEx(hdc, MARGIN, SEP2_Y, NULL);
            LineTo(hdc, rc.right - MARGIN, SEP2_Y);

            /* Separator above status */
            MoveToEx(hdc, MARGIN, STAT_Y - 4, NULL);
            LineTo(hdc, rc.right - MARGIN, STAT_Y - 4);
            SelectObject(hdc, oldPen2);
            DeleteObject(hpen2);

            /* Edit background panel */
            RECT editPanelRc = { MARGIN - 2, ROW1_Y - 3,
                                 WIN_W - MARGIN + 2, ROW1_Y + 30 };
            FillRect(hdc, &editPanelRc, g_hBrushPanel);

            EndPaint(hWnd, &ps);
            return 0;
        }

        /* ── Worker thread messages ── */
        case WM_INJECT_LOG: {
            char* msg = (char*)lParam;
            if (msg) {
                SendMessageA(g_hListLog, LB_ADDSTRING, 0, (LPARAM)msg);
                SendMessageA(g_hListLog, LB_SETTOPINDEX,
                    SendMessageA(g_hListLog, LB_GETCOUNT, 0, 0) - 1, 0);
                SetWindowTextA(g_hStaticStatus, msg);
                free(msg);
            }
            return 0;
        }

        case WM_INJECT_PROGRESS:
            SendMessage(g_hProgress, PBM_SETPOS, wParam, 0);
            return 0;

        case WM_INJECT_START:
            SetUIControls(FALSE);
            SendMessage(g_hProgress, PBM_SETPOS, 0, 0);
            SetWindowTextA(g_hStaticStatus, "Injecting ...");
            InvalidateRect(hWnd, NULL, FALSE);
            return 0;

        case WM_INJECT_DONE:
            SetUIControls(TRUE);
            g_injectRunning = 0;
            SetWindowTextA(g_hStaticStatus, "Ready.");
            InvalidateRect(hWnd, NULL, FALSE);
            return 0;

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BTN_BROWSE:       OnBrowse(hWnd); break;
                case ID_BTN_INJECT_RUN:   StartInjection(0); break;
                case ID_BTN_INJECT_LAUNCH: StartInjection(1); break;
                case ID_BTN_OPEN_FOLDER: {
                    char myDir[MAX_PATH];
                    GetMyDir(myDir, sizeof(myDir));
                    if (myDir[0]) {
                        ShellExecuteA(hWnd, "open", myDir, NULL, NULL, SW_SHOW);
                    }
                    break;
                }
            }
            return 0;
        }

        case WM_CLOSE: {
            /* Kill injector.exe if it's still running */
            HANDLE hProc = g_injectorProcess;
            if (hProc) {
                DWORD exitCode;
                if (GetExitCodeProcess(hProc, &exitCode) && exitCode == STILL_ACTIVE) {
                    TerminateProcess(hProc, 1);
                }
            }
            DestroyWindow(hWnd);
            return 0;
        }

        case WM_DESTROY:
            if (g_hBrushBg)    DeleteObject(g_hBrushBg);
            if (g_hBrushPanel) DeleteObject(g_hBrushPanel);
            if (g_hBrushLogBg) DeleteObject(g_hBrushLogBg);
            if (g_hBrushWarn)  DeleteObject(g_hBrushWarn);
            if (g_hFontUI)     DeleteObject(g_hFontUI);
            if (g_hFontMono)   DeleteObject(g_hFontMono);
            if (g_hFontTitle)  DeleteObject(g_hFontTitle);
            PostQuitMessage(0);
            return 0;

        case WM_CTLCOLORSTATIC: {
            HDC hdc = (HDC)wParam;
            HWND hCtrl = (HWND)lParam;
            if (hCtrl == g_hStaticWarn) {
                SetBkColor(hdc, COL_WARN_BG);
                SetTextColor(hdc, COL_WARN_FG);
                return (LRESULT)g_hBrushWarn;
            }
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, hCtrl == g_hStaticStatus ? COL_TXT_DIM : COL_TXT);
            return (LRESULT)g_hBrushBg;
        }
        case WM_CTLCOLOREDIT: {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, COL_PANEL);
            SetTextColor(hdc, COL_TXT);
            return (LRESULT)g_hBrushPanel;
        }
        case WM_CTLCOLORLISTBOX: {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, COL_LOG_BG);
            SetTextColor(hdc, COL_TXT);
            return (LRESULT)g_hBrushLogBg;
        }

        case WM_MEASUREITEM: {
            MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
            if (mis->CtlID == ID_LIST_LOG)
                mis->itemHeight = 17;
            return TRUE;
        }

        case WM_DRAWITEM: {
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
            if (dis->CtlID == ID_LIST_LOG) {
                if (dis->itemID == (UINT)-1) break;

                char text[1024] = {0};
                SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)text);

                COLORREF fg;
                if      (text[0]=='['&&text[1]=='+') fg = RGB(90,  210, 110); /* green  */
                else if (text[0]=='['&&text[1]=='-') fg = RGB(220, 75,  75);  /* red    */
                else if (strncmp(text,"[injector]",10)==0) fg = RGB(120,170,240); /* blue */
                else                                 fg = COL_TXT_DIM;        /* gray   */

                COLORREF bg = (dis->itemState & ODS_SELECTED) ? COL_SEL_BG : COL_LOG_BG;
                HBRUSH hbr = CreateSolidBrush(bg);
                FillRect(dis->hDC, &dis->rcItem, hbr);
                DeleteObject(hbr);

                /* Left accent stripe for [+] / [-] */
                if (text[0]=='['&&(text[1]=='+'||text[1]=='-')) {
                    HBRUSH stripe = CreateSolidBrush(fg);
                    RECT sr = dis->rcItem; sr.right = sr.left + 3;
                    FillRect(dis->hDC, &sr, stripe);
                    DeleteObject(stripe);
                }

                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, fg);
                if (g_hFontMono) SelectObject(dis->hDC, g_hFontMono);
                RECT rc = dis->rcItem; rc.left += 8;
                DrawTextA(dis->hDC, text, -1, &rc,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                return TRUE;
            }
            if (dis->CtlID == ID_BTN_INJECT_RUN)    { DrawOwnedButton(dis, 0); return TRUE; }
            if (dis->CtlID == ID_BTN_INJECT_LAUNCH)  { DrawOwnedButton(dis, 1); return TRUE; }
            if (dis->CtlID == ID_BTN_OPEN_FOLDER)    { DrawOwnedButton(dis, 2); return TRUE; }
            if (dis->CtlID == ID_BTN_BROWSE)         { DrawOwnedButton(dis, 3); return TRUE; }
            break;
        }
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;

    INITCOMMONCONTROLSEX icc = {0};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(COL_BG);
    wc.lpszClassName = "InjectorGUI";

    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class.", "Error", MB_ICONERROR);
        return 1;
    }

    HWND hWnd = CreateWindowExA(0, "InjectorGUI", "AutoDump",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU |
                                WS_MINIMIZEBOX,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                WIN_W + 16, WIN_H + 39, NULL, NULL, hInstance, NULL);
    if (!hWnd) {
        MessageBoxA(NULL, "Failed to create window.", "Error", MB_ICONERROR);
        return 1;
    }
    g_hWnd = hWnd;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
