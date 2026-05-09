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

static HWND g_hWnd           = NULL; /* main window handle */
static HWND g_hEditProcess;
static HWND g_hListLog;
static HWND g_hBtnInjectRun;
static HWND g_hBtnInjectLaunch;
static HWND g_hBtnBrowse;
static HWND g_hBtnOpenFolder;
static HWND g_hStaticStatus;
static HWND g_hProgress;
static char g_selectedExe[MAX_PATH] = {0};
static volatile int g_injectRunning = 0;
static HANDLE g_injectorProcess = NULL; /* handle to the running injector.exe */

/* Custom messages from worker -> main thread */
#define WM_INJECT_LOG     (WM_APP + 1)
#define WM_INJECT_START   (WM_APP + 2)
#define WM_INJECT_DONE    (WM_APP + 3)

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

    char processName[MAX_PATH] = {0};
    GetWindowTextA(g_hEditProcess, processName, sizeof(processName));

    if (processName[0] == 0) {
        LogMessage("[-] No target specified.");
        PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
        return 0;
    }

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
    if (exitCode == 0)
        LogMessage("[+] Injection complete. Dump running in target process (~2 min).");
    else
        LogMessage("[-] Injector failed with exit code %lu", exitCode);

    /* Keep the progress bar / "injecting" state alive for a bit more
       since the actual dump runs inside the target process. We'll show
       a "waiting for dump" state for up to 2 minutes. */
    LogMessage("[*] Waiting for dump output files ...");

    /* Poll for dump files up to ~3 minutes.
       The helper DLL now writes output files to our directory (thanks to
       the output-directory-marker fix), but also check CWD as fallback. */
    char pollDirs[2][MAX_PATH];
    int numPollDirs = 0;

    GetMyDir(pollDirs[0], sizeof(pollDirs[0]));
    if (pollDirs[0][0]) numPollDirs = 1;

    /* Also add CWD as a fallback */
    if (GetCurrentDirectoryA(MAX_PATH, pollDirs[1]) > 0) {
        /* Avoid duplicating if same as our dir */
        if (numPollDirs == 0 || _stricmp(pollDirs[0], pollDirs[1]) != 0) {
            /* Add backslash if missing */
            size_t cwdLen = strlen(pollDirs[1]);
            if (cwdLen > 0 && pollDirs[1][cwdLen - 1] != '\\') {
                pollDirs[1][cwdLen] = '\\';
                pollDirs[1][cwdLen + 1] = 0;
            }
            numPollDirs = 2;
        }
    }

    int pollCount = 0;
    int maxPolls  = 360; /* 360 * 500ms = 180s = 3 min */
    int lastFileCount = 0;
    int stableCount  = 0; /* consecutive polls with same count */

    while (pollCount < maxPolls) {
        int count = 0;

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
            LogMessage("[*] Dump polling ended (%d files found, dirs: %s & CWD).",
                       lastFileCount, pollDirs[0]);
        } else {
            LogMessage("[*] Dump polling timed out (%d min). No dump files found.",
                       maxPolls * 500 / 60000);
            LogMessage("[*] Check the target process's working directory for dump files.");
            LogMessage("[*] Or look for helper_debug.txt for debug logs.");
        }
    }

    PostMessageA(g_hWnd, WM_INJECT_DONE, 0, 0);
    return 0;
}

/* Global brushes for dark theme */
static HBRUSH g_hBrushDark     = NULL; /* RGB(30,30,30)  — main bg */
static HBRUSH g_hBrushDarkEdit = NULL; /* RGB(40,40,40)  — edit/list bg */

/* ── Enable/disable controls (main thread only!) ── */
static void SetUIControls(BOOL enable) {
    EnableWindow(g_hBtnInjectRun, enable);
    EnableWindow(g_hBtnInjectLaunch, enable);
    EnableWindow(g_hBtnBrowse, enable);
    EnableWindow(g_hBtnOpenFolder, enable);
    ShowWindow(g_hProgress, enable ? SW_HIDE : SW_SHOW);
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

/* ── Window procedure ── */
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            /* Create dark background brushes */
            g_hBrushDark     = CreateSolidBrush(RGB(30, 30, 30));
            g_hBrushDarkEdit = CreateSolidBrush(RGB(40, 40, 40));

            HFONT hFont = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                      CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                      DEFAULT_PITCH | FF_DONTCARE, "Consolas");

            /* Try dark title bar (Win10 20H1+), silently ignored on older builds */
            HMODULE hDwm = LoadLibraryA("dwmapi.dll");
            if (hDwm) {
                typedef HRESULT (WINAPI *DWMSETWINDOWATTR)(HWND, DWORD, LPCVOID, DWORD);
                DWMSETWINDOWATTR pDwm = (DWMSETWINDOWATTR)GetProcAddress(hDwm, "DwmSetWindowAttribute");
                if (pDwm) {
                    BOOL dark = TRUE;
                    pDwm(hWnd, 20, &dark, sizeof(dark));
                }
                FreeLibrary(hDwm);
            }

            CreateWindowA("STATIC", "Target Process:",
                          WS_CHILD | WS_VISIBLE, 10, 10, 120, 22,
                          hWnd, NULL, NULL, NULL);

            g_hEditProcess = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                             WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                             130, 10, 310, 24,
                                             hWnd, (HMENU)ID_EDIT_PROCESS, NULL, NULL);
            if (hFont) SendMessage(g_hEditProcess, WM_SETFONT, (WPARAM)hFont, 0);

            g_hBtnBrowse = CreateWindowA("BUTTON", "Browse...",
                                         WS_CHILD | WS_VISIBLE, 445, 10, 85, 24,
                                         hWnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);

            g_hBtnInjectRun = CreateWindowA("BUTTON", "Inject into Running",
                                            WS_CHILD | WS_VISIBLE, 10, 45, 130, 30,
                                            hWnd, (HMENU)ID_BTN_INJECT_RUN, NULL, NULL);

            g_hBtnInjectLaunch = CreateWindowA("BUTTON", "Launch && Inject",
                                               WS_CHILD | WS_VISIBLE, 145, 45, 130, 30,
                                               hWnd, (HMENU)ID_BTN_INJECT_LAUNCH, NULL, NULL);

            g_hBtnOpenFolder = CreateWindowA("BUTTON", "Open Dump Folder",
                                             WS_CHILD | WS_VISIBLE,
                                             280, 45, 120, 30,
                                             hWnd, (HMENU)ID_BTN_OPEN_FOLDER, NULL, NULL);

            /* Marquee progress bar (hidden until injection starts) */
            g_hProgress = CreateWindowExA(0, PROGRESS_CLASSA, "",
                                          WS_CHILD | PBS_MARQUEE,
                                          405, 49, 130, 22,
                                          hWnd, (HMENU)ID_PROGRESS, NULL, NULL);
            SendMessage(g_hProgress, PBM_SETMARQUEE, (WPARAM)TRUE, 0);
            ShowWindow(g_hProgress, SW_HIDE);

            g_hStaticStatus = CreateWindowA("STATIC", "Ready.",
                                            WS_CHILD | WS_VISIBLE | SS_SUNKEN,
                                            10, 85, 530, 20,
                                            hWnd, (HMENU)ID_STATIC_STATUS, NULL, NULL);
            if (hFont) SendMessage(g_hStaticStatus, WM_SETFONT, (WPARAM)hFont, 0);

            g_hListLog = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
                                         WS_CHILD | WS_VISIBLE | LBS_NOINTEGRALHEIGHT |
                                         WS_VSCROLL | WS_HSCROLL,
                                         10, 115, 530, 220,
                                         hWnd, (HMENU)ID_LIST_LOG, NULL, NULL);
            if (hFont) SendMessage(g_hListLog, WM_SETFONT, (WPARAM)hFont, 0);

            LogMessage("[*] Ready. Enter a process name or browse for an .exe.");
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

        case WM_INJECT_START:
            SetUIControls(FALSE);
            SetWindowTextA(g_hStaticStatus, "Injecting ...");
            return 0;

        case WM_INJECT_DONE:
            SetUIControls(TRUE);
            g_injectRunning = 0;
            SetWindowTextA(g_hStaticStatus, "Ready.");
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
            /* Clean up brushes */
            if (g_hBrushDark)     DeleteObject(g_hBrushDark);
            if (g_hBrushDarkEdit) DeleteObject(g_hBrushDarkEdit);
            PostQuitMessage(0);
            return 0;

        /* ── Dark mode background colors using pre-created brushes ── */
        case WM_CTLCOLORSTATIC: {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(30, 30, 30));
            SetTextColor(hdc, RGB(200, 200, 200));
            return (LRESULT)g_hBrushDark;
        }
        case WM_CTLCOLOREDIT: {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(40, 40, 40));
            SetTextColor(hdc, RGB(220, 220, 220));
            return (LRESULT)g_hBrushDarkEdit;
        }
        case WM_CTLCOLORLISTBOX: {
            HDC hdc = (HDC)wParam;
            SetBkColor(hdc, RGB(25, 25, 25));
            SetTextColor(hdc, RGB(180, 220, 180));
            return (LRESULT)g_hBrushDarkEdit;
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
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszClassName = "InjectorGUI";

    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class.", "Error", MB_ICONERROR);
        return 1;
    }

    HWND hWnd = CreateWindowExA(0, "InjectorGUI", "Stealth DLL Injector - GUI",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU |
                                WS_MINIMIZEBOX,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                570, 380, NULL, NULL, hInstance, NULL);
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
