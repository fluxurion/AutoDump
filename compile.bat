@echo off
setlocal enabledelayedexpansion

:: Auto-detect MSYS2/MinGW GCC if not in PATH
where gcc >nul 2>nul
if %errorlevel% neq 0 (
    if exist "C:\msys64\ucrt64\bin\gcc.exe" set "PATH=C:\msys64\ucrt64\bin;%PATH%"
    if exist "C:\msys64\mingw64\bin\gcc.exe" set "PATH=C:\msys64\mingw64\bin;%PATH%"
)

set CC=gcc
set CFLAGS=-O2

echo ============================================
echo  Reverse Engineering Toolkit - Compilation
echo ============================================
echo.
echo [1/3] Compiling injector.exe ...
%CC% %CFLAGS% -o injector.exe injector.c
if %errorlevel% equ 0 (
    echo   [+] injector.exe created successfully
) else (
    echo   [-] FAILED with error code %errorlevel%
    pause
    exit /b %errorlevel%
)

echo.
echo [2/3] Compiling helper.dll ...
%CC% %CFLAGS% -shared -o helper.dll helper_dll.c -lversion
if %errorlevel% equ 0 (
    echo   [+] helper.dll created successfully
) else (
    echo   [-] FAILED with error code %errorlevel%
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Compiling injector_gui.exe ...
%CC% %CFLAGS% -mwindows -o injector_gui.exe injector_gui.c -lcomctl32 -lcomdlg32
if %errorlevel% equ 0 (
    echo   [+] injector_gui.exe created successfully
) else (
    echo   [-] FAILED with error code %errorlevel%
    pause
    exit /b %errorlevel%
)

echo.
echo ============================================
echo  Build complete!
echo   - injector.exe        (CLI injector)
echo   - helper.dll          (stealth helper DLL)
echo   - injector_gui.exe    (GUI launcher)
echo.
echo  Place all three files in the same directory
echo  and run as Administrator:
echo     .\injector_gui.exe
echo     - or -
echo     .\injector.exe target.exe
echo ============================================
echo.
pause
