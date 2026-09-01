@echo off
rem sigrok_iso7816_stream setup (Windows): verify sigrok-cli, register decoder.
setlocal EnableExtensions EnableDelayedExpansion

set "REPO_DIR=%~dp0"
if "%REPO_DIR:~-1%"=="\" set "REPO_DIR=%REPO_DIR:~0,-1%"
set "DEC_DIR=%LOCALAPPDATA%\libsigrokdecode\decoders"
set "LINK=%DEC_DIR%\iso7816"

echo sigrok_iso7816_stream setup (Windows)
echo.

rem ---- sigrok-cli -------------------------------------------------------
echo Checking sigrok-cli...
set "SIGROK_EXE="
if not defined SIGROK_EXE if exist "%ProgramFiles%\sigrok\sigrok-cli\sigrok-cli.exe" set "SIGROK_EXE=%ProgramFiles%\sigrok\sigrok-cli\sigrok-cli.exe"
if not defined SIGROK_EXE if exist "%ProgramFiles(x86)%\sigrok\sigrok-cli\sigrok-cli.exe" set "SIGROK_EXE=%ProgramFiles(x86)%\sigrok\sigrok-cli\sigrok-cli.exe"
if not defined SIGROK_EXE if exist "%ProgramFiles%\sigrok\PulseView\sigrok-cli.exe" set "SIGROK_EXE=%ProgramFiles%\sigrok\PulseView\sigrok-cli.exe"
if not defined SIGROK_EXE if exist "%ProgramFiles(x86)%\sigrok\PulseView\sigrok-cli.exe" set "SIGROK_EXE=%ProgramFiles(x86)%\sigrok\PulseView\sigrok-cli.exe"
if not defined SIGROK_EXE where sigrok-cli >nul 2>&1 && for /f "delims=" %%i in ('where sigrok-cli') do set "SIGROK_EXE=%%i"
if not defined SIGROK_EXE goto :notfound
for %%i in ("!SIGROK_EXE!") do set "SIGROK_DIR=%%~dpi"
if "!SIGROK_DIR:~-1!"=="\" set "SIGROK_DIR=!SIGROK_DIR:~0,-1!"
echo [ok] !SIGROK_EXE!
rem Add sigrok-cli dir to PATH so subsequent calls work even if only
rem discovered at the default install location.
set "PATH=!SIGROK_DIR!;!PATH!"
sigrok-cli --version 2>nul | findstr /r "^"
goto :sigrok_ok

:notfound
echo [X] sigrok-cli not found.
echo     Searched:
echo       %ProgramFiles%\sigrok\sigrok-cli
echo       %ProgramFiles(x86)%\sigrok\sigrok-cli
echo       %ProgramFiles%\sigrok\PulseView
echo       %ProgramFiles(x86)%\sigrok\PulseView
echo       PATH
echo     Install it from https://sigrok.org/wiki/Downloads
echo     ^(sigrok-cli-0.7.2-x86_64-installer.exe^), then re-open this
echo     window so PATH changes take effect and re-run.
exit /b 1

:sigrok_ok

rem If sigrok-cli fails to start with error 0xc0150002, install the
rem Microsoft Visual C++ 2010 Redistributable (msvcr100.dll).

rem ---- firmware ---------------------------------------------------------
echo Checking fx2lafw firmware...
set "FW_FOUND="
if not defined FW_FOUND if exist "!SIGROK_DIR!\share\sigrok-firmware\fx2lafw-cypress-fx2.fw" set "FW_FOUND=!SIGROK_DIR!\share\sigrok-firmware"
if not defined FW_FOUND if exist "!SIGROK_DIR!\..\share\sigrok-firmware\fx2lafw-cypress-fx2.fw" set "FW_FOUND=!SIGROK_DIR!\..\share\sigrok-firmware"
if not defined FW_FOUND if exist "%ProgramFiles%\sigrok\sigrok-cli\share\sigrok-firmware\fx2lafw-cypress-fx2.fw" set "FW_FOUND=%ProgramFiles%\sigrok\sigrok-cli\share\sigrok-firmware"
if not defined FW_FOUND if exist "%ProgramFiles(x86)%\sigrok\sigrok-cli\share\sigrok-firmware\fx2lafw-cypress-fx2.fw" set "FW_FOUND=%ProgramFiles(x86)%\sigrok\sigrok-cli\share\sigrok-firmware"
if not defined FW_FOUND if exist "%ProgramFiles%\sigrok\PulseView\share\sigrok-firmware\fx2lafw-cypress-fx2.fw" set "FW_FOUND=%ProgramFiles%\sigrok\PulseView\share\sigrok-firmware"
if not defined FW_FOUND if exist "%ProgramFiles(x86)%\sigrok\PulseView\share\sigrok-firmware\fx2lafw-cypress-fx2.fw" set "FW_FOUND=%ProgramFiles(x86)%\sigrok\PulseView\share\sigrok-firmware"
if not defined FW_FOUND if exist "%LOCALAPPDATA%\sigrok-firmware\fx2lafw-cypress-fx2.fw" set "FW_FOUND=%LOCALAPPDATA%\sigrok-firmware"
if not defined FW_FOUND if exist "%ProgramData%\sigrok-firmware\fx2lafw-cypress-fx2.fw" set "FW_FOUND=%ProgramData%\sigrok-firmware"
if defined FW_FOUND (
    echo [ok] !FW_FOUND!
) else (
    echo [!] bundled firmware directory not found - continuing anyway;
    echo     the installer normally ships fx2lafw firmware, and libsigrok
    echo     also searches %LOCALAPPDATA%\sigrok-firmware
)

rem ---- decoder registration --------------------------------------------
echo Registering decoder...
if not exist "%DEC_DIR%" mkdir "%DEC_DIR%"
if exist "%LINK%\pd.py" goto :link_ok
if exist "%LINK%" rmdir "%LINK%"
mklink /J "%LINK%" "%REPO_DIR%" >nul 2>&1
if errorlevel 1 (
    echo [X] could not create junction %LINK%
    exit /b 1
)
:link_ok
sigrok-cli -L 2>nul | findstr /i "iso7816" >nul
if errorlevel 1 (
    echo [X] decoder registered but NOT listed by sigrok-cli.
    echo     Expected junction: %LINK%
    exit /b 1
)
echo [ok] %LINK% -^> listed by sigrok-cli

rem ---- python / numpy (for tools\detect_pins.py) ------------------------
echo Checking Python + numpy...
set "PY="
py -3 --version >nul 2>&1 && set "PY=py -3"
if not defined PY (
    python --version >nul 2>&1 && set "PY=python"
)
if defined PY (
    for /f "delims=" %%v in ('!PY! --version 2^>^&1') do echo [ok] %%v
    !PY! -c "import numpy" >nul 2>&1 || echo [!] numpy missing: run '!PY! -m pip install numpy'
) else (
    echo [!] no python launcher found; detect_pins.py needs Python 3.8+ and numpy
)

rem ---- hardware samplerate probe ---------------------------------------
echo Probing device samplerates...
set "MAX_RATE="
for %%r in (1M 2M 4M 8M 12M 16M 20M 24M) do (
    sigrok-cli -d fx2lafw --config samplerate=%%r --continuous --time 20 ^
        -P "iso7816:clk=D0:data=D1" >"%TEMP%\iso7816-probe.txt" 2>&1
    type "%TEMP%\iso7816-probe.txt" | findstr /c:"Unable to claim" >nul && (
        echo blocked - another program holds the device
        goto :probedone
    )
    type "%TEMP%\iso7816-probe.txt" | findstr /c:"Failed to open" /c:"No devices found" >nul && (
        echo skipped - no FX2 device connected
        goto :probedone
    )
    type "%TEMP%\iso7816-probe.txt" | findstr /r /c:"invalid argument" /c:"Unable to sample" /c:"Could not start" >nul || set MAX_RATE=%%r
)
:probedone
if defined MAX_RATE (
    echo Highest accepted samplerate: !MAX_RATE!
) else if not defined MAX_RATE if not defined DEVICE_MSG (
    echo unknown - device present but no rate accepted
)

echo.
echo Done. Next steps:
echo   1. Plug GND first and verify contact manually (see README).
echo   2. tools\detect_pins.py   -- find the wiring
echo   3. start.bat              -- capture + GSMTAP stream
endlocal
