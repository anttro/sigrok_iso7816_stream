@echo off
rem sigrok_iso7816_stream setup (Windows): verify sigrok-cli, register decoder.
setlocal EnableExtensions EnableDelayedExpansion

set "DRAIN_TEST="
if /i "%~1"=="--drain-test" set "DRAIN_TEST=force"
if /i "%~1"=="--help" (
    echo Usage: setup.bat [--drain-test]
    echo   --drain-test  run the long CPU drain test without prompting
    exit /b 0
)

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

rem ---- hardware samplerate probe ---------------------------------------
echo Probing device samplerates...
set "MAX_RATE="
for %%r in (1M 2M 4M 8M 12M 16M 20M 24M) do (
    sigrok-cli -d fx2lafw --config samplerate=%%r --continuous --time 20 ^
        -P "iso7816:clk=D0:data=D1" >"%TEMP%\iso7816-probe.txt" 2>&1
    type "%TEMP%\iso7816-probe.txt" | findstr /c:"Unable to claim" >nul && (
        echo blocked - another program holds the device
        set "DEVICE_MSG=1"
        goto :probedone
    )
    type "%TEMP%\iso7816-probe.txt" | findstr /c:"Failed to open" /c:"No devices found" >nul && (
        echo skipped - no FX2 device connected
        set "DEVICE_MSG=1"
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

rem ---- optional long-duration CPU drain test ----------------------------
rem The probe above only checks whether the *device* accepts a rate.  On a
rem slow host the FX2 FIFO overflows and the device stops on its own a few
rem seconds in, even though the rate was accepted.  Ask first: on a fast
rem machine it is wasted time.  Each candidate runs up to 15s; an early stop
rem means the host cannot drain that rate.
set "DRAIN_DURATION_MS=15000"
set "CONFIG_FILE=%APPDATA%\sigrok_iso7816_stream\samplerate"
if defined MAX_RATE if not defined DEVICE_MSG if /i not "!DRAIN_TEST!"=="force" (
    echo.
    set /p "ANS=Run a long CPU drain test to find the highest sustainable rate? (skip on fast machines) [y/N]: "
    echo !ANS! | findstr /i /b "y" >nul && set "DRAIN_TEST=yes"
)
if /i "!DRAIN_TEST!"=="force" set "DRAIN_TEST=yes"

if defined MAX_RATE if not defined DEVICE_MSG if /i "!DRAIN_TEST!"=="yes" (
    echo Drain test ^(an early stop means the host cannot keep up^):
    set "MAX_MHZ=!MAX_RATE:~0,-1!"
    set /a "MIN_ELAPSED=!DRAIN_DURATION_MS!*70/100"
    for %%m in (24 20 16 12 8 4 2 1) do (
        if not defined SUSTAINABLE if %%m LEQ !MAX_MHZ! (
            for /f "usebackq" %%e in (`powershell -NoProfile -Command "$sw=[Diagnostics.Stopwatch]::StartNew(); & sigrok-cli -d fx2lafw --config samplerate=%%mM --continuous --time !DRAIN_DURATION_MS! -P 'iso7816:clk=D0:data=D1' *>$null; $sw.Stop(); $sw.ElapsedMilliseconds"`) do set "ELAPSED=%%e"
            if !ELAPSED! GEQ !MIN_ELAPSED! (
                set "SUSTAINABLE=%%m"
                echo   %%mM sustained
            ) else (
                echo   %%mM stopped early
            )
        )
    )
    if defined SUSTAINABLE (
        echo Highest sustainable rate: !SUSTAINABLE!M
        if !SUSTAINABLE! LSS 16 (
            echo This host cannot sustain the 16M default.
            set /p "ANS=Write a config pinning !SUSTAINABLE!M? [y/N]: "
            echo !ANS! | findstr /i /b "y" >nul
            if not errorlevel 1 (
                if not exist "%APPDATA%\sigrok_iso7816_stream" mkdir "%APPDATA%\sigrok_iso7816_stream"
                >"%CONFIG_FILE%" echo !SUSTAINABLE!M
                echo Wrote config; start.bat will use !SUSTAINABLE!M.
            ) else (
                echo Config not written; start.bat will keep trying 16M here.
                echo   Per-run override: start.bat --samplerate !SUSTAINABLE!M
            )
        )
    ) else (
        echo No rate survived !DRAIN_DURATION_MS! ms - device or host problem.
    )
)

echo.
echo Done. Next steps:
echo   1. Plug GND first and verify contact manually (see README).
echo   2. start.bat              -- capture + GSMTAP stream
endlocal
