@echo off
rem sigrok_iso7816_stream launcher (Windows): capture ISO 7816 and stream
rem GSMTAP to :4729.  Flag-for-flag equivalent of start.sh.

setlocal EnableExtensions EnableDelayedExpansion

set "CLK=D1"
set "DATA=D6"
set "RST=D0"
set "VCC=D4"
set "SAMPLERATE=16M"
set "CLOCK=native"
set "HOST=127.0.0.1"
set "PORT=4729"
set "PCAP="
set "DEBUG="

:argloop
if "%~1"=="" goto :argsdone
if /i "%~1"=="--clk"         ( set "CLK=%~2"         & shift & shift & goto :argloop )
if /i "%~1"=="--data"        ( set "DATA=%~2"        & shift & shift & goto :argloop )
if /i "%~1"=="--rst"         ( set "RST=%~2"         & shift & shift & goto :argloop )
if /i "%~1"=="--vcc"         ( set "VCC=%~2"         & shift & shift & goto :argloop )
if /i "%~1"=="--samplerate"  ( set "SAMPLERATE=%~2"  & shift & shift & goto :argloop )
if /i "%~1"=="--clock"       ( set "CLOCK=%~2"       & shift & shift & goto :argloop )
if /i "%~1"=="--host"        ( set "HOST=%~2"        & shift & shift & goto :argloop )
if /i "%~1"=="--port"        ( set "PORT=%~2"        & shift & shift & goto :argloop )
if /i "%~1"=="--pcap"        ( set "PCAP=%~2"        & shift & shift & goto :argloop )
if /i "%~1"=="--debug"       ( set "DEBUG=1"         & shift & goto :argloop )
if /i "%~1"=="--no-rst"      ( set "RST="            & shift & goto :argloop )
if /i "%~1"=="--no-vcc"      ( set "VCC="            & shift & goto :argloop )
if /i "%~1"=="-h"            ( goto :usage )
if /i "%~1"=="--help"        ( goto :usage )
echo Unknown option: %~1
exit /b 1

:usage
echo Usage: %~n0 [OPTIONS]
echo   --clk=CH          CLK channel        default: %CLK%
echo   --data=CH         I/O channel        default: %DATA%
echo   --rst=CH          RST channel        default: %RST%
echo   --vcc=CH          VCC channel        default: %VCC%
echo   --samplerate=SR   Sample rate        default: %SAMPLERATE%
echo   --clock=MODE      native/detect/sample_as_clock
echo   --host=IP         GSMTAP destination default: 127.0.0.1
echo   --port=N          GSMTAP port        default: 4729
echo   --pcap=FILE       Also write decoded events to FILE (no spaces in path)
echo   --debug           Verbose libsigrokdecode logging (-l 4)
echo   --no-rst          Disable RST tracking
echo   --no-vcc          Disable VCC tracking
echo.
echo To log output on Windows use redirection: %~n0 ... ^> capture.log 2^>^&1
exit /b 0

:argsdone
set "SIGROK_EXE="
rem Try known install locations (order: 64-bit, 32-bit, then PATH)
if not defined SIGROK_EXE if exist "%ProgramFiles%\sigrok\sigrok-cli\sigrok-cli.exe" set "SIGROK_EXE=%ProgramFiles%\sigrok\sigrok-cli\sigrok-cli.exe"
if not defined SIGROK_EXE if exist "%ProgramFiles(x86)%\sigrok\sigrok-cli\sigrok-cli.exe" set "SIGROK_EXE=%ProgramFiles(x86)%\sigrok\sigrok-cli\sigrok-cli.exe"
if not defined SIGROK_EXE if exist "%ProgramFiles%\sigrok\PulseView\sigrok-cli.exe" set "SIGROK_EXE=%ProgramFiles%\sigrok\PulseView\sigrok-cli.exe"
if not defined SIGROK_EXE if exist "%ProgramFiles(x86)%\sigrok\PulseView\sigrok-cli.exe" set "SIGROK_EXE=%ProgramFiles(x86)%\sigrok\PulseView\sigrok-cli.exe"
if not defined SIGROK_EXE where sigrok-cli >nul 2>&1 && for /f "delims=" %%i in ('where sigrok-cli') do set "SIGROK_EXE=%%i"
if not defined SIGROK_EXE goto :notfound
for %%i in ("!SIGROK_EXE!") do set "SIGROK_DIR=%%~dpi"
if "!SIGROK_DIR:~-1!"=="\" set "SIGROK_DIR=!SIGROK_DIR:~0,-1!"
set "PATH=!SIGROK_DIR!;!PATH!"
goto :found

:notfound
echo [X] sigrok-cli not found.
echo     Searched:
echo       %ProgramFiles%\sigrok\sigrok-cli
echo       %ProgramFiles(x86)%\sigrok\sigrok-cli
echo       %ProgramFiles%\sigrok\PulseView
echo       %ProgramFiles(x86)%\sigrok\PulseView
echo       PATH
echo     Install from https://sigrok.org/wiki/Downloads
exit /b 1

:found

set "OPTS=clk=%CLK%:data=%DATA%:clock_option=%CLOCK%"
set "OPTS=%OPTS%:gsmtap_host=%HOST%:gsmtap_port=%PORT%"
if defined RST set "OPTS=%OPTS%:rst=%RST%:rst_detect=true"
if defined VCC set "OPTS=%OPTS%:vcc=%VCC%:vcc_detect=true"
if defined PCAP set "OPTS=%OPTS%:pcap_file=%PCAP%"

set "CMDLINE=sigrok-cli -d fx2lafw --config samplerate=%SAMPLERATE% --continuous -C D0,D1,D2,D3,D4,D5,D6,D7"
if defined DEBUG set "CMDLINE=%CMDLINE% -l 4"
set "CMDLINE=%CMDLINE% -P iso7816:%OPTS% -A iso7816"

echo ISO 7816 streamer - clk=%CLK% data=%DATA% clock=%CLOCK%
if defined RST echo   RST tracking on channel %RST%
if defined VCC echo   VCC tracking on channel %VCC%
if defined PCAP echo   PCAP output: %PCAP%
echo Samplerate: %SAMPLERATE% ^| GSMTAP -^> %HOST%:%PORT%
echo Capture runs until you press Ctrl+C.
echo.

rem <NUL detaches stdin (best-effort to disable sigrok's "press any key
rem to stop acquisition" prompt); not verified on Windows, where the
rem prompt may read the console rather than stdin.
%CMDLINE% <NUL
exit /b %errorlevel%
