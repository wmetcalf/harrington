@echo off
rem ============================================================================
rem  collect-windows-env.bat
rem  Harvest the data harrington needs to emulate cmd.exe behaviors statically:
rem    - assoc                 (file ext -> ProgID map)
rem    - ftype                 (ProgID  -> command template)
rem    - environment variables (set)
rem    - where <binary>        (PATH resolution for known LOLBAS)
rem    - ver                   (Windows version string)
rem
rem  Run inside a clean sandbox VM. Produces ONE output file:
rem    %~dp0windows-env.json
rem  Commit it under: rust/crates/harrington-core/data/<winver>.json
rem
rem  No PowerShell, no .NET, no third-party tools. Plain cmd.exe only.
rem  Tested on Windows 7 SP1, Windows 10 21H2, Windows 11 23H2.
rem ============================================================================

setlocal enabledelayedexpansion

set "OUT=%~dp0windows-env.json"
set "TMPDIR=%TEMP%\harrington-collect"
if exist "%TMPDIR%" rd /s /q "%TMPDIR%" 2>nul
mkdir "%TMPDIR%" >nul 2>&1

echo [+] Collecting from %COMPUTERNAME% ^(user: %USERNAME%^)
echo [+] Output: %OUT%
echo.

rem --- raw captures -----------------------------------------------------------
echo [1/6] ver
ver > "%TMPDIR%\ver.txt" 2>&1

echo [2/6] assoc
assoc > "%TMPDIR%\assoc.txt" 2>&1

echo [3/6] ftype
ftype > "%TMPDIR%\ftype.txt" 2>&1

echo [4/6] set
set > "%TMPDIR%\set.txt" 2>&1

echo [5/6] where ^<lolbas^>
del "%TMPDIR%\where.txt" 2>nul
for %%B in (
    cmd.exe powershell.exe pwsh.exe cscript.exe wscript.exe
    mshta.exe rundll32.exe regsvr32.exe certutil.exe bitsadmin.exe
    curl.exe wget.exe ftp.exe tftp.exe
    wmic.exe schtasks.exe at.exe sc.exe net.exe net1.exe
    reg.exe regedit.exe taskkill.exe tasklist.exe whoami.exe
    forfiles.exe findstr.exe find.exe more.exe sort.exe type.com
    msbuild.exe regsvcs.exe regasm.exe installutil.exe ieexec.exe
    msxsl.exe odbcconf.exe sqldumper.exe pcalua.exe appvlp.exe
    runscripthelper.exe infdefaultinstall.exe diskshadow.exe msdt.exe
    hh.exe scriptrunner.exe syncappvpublishingserver.exe bash.exe
    msiexec.exe explorer.exe taskhost.exe svchost.exe conhost.exe
) do (
    set "_B=%%B"
    set "_W="
    for /f "delims=" %%P in ('where %%B 2^>nul') do (
        if not defined _W set "_W=%%P"
    )
    if defined _W (
        >> "%TMPDIR%\where.txt" echo !_B!=!_W!
    ) else (
        >> "%TMPDIR%\where.txt" echo !_B!=
    )
)

echo [6/6] PATHEXT, OS identity
> "%TMPDIR%\identity.txt" echo PATHEXT=%PATHEXT%
>> "%TMPDIR%\identity.txt" echo OS=%OS%
>> "%TMPDIR%\identity.txt" echo PROCESSOR_ARCHITECTURE=%PROCESSOR_ARCHITECTURE%
>> "%TMPDIR%\identity.txt" echo NUMBER_OF_PROCESSORS=%NUMBER_OF_PROCESSORS%
>> "%TMPDIR%\identity.txt" echo SystemRoot=%SystemRoot%
>> "%TMPDIR%\identity.txt" echo SystemDrive=%SystemDrive%
>> "%TMPDIR%\identity.txt" echo ProgramFiles=%ProgramFiles%
>> "%TMPDIR%\identity.txt" echo ProgramFiles(x86)=%ProgramFiles(x86)%
>> "%TMPDIR%\identity.txt" echo CommonProgramFiles=%CommonProgramFiles%
>> "%TMPDIR%\identity.txt" echo ComSpec=%ComSpec%
>> "%TMPDIR%\identity.txt" echo windir=%windir%

rem --- assemble JSON ----------------------------------------------------------
echo.
echo [+] Assembling JSON...

set "Q=^""
> "%OUT%" echo {
>> "%OUT%" echo   "schema": "harrington-windows-env/v1",

rem ver
for /f "delims=" %%L in (%TMPDIR%\ver.txt) do set "VER_LINE=%%L"
call :jsonEscape "%VER_LINE%" VER_LINE_ESC
>> "%OUT%" echo   "ver": "%VER_LINE_ESC%",

rem identity (flat key/value)
>> "%OUT%" echo   "identity": {
set "SEP="
for /f "tokens=1* delims==" %%K in (%TMPDIR%\identity.txt) do (
    set "K=%%K"
    set "V=%%L"
    if not "!K!"=="" (
        call :jsonEscape "!V!" V_ESC
        if not defined SEP (
            >> "%OUT%" echo     "!K!": "!V_ESC!"
            set "SEP=,"
        ) else (
            >> "%OUT%" echo     ,"!K!": "!V_ESC!"
        )
    )
)
>> "%OUT%" echo   },

rem assoc: lines look like .ext=ProgID
>> "%OUT%" echo   "assoc": {
set "SEP="
for /f "tokens=1* delims==" %%K in (%TMPDIR%\assoc.txt) do (
    set "K=%%K"
    set "V=%%L"
    if not "!K!"=="" (
        call :jsonEscape "!K!" K_ESC
        call :jsonEscape "!V!" V_ESC
        if not defined SEP (
            >> "%OUT%" echo     "!K_ESC!": "!V_ESC!"
            set "SEP=,"
        ) else (
            >> "%OUT%" echo     ,"!K_ESC!": "!V_ESC!"
        )
    )
)
>> "%OUT%" echo   },

rem ftype: lines look like ProgID=command-template
>> "%OUT%" echo   "ftype": {
set "SEP="
for /f "tokens=1* delims==" %%K in (%TMPDIR%\ftype.txt) do (
    set "K=%%K"
    set "V=%%L"
    if not "!K!"=="" (
        call :jsonEscape "!K!" K_ESC
        call :jsonEscape "!V!" V_ESC
        if not defined SEP (
            >> "%OUT%" echo     "!K_ESC!": "!V_ESC!"
            set "SEP=,"
        ) else (
            >> "%OUT%" echo     ,"!K_ESC!": "!V_ESC!"
        )
    )
)
>> "%OUT%" echo   },

rem env: SET output, lines look like NAME=VALUE
>> "%OUT%" echo   "env": {
set "SEP="
for /f "tokens=1* delims==" %%K in (%TMPDIR%\set.txt) do (
    set "K=%%K"
    set "V=%%L"
    if not "!K!"=="" (
        call :jsonEscape "!K!" K_ESC
        call :jsonEscape "!V!" V_ESC
        if not defined SEP (
            >> "%OUT%" echo     "!K_ESC!": "!V_ESC!"
            set "SEP=,"
        ) else (
            >> "%OUT%" echo     ,"!K_ESC!": "!V_ESC!"
        )
    )
)
>> "%OUT%" echo   },

rem where: NAME=PATH (PATH may be empty)
>> "%OUT%" echo   "where": {
set "SEP="
for /f "tokens=1* delims==" %%K in (%TMPDIR%\where.txt) do (
    set "K=%%K"
    set "V=%%L"
    if not "!K!"=="" (
        call :jsonEscape "!K!" K_ESC
        call :jsonEscape "!V!" V_ESC
        if not defined SEP (
            >> "%OUT%" echo     "!K_ESC!": "!V_ESC!"
            set "SEP=,"
        ) else (
            >> "%OUT%" echo     ,"!K_ESC!": "!V_ESC!"
        )
    )
)
>> "%OUT%" echo   }
>> "%OUT%" echo }

rd /s /q "%TMPDIR%" 2>nul
echo.
echo [+] Done. Wrote: %OUT%
echo.
echo Next: copy this file to
echo   rust/crates/harrington-core/data/^<winver^>.json
echo where ^<winver^> is one of: win7, win10, win11
exit /b 0


rem ============================================================================
rem  :jsonEscape <raw-string> <out-var-name>
rem  Escapes backslashes and double-quotes for JSON. cmd.exe-safe: we work
rem  through delayed expansion to avoid early percent-substitution.
rem ============================================================================
:jsonEscape
set "JE_IN=%~1"
rem escape backslash first, then double-quote
set "JE_IN=!JE_IN:\=\\!"
set "JE_IN=!JE_IN:"=\"!"
set "%~2=!JE_IN!"
exit /b 0
