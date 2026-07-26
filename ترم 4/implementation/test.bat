@echo off
setlocal EnableExtensions DisableDelayedExpansion

cd /d "%~dp0"
if not "%~1"=="" (
    echo test.bat: run test.bat without command-line parameters; it will prompt for the mode and inputs. 1>&2
    exit /b 2
)

if not exist Cargo.lock (
    echo test.bat: Cargo.lock was not found; run this script from the repository root. 1>&2
    exit /b 1
)
if not exist rust-toolchain.toml (
    echo test.bat: rust-toolchain.toml was not found. 1>&2
    exit /b 1
)

where cargo.exe >nul 2>nul
if errorlevel 1 (
    echo test.bat: cargo.exe is not available in PATH. Install Rustup and the repository-pinned toolchain. 1>&2
    exit /b 1
)

set "CARGO_TOOLCHAIN_ARG="
set "WINDOWS_RUST_MODE=MSVC"
where link.exe >nul 2>nul
if errorlevel 1 call :activate_msvc
where link.exe >nul 2>nul
if errorlevel 1 (
    set "GNU_RUSTUP_HOME=E:\rustup-gnu"
    set "GNU_TOOLCHAIN=1.93.1-x86_64-pc-windows-gnu"
    if not exist "E:\rustup-gnu\toolchains\1.93.1-x86_64-pc-windows-gnu\bin\rustc.exe" (
        echo test.bat: neither the MSVC linker nor the E:\rustup-gnu toolchain is available. 1>&2
        echo Install the GNU toolchain once with: 1>&2
        echo   set RUSTUP_HOME=E:\rustup-gnu 1>&2
        echo   rustup toolchain install 1.93.1-x86_64-pc-windows-gnu --profile minimal 1>&2
        exit /b 1
    )
    set "RUSTUP_HOME=E:\rustup-gnu"
    set "CARGO_TARGET_DIR=E:\cargo-target\master-hybrid-mls"
    set "CARGO_TOOLCHAIN_ARG=+1.93.1-x86_64-pc-windows-gnu"
    set "GNU_TOOLCHAIN_ROOT=E:\rustup-gnu\toolchains\1.93.1-x86_64-pc-windows-gnu"
    set "PATH=%GNU_TOOLCHAIN_ROOT%\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained;%PATH%"
    set "WINDOWS_RUST_MODE=GNU/MinGW from E:"
)

echo.
echo === Adaptive Hybrid MLS Interactive Demo ===
echo Windows Rust toolchain: %WINDOWS_RUST_MODE%
echo Choose a mode:
echo   3^) Clear 64-member real-protocol report
echo   4^) Real fork delivery-health report (2 -^> 4, random Add/Update/Remove, authenticated retirement)
set /p "MODE=Selection [3/4]: "
if "%MODE%"=="3" goto clear_report
if "%MODE%"=="4" goto delivery_health
echo test.bat: select 3 or 4 from the displayed mode menu. 1>&2
exit /b 2

:delivery_health
set "INITIAL_ARITY=2"
set "TARGET_ARITY=4"
set /p "INITIAL_MEMBERS=Initial MLS client number [64..256]: "
set "INITIAL_MEMBERS_ENV=%INITIAL_MEMBERS%"
powershell.exe -NoProfile -Command "$value = $env:INITIAL_MEMBERS_ENV; if ($value -notmatch '^[0-9]+$' -or [int]$value -lt 64 -or [int]$value -gt 256) { exit 1 }"
if errorlevel 1 (
    echo test.bat: initial MLS client number must be an integer between 64 and 256. 1>&2
    exit /b 2
)

for /f %%I in ('powershell.exe -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')"') do set "UTC_STAMP=%%I"
if not defined UTC_STAMP set "UTC_STAMP=%RANDOM%-%RANDOM%"
set "DEFAULT_RUN=professor-demo-%UTC_STAMP%"
set /p "RUN_NAME=Public run label [%DEFAULT_RUN%]: "
if not defined RUN_NAME set "RUN_NAME=%DEFAULT_RUN%"
set "RUN_NAME_ENV=%RUN_NAME%"
powershell.exe -NoProfile -Command "if ($env:RUN_NAME_ENV -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$') { exit 1 }"
if errorlevel 1 (
    echo test.bat: run name must contain only letters, digits, underscores, or hyphens. 1>&2
    exit /b 2
)

set "OUTPUT_DIR=output\%RUN_NAME%"
set "REPORT_DIR=report\%RUN_NAME%"
if exist "%OUTPUT_DIR%" (
    echo test.bat: output directory already exists: %OUTPUT_DIR% 1>&2
    exit /b 1
)
if exist "%REPORT_DIR%" (
    echo test.bat: report directory already exists: %REPORT_DIR% 1>&2
    exit /b 1
)

echo.
echo Selected mode: real fork delivery-health report
echo Output: %OUTPUT_DIR%\
echo Report: %REPORT_DIR%\
echo Arity: %INITIAL_ARITY% -^> %TARGET_ARITY%; initial clients: %INITIAL_MEMBERS%
echo Public random seed: 42; post-transition Commit limit: 128
echo Operations: random Add/Update/Remove before transition, then Update/Remove until retirement
echo Minimum trace: 5 binary observations including an Update probe before transition; 5 post-transition Commits before retirement
echo Healthy comparison setup: populate both binary and quaternary internal nodes; setup Commit bytes are excluded
set /p "CONFIRM=Proceed? [y/N]: "
if /I not "%CONFIRM%"=="y" if /I not "%CONFIRM%"=="yes" (
    echo Cancelled. No protocol command was run.
    exit /b 0
)

echo.
echo === Real Fork Delivery-Health Report ===
echo Running authenticated fork workload...
set "CARGO_BUILD_JOBS=1"
set "CARGO_TERM_COLOR=never"
cargo %CARGO_TOOLCHAIN_ARG% run --quiet -p report --bin simulate_delivery_health --release --locked --offline -- ^
    --initial-arity %INITIAL_ARITY% ^
    --target-arity %TARGET_ARITY% ^
    --initial-members %INITIAL_MEMBERS% ^
    --seed 42 ^
    --maximum-commits 128 ^
    --output "%OUTPUT_DIR%" ^
    --report "%REPORT_DIR%"
if errorlevel 1 (
    echo test.bat: the authenticated fork workload failed. 1>&2
    exit /b 1
)

if not exist "%OUTPUT_DIR%\summary.csv" (
    echo test.bat: summary.csv was not created. 1>&2
    exit /b 1
)
if not exist "%OUTPUT_DIR%\events.csv" (
    echo test.bat: events.csv was not created. 1>&2
    exit /b 1
)
if not exist "%REPORT_DIR%\report.md" (
    echo test.bat: report.md was not created. 1>&2
    exit /b 1
)

echo.
echo Generated:
echo   Summary: %OUTPUT_DIR%\summary.csv
echo   Events:  %OUTPUT_DIR%\events.csv
echo   Report:  %REPORT_DIR%\report.md
echo.
echo Scope: real authenticated fork Commit observations and atomic TreeCover retirement.
echo The report remains thesis-local experimental software; no production or interoperability claim is made.
exit /b 0

:clear_report
for /f %%I in ('powershell.exe -NoProfile -Command "(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')"') do set "UTC_STAMP=%%I"
if not defined UTC_STAMP set "UTC_STAMP=%RANDOM%-%RANDOM%"
set "DEFAULT_RUN=clear-64-windows-%UTC_STAMP%"
set /p "RUN_NAME=Public run label [%DEFAULT_RUN%]: "
if not defined RUN_NAME set "RUN_NAME=%DEFAULT_RUN%"
set "RUN_NAME_ENV=%RUN_NAME%"
powershell.exe -NoProfile -Command "if ($env:RUN_NAME_ENV -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$') { exit 1 }"
if errorlevel 1 (
    echo test.bat: run name must contain only letters, digits, underscores, or hyphens. 1>&2
    exit /b 2
)

set "OUTPUT_DIR=output\%RUN_NAME%"
set "REPORT_DIR=report\%RUN_NAME%"
if exist "%OUTPUT_DIR%" (
    echo test.bat: output directory already exists: %OUTPUT_DIR% 1>&2
    exit /b 1
)
if exist "%REPORT_DIR%" (
    echo test.bat: report directory already exists: %REPORT_DIR% 1>&2
    exit /b 1
)

echo.
echo === Clear 64-Member MLS Report for Windows ===
echo Members: 64
echo Real baseline operations: Update, Add, Remove
echo Adaptive operations: seeded-random Updates through transition and one maturity evaluation
set /p "CONFIRM=Proceed? [y/N]: "
if /I not "%CONFIRM%"=="y" if /I not "%CONFIRM%"=="yes" (
    echo Cancelled. No protocol command was run.
    exit /b 0
)

echo.
echo Running clear 64-member experiment...
set "CARGO_BUILD_JOBS=1"
set "CARGO_TERM_COLOR=never"
cargo %CARGO_TOOLCHAIN_ARG% run --quiet -p report --bin run_clear_64 --release --locked --offline -- ^
    --seed 42 ^
    --output "%OUTPUT_DIR%" ^
    --report "%REPORT_DIR%"
if errorlevel 1 (
    echo test.bat: the clear experiment failed. 1>&2
    exit /b 1
)

if not exist "%OUTPUT_DIR%\clear_report.csv" (
    echo test.bat: clear_report.csv was not created. 1>&2
    exit /b 1
)
if not exist "%OUTPUT_DIR%\clear_events.csv" (
    echo test.bat: clear_events.csv was not created. 1>&2
    exit /b 1
)
if not exist "%REPORT_DIR%\clear_report.md" (
    echo test.bat: clear_report.md was not created. 1>&2
    exit /b 1
)

echo.
echo === Complete ===
echo Summary: %OUTPUT_DIR%\clear_report.csv
echo Events:  %OUTPUT_DIR%\clear_events.csv
echo Report:  %REPORT_DIR%\clear_report.md
echo.
echo Scope: real local protocol execution; lifecycle timing is environment-dependent.
echo The experimental modes are thesis-local and non-interoperable with stock MLS.
exit /b 0

:activate_msvc
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" exit /b 0
set "VS_INSTALL="
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL exit /b 0
if exist "%VS_INSTALL%\Common7\Tools\VsDevCmd.bat" call "%VS_INSTALL%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
exit /b 0
