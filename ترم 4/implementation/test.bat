@echo off
setlocal EnableExtensions DisableDelayedExpansion

cd /d "%~dp0"
if not "%~1"=="" (
    echo test.bat: run test.bat without command-line parameters; it will prompt for a run label. 1>&2
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

where link.exe >nul 2>nul
if errorlevel 1 call :activate_msvc
where link.exe >nul 2>nul
if errorlevel 1 (
    echo test.bat: the MSVC linker is unavailable. 1>&2
    echo Install Visual Studio Build Tools with the "Desktop development with C++" workload, then rerun test.bat. 1>&2
    exit /b 1
)

for /f %%I in ('powershell.exe -NoProfile -Command "Get-Date -AsUTC -Format yyyyMMddTHHmmssZ"') do set "UTC_STAMP=%%I"
if not defined UTC_STAMP set "UTC_STAMP=%RANDOM%-%RANDOM%"
set "DEFAULT_RUN=clear-64-windows-%UTC_STAMP%"

echo.
echo === Clear 64-Member MLS Report for Windows ===
set /p "RUN_NAME=Public run label [%DEFAULT_RUN%]: "
if not defined RUN_NAME set "RUN_NAME=%DEFAULT_RUN%"
set "CLEAR_RUN_NAME=%RUN_NAME%"
powershell.exe -NoProfile -Command "if ($env:CLEAR_RUN_NAME -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$') { exit 1 }"
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

echo Members: 64
echo Real baseline operations: Update, Add, Remove
echo Adaptive run: seeded-random Updates through transition and one maturity evaluation
set /p "CONFIRM=Proceed? [y/N]: "
if /I not "%CONFIRM%"=="y" if /I not "%CONFIRM%"=="yes" (
    echo Cancelled. No protocol command was run.
    exit /b 0
)

echo.
echo Running clear 64-member experiment...
set "CARGO_BUILD_JOBS=1"
cargo run --quiet -p report --bin run_clear_64 --release --locked --offline -- --seed 42 --output "output/%RUN_NAME%" --report "report/%RUN_NAME%"
if errorlevel 1 (
    echo test.bat: the experiment failed. 1>&2
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
echo TreeCover retirement is formula-authorized/modelled; the live fork retirement Commit remains unsupported.
exit /b 0

:activate_msvc
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" exit /b 0
set "VS_INSTALL="
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL exit /b 0
if exist "%VS_INSTALL%\Common7\Tools\VsDevCmd.bat" call "%VS_INSTALL%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
exit /b 0
