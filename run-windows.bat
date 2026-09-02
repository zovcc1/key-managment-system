@echo off
REM One-command launcher for Windows: sets up the venv, applies migrations,
REM builds the console if needed, and starts the API on http://127.0.0.1:8010
REM (which also serves the built web console). See README.md for details.
REM
REM Missing prerequisites (Python, Node.js/npm) are installed automatically
REM via winget when possible.
REM
REM Usage (double-click, or from cmd.exe):
REM   run-windows.bat            start (setup is idempotent, safe to re-run)
REM   run-windows.bat --seed     force re-seed the demo dataset
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "SEED=0"
if /i "%~1"=="--seed" set "SEED=1"

echo [1/6] Checking Python...
call :find_python
if not defined PY_CMD (
    call :ensure_winget
    if errorlevel 1 (
        echo Python 3.11+ not found, and winget is unavailable to install it.
        echo Install Python from https://www.python.org/downloads/ ^(check "Add python.exe to PATH"^) and re-run this script.
        goto :fail
    )
    echo Python not found. Installing Python via winget...
    winget install -e --id Python.Python.3.12 --source winget --silent --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo Failed to install Python via winget. Install manually from https://www.python.org/downloads/ and re-run.
        goto :fail
    )
    call :refresh_path
    call :find_python
)
if not defined PY_CMD (
    echo Python was installed but is not on PATH yet. Close this window, open a new terminal, and re-run run-windows.bat.
    goto :fail
)
for /f "delims=" %%v in ('%PY_CMD% -c "import sys; print(1 if sys.version_info >= (3, 11) else 0)"') do set "PY_OK=%%v"
if not "%PY_OK%"=="1" (
    echo Python 3.11+ required.
    %PY_CMD% --version
    goto :fail
)

echo [2/6] Setting up virtual environment ^(.venv^)...
if not exist ".venv\Scripts\python.exe" (
    %PY_CMD% -m venv .venv
    if errorlevel 1 goto :fail
)
".venv\Scripts\pip.exe" install -q --upgrade pip
if errorlevel 1 goto :fail
".venv\Scripts\pip.exe" install -q -e ".[dev]"
if errorlevel 1 goto :fail

echo [3/6] Restoring secret file read-only attribute ^(git does not preserve it^)...
if exist "data\root.passphrase" attrib +R "data\root.passphrase"
if exist "data\root.salt" attrib +R "data\root.salt"

echo [4/6] Applying database migrations...
set "DB_EXISTED=1"
if not exist "keyring.db" set "DB_EXISTED=0"
".venv\Scripts\alembic.exe" upgrade head
if errorlevel 1 goto :fail

if "%SEED%"=="1" goto :do_seed
if "%DB_EXISTED%"=="0" goto :do_seed
echo [5/6] Database already present, skipping seed ^(use --seed to force^).
goto :after_seed
:do_seed
echo [5/6] Seeding demo dataset...
".venv\Scripts\python.exe" -m keyring.seed
if errorlevel 1 goto :fail
if exist "data\root.passphrase" attrib +R "data\root.passphrase"
if exist "data\root.salt" attrib +R "data\root.salt"
:after_seed

echo [6/6] Preparing console ^(web\dist^)...
if not exist "web\dist\index.html" (
    where npm >nul 2>&1
    if errorlevel 1 (
        call :ensure_winget
        if not errorlevel 1 (
            echo npm not found. Installing Node.js LTS via winget...
            winget install -e --id OpenJS.NodeJS.LTS --source winget --silent --accept-source-agreements --accept-package-agreements
            call :refresh_path
        )
    )
    where npm >nul 2>&1
    if not errorlevel 1 (
        pushd web
        call npm install
        if errorlevel 1 (popd & goto :fail)
        call npm run build
        if errorlevel 1 (popd & goto :fail)
        popd
    ) else (
        echo npm/Node.js not found and could not be installed automatically -- the API will run without the console UI.
        echo Install it from https://nodejs.org/ and re-run this script to build the console.
    )
)

echo.
echo Demo API keys ^(X-Api-Key header on POST /api/session^):
echo   Alice ^(key-admin^): demo-key-admin-alice-9f2a
echo   Bob   ^(key-admin^): demo-key-admin-bob-7c31
echo   Carol ^(auditor^):   demo-auditor-carol-1e88
echo   Dan   ^(operator^):  demo-operator-dan-4b60
echo.
echo Starting API + console at http://127.0.0.1:8010 ...
start "" http://127.0.0.1:8010
".venv\Scripts\uvicorn.exe" keyring.main:app --port 8010
goto :eof

:fail
echo.
echo Setup failed. See the message above.
pause
exit /b 1

REM ------------------------------------------------------------------
REM Subroutines
REM ------------------------------------------------------------------

:find_python
REM Sets PY_CMD to a usable "python 3.11+" launcher command, or leaves it
REM undefined if none is found on PATH.
set "PY_CMD="
py -3 --version >nul 2>&1
if not errorlevel 1 (
    set "PY_CMD=py -3"
    exit /b 0
)
python --version >nul 2>&1
if not errorlevel 1 (
    set "PY_CMD=python"
)
exit /b 0

:ensure_winget
REM Returns errorlevel 0 if winget is available, 1 otherwise.
where winget >nul 2>&1
if errorlevel 1 (
    echo winget was not found. It ships with Windows 10 2004+/Windows 11 via the
    echo "App Installer" package from the Microsoft Store. Install it there, or
    echo install prerequisites manually, then re-run this script.
    exit /b 1
)
exit /b 0

:refresh_path
REM Rebuilds PATH for this session from the registry so binaries installed by
REM winget (Python, Node.js) are found without opening a new terminal.
set "SYS_PATH="
set "USER_PATH="
for /f "usebackq tokens=2,*" %%A in (`reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul`) do set "SYS_PATH=%%B"
for /f "usebackq tokens=2,*" %%A in (`reg query "HKCU\Environment" /v PATH 2^>nul`) do set "USER_PATH=%%B"
if defined SYS_PATH if defined USER_PATH (
    set "PATH=%SYS_PATH%;%USER_PATH%"
) else if defined SYS_PATH (
    set "PATH=%SYS_PATH%"
)
exit /b 0
