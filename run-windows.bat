@echo off
REM One-command launcher for Windows: sets up the venv, applies migrations,
REM builds the console if needed, and starts the API on http://127.0.0.1:8010
REM (which also serves the built web console). See README.md for details.
REM
REM Usage (double-click, or from cmd.exe):
REM   run-windows.bat            start (setup is idempotent, safe to re-run)
REM   run-windows.bat --seed     force re-seed the demo dataset
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "SEED=0"
if /i "%~1"=="--seed" set "SEED=1"

echo [1/6] Checking Python...
set "PY_CMD="
py -3 --version >nul 2>&1
if not errorlevel 1 (
    set "PY_CMD=py -3"
) else (
    python --version >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python"
)
if not defined PY_CMD (
    echo Python 3.11+ not found. Install it from https://www.python.org/downloads/ ^(check "Add python.exe to PATH"^) and re-run this script.
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
    if not errorlevel 1 (
        pushd web
        call npm install
        if errorlevel 1 (popd & goto :fail)
        call npm run build
        if errorlevel 1 (popd & goto :fail)
        popd
    ) else (
        echo npm not found and web\dist is missing -- the API will run without the console UI.
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
