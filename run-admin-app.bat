@echo off
setlocal ENABLEDELAYEDEXPANSION

REM Ensure Node & npm are available
where node >NUL 2>&1
IF ERRORLEVEL 1 (
  echo Node.js is required. Install from https://nodejs.org/
  pause
  exit /b 1
)
where npm >NUL 2>&1
IF ERRORLEVEL 1 (
  echo npm is required. Install Node.js which includes npm.
  pause
  exit /b 1
)

REM Ensure .env has PORT; app will generate a runtime ADMIN_SECRET automatically
if not exist ".env" (
  echo PORT=3000> .env
)

REM Install deps (including electron) if needed
if not exist "node_modules" (
  echo Installing dependencies (this can take a minute)...
  call npm install
)

REM Run the Electron admin app
start "AuraSync Admin" cmd /c "npx electron ./admin-app/main.js"

endlocal
