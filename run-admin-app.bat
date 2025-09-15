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

REM Create .env if missing and prompt for ADMIN_SECRET once
if not exist ".env" (
  echo Creating .env
  echo PORT=3000> .env
  set /p ADMIN_SECRET_INPUT=Enter ADMIN_SECRET to protect admin routes: 
  echo ADMIN_SECRET=!ADMIN_SECRET_INPUT!>> .env
) else (
  for /f "tokens=1,2 delims==" %%A in (.env) do (
    if /I "%%A"=="ADMIN_SECRET" set FOUND_SECRET=1
  )
  if not defined FOUND_SECRET (
    set /p ADMIN_SECRET_INPUT=Enter ADMIN_SECRET to protect admin routes: 
    echo ADMIN_SECRET=!ADMIN_SECRET_INPUT!>> .env
  )
)

REM Install deps (including electron) if needed
if not exist "node_modules" (
  echo Installing dependencies (this can take a minute)...
  call npm install
)

REM Run the Electron admin app
call npx electron ./admin-app/main.js

endlocal
