@echo off
setlocal ENABLEDELAYEDEXPANSION

REM Ensure Node is available
where node >NUL 2>&1
IF ERRORLEVEL 1 (
  echo Node.js is required. Install from https://nodejs.org/
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

REM Install deps if needed
if not exist "node_modules" (
  echo Installing dependencies...
  call npm install
)

REM Start server in a new window
start "AuraSync Admin Server" cmd /c "node backend/server.js"

REM Give server a moment to start
timeout /t 2 >NUL

REM Open admin UI
start "" http://localhost:3000/admin/

echo Admin is opening in your browser. Close this window if done.
