@echo off
setlocal ENABLEDELAYEDEXPANSION

REM Prefer pythonw.exe to avoid console window
set PY=
for %%P in (pythonw.exe,python.exe,py.exe) do (
  where %%P >NUL 2>&1 && (set PY=%%P & goto :found)
)
:found
if not defined PY (
  echo Python is required to run the admin launcher. Install from https://www.python.org/
  pause
  exit /b 1
)

REM Ensure Node/npm are present (the Python app will also check)
where node >NUL 2>&1 || echo Warning: Node.js not found in PATH.
where npm >NUL 2>&1 || echo Warning: npm not found in PATH.

start "AuraSync Admin" %PY% "%~dp0run-admin.pyw"
echo AuraSync Admin window should open. If not, check antivirus or PATH settings.
exit /b 0
