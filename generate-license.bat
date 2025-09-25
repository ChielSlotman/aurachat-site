@echo off
setlocal

REM Launch the Python GUI to generate a license code.
REM Tries pythonw.exe, then python.exe, then the "py" launcher.

set SCRIPT=%~dp0generate-license.pyw

REM Prefer pythonw (no console window)
where pythonw >NUL 2>&1
if %ERRORLEVEL%==0 (
  start "AuraSync License Generator" pythonw "%SCRIPT%"
  exit /b 0
)

REM Fallback to python
where python >NUL 2>&1
if %ERRORLEVEL%==0 (
  start "AuraSync License Generator" python "%SCRIPT%"
  exit /b 0
)

REM Fallback to py launcher
where py >NUL 2>&1
if %ERRORLEVEL%==0 (
  start "AuraSync License Generator" py "%SCRIPT%"
  exit /b 0
)

echo Could not find Python. Please install Python 3 from https://www.python.org/downloads/ and try again.
pause
exit /b 1
