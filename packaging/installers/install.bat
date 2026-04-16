@echo off
REM Cullis Connector — Windows installer.
REM
REM Double-click install.bat from the extracted zip. It copies the binary
REM to %USERPROFILE%\.cullis\bin, registers a Scheduled Task so the
REM dashboard starts on login, and opens the onboarding page in your
REM default browser.
REM
REM To uninstall later:
REM     %USERPROFILE%\.cullis\bin\cullis-connector.exe install-autostart --uninstall
REM     del %USERPROFILE%\.cullis\bin\cullis-connector.exe

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

set BIN_DIR=%USERPROFILE%\.cullis\bin
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

set SOURCE=
for %%F in (cullis-connector-windows-*.exe) do (
    set SOURCE=%%F
    goto :found
)
:found

if "!SOURCE!"=="" (
    echo error: could not find a Windows binary next to install.bat
    echo        expected a cullis-connector-windows-*.exe file
    pause
    exit /b 1
)

echo Installing !SOURCE! to %BIN_DIR%\cullis-connector.exe
copy /Y "!SOURCE!" "%BIN_DIR%\cullis-connector.exe" >nul

echo Registering autostart...
"%BIN_DIR%\cullis-connector.exe" install-autostart

echo Starting the dashboard...
start "" "%BIN_DIR%\cullis-connector.exe" dashboard
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:7777"

echo.
echo ==========================================================
echo  Cullis Connector is running.
echo  Dashboard: http://127.0.0.1:7777
echo.
echo  The binary lives at %BIN_DIR%\cullis-connector.exe
echo ==========================================================
echo.
pause
