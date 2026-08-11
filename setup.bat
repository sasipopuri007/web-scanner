@echo off
title Web Vulnerability Scanner - Setup
cd /d "%~dp0"

echo ==========================================
echo   WEB VULNERABILITY SCANNER - SETUP
echo ==========================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python is not installed.
    echo Install Python 3.12 or newer and try again.
    pause
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo ERROR: Node.js is not installed.
    echo Install Node.js and try again.
    pause
    exit /b 1
)

echo Creating backend environment...
if not exist "backend\.venv\Scripts\python.exe" (
    python -m venv "backend\.venv"
)

echo Installing backend dependencies...
"backend\.venv\Scripts\python.exe" -m pip install fastapi uvicorn requests beautifulsoup4 sqlalchemy

echo.
echo Creating scanner environment...
if not exist "scanner\.venv\Scripts\python.exe" (
    python -m venv "scanner\.venv"
)

echo Installing scanner dependencies...
"scanner\.venv\Scripts\python.exe" -m pip install requests beautifulsoup4

echo.
echo Installing frontend dependencies...
cd frontend
call npm install
cd ..

echo.
echo ==========================================
echo          SETUP COMPLETE
echo ==========================================
echo.
echo Now double-click START.BAT to run the scanner.
echo.
pause
