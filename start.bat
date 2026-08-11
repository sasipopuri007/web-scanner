@echo off
title Web Vulnerability Scanner
cd /d "%~dp0"

echo ==========================================
echo      WEB VULNERABILITY SCANNER
echo ==========================================
echo.

if not exist "backend\.venv\Scripts\python.exe" (
    echo Setup has not been completed.
    echo.
    echo Please double-click setup.bat first.
    pause
    exit /b 1
)

if not exist "frontend\node_modules" (
    echo Frontend dependencies are missing.
    echo Please double-click setup.bat first.
    pause
    exit /b 1
)

echo Starting backend...

start "Vulnerability Scanner Backend" cmd /k "cd /d "%~dp0backend" && .venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000"

timeout /t 5 /nobreak >nul

echo Starting frontend...

start "Vulnerability Scanner Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

timeout /t 7 /nobreak >nul

echo Opening scanner...

start http://localhost:5173

echo.
echo ==========================================
echo       SCANNER STARTED SUCCESSFULLY
echo ==========================================
echo.
echo Dashboard:
echo http://localhost:5173
echo.
echo Keep the backend and frontend windows open.
echo.
pause
