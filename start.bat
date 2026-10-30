@echo off
title FaceVault - Biometric Face Encryption
setlocal
cd /d "%~dp0"

where python >nul 2>nul && (set PY=python) || (set PY=py)
where npm >nul 2>nul || (
  echo Node.js is not installed. Install it from https://nodejs.org ^(version 20.19+ or 22.12+^), then run this again.
  pause & exit /b 1
)

echo [1/4] Installing Python dependencies...
%PY% -m pip install -q -r backend\requirements.txt || goto :fail

echo [2/4] Installing frontend dependencies...
pushd frontend
if not exist node_modules ( call npm install || goto :failpop )

echo [3/4] Building the TypeScript + Tailwind frontend...
call npm run build || goto :failpop
popd

echo [4/4] Starting FaceVault on http://localhost:5000 ...
cd backend
%PY% app.py %*
pause
exit /b 0

:failpop
popd
:fail
echo.
echo Setup failed. Check the messages above.
pause
exit /b 1
