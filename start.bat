@echo off
goto :main
REM ===========================================================================================
REM  FaceVault - one-command start (Windows)
REM
REM  QUICK START
REM    PowerShell :  cd "C:\Users\Asus\OneDrive\Desktop\CNS\biometric-face-encryption"; .\start.bat
REM    cmd        :  cd /d "C:\Users\Asus\OneDrive\Desktop\CNS\biometric-face-encryption" && start.bat
REM    Options    :  start.bat --https        serve on https://localhost:5443 (self-signed certificate)
REM                  start.bat --port 5050    use another port
REM                  start.bat --no-browser   don't open the browser automatically
REM
REM  WORKS OFFLINE: after the first successful run (which downloads the packages), this script only
REM  installs packages that are missing and skips the internet otherwise. Fonts, face models and all
REM  libraries are served locally. Offline needs DATABASE_URL to be empty in .env (local SQLite).
REM
REM  CREDENTIALS: .env in this folder (BFE_SUPER_ADMIN, BFE_ADMIN_PASSWORD). Never commit .env.
REM
REM ===========================================================================================
REM  MANUAL COMMANDS (PowerShell), if this script fails. Run them from the project folder.
REM ===========================================================================================
REM
REM  1) One-time install (needs internet)
REM       cd backend;  python -m pip install -r requirements.txt;  cd ..
REM       cd frontend; npm install;  cd ..
REM
REM  2) Build the frontend (works offline)
REM       cd frontend; npm run build;  cd ..
REM
REM  3) Run (works offline)
REM       cd backend;  python app.py
REM       then open http://localhost:5000      (Ctrl+C in that window stops the server)
REM
REM ===========================================================================================
REM  IF SOMETHING GOES WRONG
REM ===========================================================================================
REM   Frontend build fails        Skip step 2. "python app.py" serves the last good build
REM                                (frontend\dist), as long as it exists.
REM   "python" not recognized     Use "py" instead:  py app.py
REM   Port 5000 already in use    FaceVault may already be running: open http://localhost:5000.
REM                                Or use another port:  python app.py --port 5050
REM                                Or free the port:     netstat -ano | findstr :5000
REM                                                      taskkill /PID <number-from-last-column> /F
REM   "Cannot unlock keyring"     BFE_MASTER_PASSPHRASE in .env was changed. Put the old value back.
REM                                To really change it, run:  cd backend; python change_passphrase.py
REM   Forgot the password         Set BFE_ADMIN_PASSWORD in .env and restart
REM                                (or: cd backend; python reset_admin.py)
REM   Camera not working          Use http://localhost:5000 (not an IP address), allow the camera
REM                                in the browser, close other apps using it, or use "Upload photo".
REM   "Face models failed"        cd frontend; npm run models; npm run build
REM   Online site is down         Run locally with this script. Online backend health check:
REM                                https://biometric-face-image-encryption.onrender.com/api/health
REM                                (the free Render plan may take up to a minute to wake up)
REM   Developer mode              cd frontend; npm run dev:full   then open http://localhost:5173
REM   Run the security tests      cd backend; python -m unittest discover tests
REM   Start completely fresh      Delete the folder backend\instance
REM                                WARNING: this permanently deletes all locally enrolled faces.
REM ===========================================================================================

:main
title FaceVault - Biometric Face Encryption
setlocal
cd /d "%~dp0"

where python >nul 2>nul && (set PY=python) || (set PY=py)

echo [1/4] Checking Python packages...
%PY% -c "import flask, cryptography, jwt" >nul 2>nul
if errorlevel 1 (
  echo        Installing Python packages ^(needs internet^)...
  %PY% -m pip install -q -r backend\requirements.txt
  if errorlevel 1 goto :fail
) else (
  echo        Already installed.
)

echo [2/4] Checking frontend packages...
where npm >nul 2>nul
if errorlevel 1 (
  if exist frontend\dist\index.html (
    echo        Node.js not found: using the existing frontend build.
    goto :run
  )
  echo Node.js is not installed. Install it from https://nodejs.org ^(version 20.19+ or 22.12+^).
  goto :fail
)
pushd frontend
if not exist node_modules (
  echo        Installing npm packages ^(needs internet^)...
  call npm install
  if errorlevel 1 (
    popd
    goto :fail
  )
) else (
  echo        Already installed.
)

echo [3/4] Building the TypeScript + Tailwind frontend...
call npm run build
if errorlevel 1 (
  popd
  if exist frontend\dist\index.html (
    echo        Build failed: using the previous build instead.
    goto :run
  )
  goto :fail
)
popd

:run
echo [4/4] Starting FaceVault on http://localhost:5000 ...
cd backend
%PY% app.py %*
pause
exit /b 0

:fail
echo.
echo Setup failed. Check the messages above, or see the MANUAL COMMANDS at the top of start.bat.
pause
exit /b 1
