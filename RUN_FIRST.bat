@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
)
call .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python scripts\generate_demo_data.py
python scripts\train_demo.py
if errorlevel 1 (
 echo [ERROR] Demo training failed.
 pause
 exit /b 1
)
echo.
echo ============================================
echo Demo setup complete.
echo Next: double-click RUN_APP.bat
echo ============================================
pause
