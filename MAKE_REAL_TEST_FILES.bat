@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run RUN_FIRST.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" scripts\make_real_test_files.py
echo.
echo Real HCRL sample files were created in data\test_samples
pause
