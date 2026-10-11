@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run RUN_FIRST.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" scripts\compare_window_sizes.py
echo.
echo Result saved to experiments\window_size_results.csv
pause
