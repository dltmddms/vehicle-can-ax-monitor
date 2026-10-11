@echo off
chcp 65001 >nul
cd /d "%~dp0"
call .venv\Scripts\activate
python scripts\train_real_hcrl.py --nrows 400000
pause
