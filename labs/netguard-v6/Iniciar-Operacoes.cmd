@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 netguard_operations.py serve
) else (
  python netguard_operations.py serve
)
pause
