@echo off
setlocal
set PYTHONUTF8=1
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 netguard_checkup.py --open
) else (
  python netguard_checkup.py --open
)
if errorlevel 1 (
  echo Confira se o Python 3.12 ou superior esta instalado e leia docs\CHECKUP_LOCAL.md.
  pause
)
endlocal
