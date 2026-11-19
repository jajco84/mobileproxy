@echo off
rem MobileProxy launcher for Windows. Arguments are passed through, e.g. run.bat --proxy-port 8888
setlocal
cd /d "%~dp0"
where uv >nul 2>nul
if %ERRORLEVEL%==0 (
  uv run mobileproxy %*
  exit /b %ERRORLEVEL%
)
if not exist .venv\Scripts\mobileproxy.exe (
  py -3.12 -m venv .venv 2>nul || python -m venv .venv
  .venv\Scripts\python -m pip install -q --upgrade pip
  .venv\Scripts\python -m pip install -q -e .
)
.venv\Scripts\mobileproxy.exe %*
