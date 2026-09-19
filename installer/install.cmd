@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if errorlevel 1 (
  echo.
  echo 安装失败。按任意键关闭窗口。
  pause >nul
)
exit /b %errorlevel%
