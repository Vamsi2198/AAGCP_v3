@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0run_with_phoenix.ps1" %*
endlocal
