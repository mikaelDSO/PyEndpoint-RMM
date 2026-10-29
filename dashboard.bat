@echo off
rem ============================================================
rem  dashboard.bat - Atalho para o painel ADM (maquina do administrador)
rem  Uso: dashboard.bat shell
rem       dashboard.bat agents
rem       dashboard.bat reboot --target PC-01 --delay 120
rem ============================================================
setlocal EnableExtensions
set "ROOT=%~dp0"
set "PYTHON=python"
if exist "%ROOT%venv\Scripts\python.exe" set "PYTHON=%ROOT%venv\Scripts\python.exe"

if "%~1"=="" goto :interactive
"%PYTHON%" "%ROOT%dashboard.py" %*
exit /b %ERRORLEVEL%

:interactive
"%PYTHON%" "%ROOT%dashboard.py" shell
exit /b %ERRORLEVEL%
