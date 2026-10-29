@echo off
rem ============================================================
rem  notifier.bat - Launcher do ticket_notifier (sessao do usuario)
rem  Uso: notifier.bat               (daemon de avisos)
rem       notifier.bat --new-ticket  (abre o formulario de chamado)
rem       notifier.bat --list        (lista chamados desta maquina)
rem ============================================================
setlocal EnableExtensions

set "ROOT=%~dp0"
set "PYTHONW=pythonw"
if exist "%ROOT%venv\Scripts\pythonw.exe" set "PYTHONW=%ROOT%venv\Scripts\pythonw.exe"
set "CONFIG=%PROGRAMDATA%\PyEndpointRMM\agent.json"

rem --list imprime no console, entao usa python.exe em vez de pythonw.exe.
if "%~1"=="--list" goto :console

start "" "%PYTHONW%" "%ROOT%ticket_notifier.py" --config "%CONFIG%" %*
exit /b 0

:console
set "PYTHON=python"
if exist "%ROOT%venv\Scripts\python.exe" set "PYTHON=%ROOT%venv\Scripts\python.exe"
"%PYTHON%" "%ROOT%ticket_notifier.py" --config "%CONFIG%" %*
exit /b %ERRORLEVEL%
