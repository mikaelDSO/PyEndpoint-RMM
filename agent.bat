@echo off
rem ============================================================
rem  agent.bat - Launcher do agente PyEndpoint-RMM (Windows)
rem  - Usa o Python do venv do projeto (se existir) ou o do PATH
rem  - Reinicia o agente se ele cair (exceto codigos 0 e 2)
rem  - Registra eventos em %PROGRAMDATA%\PyEndpointRMM\logs
rem  Uso: agent.bat [caminho\para\agent.json]
rem ============================================================
setlocal EnableExtensions

set "ROOT=%~dp0"
set "PYTHON=python"
if exist "%ROOT%venv\Scripts\python.exe" set "PYTHON=%ROOT%venv\Scripts\python.exe"

set "DATA=%PROGRAMDATA%\PyEndpointRMM"
if not exist "%DATA%\logs" mkdir "%DATA%\logs" >nul 2>&1
set "LAUNCHER_LOG=%DATA%\logs\agent_launcher.log"

set "CONFIG=%DATA%\agent.json"
if not "%~1"=="" set "CONFIG=%~1"

:loop
call :log "Iniciando agent.py"
"%PYTHON%" "%ROOT%agent.py" --config "%CONFIG%"
set "RC=%ERRORLEVEL%"
call :log "agent.py encerrou com codigo %RC%"

if "%RC%"=="0" goto :end
if "%RC%"=="2" goto :config_error

rem Falha inesperada: aguarda ~15 s (ping evita o erro do TIMEOUT sem console) e reinicia.
ping -n 16 127.0.0.1 >nul
goto :loop

:config_error
call :log "Erro de configuracao: nao sera reiniciado. Corrija %CONFIG%"
exit /b 2

:end
exit /b 0

:log
>>"%LAUNCHER_LOG%" echo [%date% %time%] %~1
exit /b 0
