@echo off
rem ============================================================
rem  uninstall_windows.bat - Remove o agente e o notificador
rem  Execute como ADMINISTRADOR:
rem      scripts\uninstall_windows.bat [/purge]
rem  /purge tambem apaga configuracao, estado e logs em %ProgramData%.
rem ============================================================
setlocal EnableExtensions

set "DEST=%ProgramFiles%\PyEndpointRMM"
set "DATA=%ProgramData%\PyEndpointRMM"

net session >nul 2>&1
if errorlevel 1 goto :need_admin

echo Parando e removendo tarefas agendadas ...
schtasks /end /tn "PyEndpointRMM-Agent" >nul 2>&1
schtasks /end /tn "PyEndpointRMM-Notifier" >nul 2>&1
schtasks /delete /tn "PyEndpointRMM-Agent" /f >nul 2>&1
schtasks /delete /tn "PyEndpointRMM-Notifier" /f >nul 2>&1

echo Removendo "%DEST%" ...
if exist "%DEST%" rmdir /s /q "%DEST%"

if /I "%~1"=="/purge" goto :purge
echo Dados mantidos em "%DATA%" (use /purge para apagar).
goto :done

:purge
echo Apagando "%DATA%" ...
if exist "%DATA%" rmdir /s /q "%DATA%"
goto :done

:need_admin
echo [ERRO] Execute este script como Administrador.
exit /b 1

:done
echo Desinstalacao concluida.
exit /b 0
