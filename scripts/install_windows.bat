@echo off
rem ============================================================
rem  install_windows.bat - Instala o agente e o notificador (Windows)
rem  Execute como ADMINISTRADOR, a partir da pasta do repositorio:
rem      scripts\install_windows.bat [/silent]
rem
rem  O que faz:
rem   1. Copia o projeto para %ProgramFiles%\PyEndpointRMM
rem      (pasta que usuarios comuns NAO conseguem alterar)
rem   2. Cria um venv e instala as dependencias
rem   3. Cria %ProgramData%\PyEndpointRMM com ACL restrita
rem   4. Registra duas tarefas agendadas (agente e notificador)
rem  Nada e iniciado automaticamente: configure e inicie manualmente.
rem ============================================================
setlocal EnableExtensions

for %%I in ("%~dp0..") do set "SRC=%%~fI"
set "DEST=%ProgramFiles%\PyEndpointRMM"
set "DATA=%ProgramData%\PyEndpointRMM"
set "TASK_AGENT=PyEndpointRMM-Agent"
set "TASK_NOTIFIER=PyEndpointRMM-Notifier"

net session >nul 2>&1
if errorlevel 1 goto :need_admin

where python >nul 2>&1
if errorlevel 1 goto :need_python

echo [1/5] Copiando arquivos para "%DEST%" ...
robocopy "%SRC%" "%DEST%" /E /XD .git venv __pycache__ logs tests /XF *.pyc /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 goto :copy_failed

echo [2/5] Criando ambiente virtual e instalando dependencias ...
python -m venv "%DEST%\venv"
if errorlevel 1 goto :venv_failed
"%DEST%\venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r "%DEST%\requirements.txt"
if errorlevel 1 goto :pip_failed

echo [3/5] Preparando "%DATA%" com permissoes restritas ...
if not exist "%DATA%\logs" mkdir "%DATA%\logs"
if not exist "%DATA%\staging" mkdir "%DATA%\staging"
if not exist "%DATA%\spool\notify" mkdir "%DATA%\spool\notify"
rem SYSTEM e Administradores: controle total | Usuarios: somente leitura
icacls "%DATA%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" >nul
rem O notificador (sessao do usuario) precisa consumir os avisos da fila
icacls "%DATA%\spool\notify" /grant "*S-1-5-32-545:(OI)(CI)M" >nul
if not exist "%DATA%\agent.json" copy "%DEST%\config\agent.example.json" "%DATA%\agent.json" >nul

echo [4/5] Registrando tarefas agendadas ...
schtasks /create /tn "%TASK_AGENT%" /tr "\"%DEST%\agent.bat\"" /sc onstart /ru SYSTEM /rl HIGHEST /f >nul
if errorlevel 1 goto :task_failed
schtasks /create /tn "%TASK_NOTIFIER%" /tr "\"%DEST%\venv\Scripts\pythonw.exe\" \"%DEST%\ticket_notifier.py\" --config \"%DATA%\agent.json\"" /sc onlogon /ru "BUILTIN\Users" /rl LIMITED /f >nul
if errorlevel 1 echo [AVISO] Nao foi possivel registrar a tarefa do notificador. Use GPO ou atalho de inicializacao com notifier.bat.

echo [5/5] Concluido.
echo.
echo Proximos passos:
echo   1. Edite "%DATA%\agent.json" (shared_dir, allowed_update_dirs, dry_run).
echo   2. Copie o admin_pub.pem do ADM para "%DATA%\admin_pub.pem".
echo   3. Teste primeiro com "dry_run": true e depois mude para false.
echo   4. Inicie: schtasks /run /tn "%TASK_AGENT%"
echo   5. Acompanhe: type "%DATA%\logs\agent.log"
goto :done

:need_admin
echo [ERRO] Execute este script como Administrador.
exit /b 1
:need_python
echo [ERRO] Python 3.9+ nao encontrado no PATH.
exit /b 1
:copy_failed
echo [ERRO] Falha ao copiar os arquivos (robocopy).
exit /b 1
:venv_failed
echo [ERRO] Falha ao criar o ambiente virtual.
exit /b 1
:pip_failed
echo [ERRO] Falha ao instalar as dependencias (verifique a rede/proxy).
exit /b 1
:task_failed
echo [ERRO] Falha ao registrar a tarefa do agente.
exit /b 1

:done
if /I "%~1"=="/silent" exit /b 0
pause
exit /b 0
