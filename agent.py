#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent.py — Agente do PyEndpoint-RMM.

Roda em segundo plano (serviço/tarefa agendada) e, em ciclo:

1. publica um *heartbeat* com o estado da máquina no diretório compartilhado;
2. lê comandos em  <shared>/commands/<agent_id>/  e  <shared>/commands/_all/;
3. VERIFICA a assinatura Ed25519, o alvo, a validade e se o comando é inédito;
4. executa somente tipos de comando conhecidos (nada de shell arbitrário);
5. grava o resultado em  <shared>/results/<agent_id>/<id>.json.

Tipos suportados: ping, status, notify, reboot, cancel_reboot, run_script, update.

Princípios de segurança:
* o agente só possui a chave PÚBLICA do ADM — não consegue forjar comandos;
* scripts e executáveis só rodam/instalam se o SHA-256 assinado bater;
* atualizações só podem gravar dentro de `allowed_update_dirs`;
* nenhuma execução usa shell=True; argumentos passam por lista branca;
* o reinício sempre avisa o usuário e respeita um atraso mínimo de 30 s.

Códigos de saída: 0 = encerrado normalmente, 2 = erro de configuração.
"""
from __future__ import annotations

import argparse
import hmac
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

import rmm_common as rc

try:  # psutil é opcional: sem ele o heartbeat traz menos métricas.
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

AGENT_VERSION = rc.__version__
EXIT_OK = 0
EXIT_CONFIG = 2

CLOCK_SKEW_SEC = 120          # tolerância de relógio entre ADM e agente
MAX_OUTPUT_CHARS = 4000       # saída de scripts gravada no resultado
MAX_PROCESSED_IDS = 2000      # tamanho do histórico anti-replay
MIN_REBOOT_DELAY = 30         # o usuário sempre tem tempo de salvar o trabalho
MAX_REBOOT_DELAY = 3600
SAFE_ARG = re.compile(r"^[A-Za-z0-9_\-.:=/\\]{0,256}$")  # sem metacaracteres de shell

DEFAULT_CONFIG: dict[str, Any] = {
    "agent_id": "",                 # padrão: hostname
    "shared_dir": "",               # ex.: \\SERVIDOR\rmm_share
    "admin_public_key": "",         # padrão: <data_dir>/admin_pub.pem
    "data_dir": "",                 # padrão: veja rc.default_data_dir
    "poll_interval_sec": 5,
    "heartbeat_interval_sec": 30,
    "max_command_ttl_sec": 900,     # validade máxima aceita para um comando
    "reboot_delay_sec": 60,
    "script_timeout_sec": 300,
    "allowed_script_exts": [".bat", ".cmd", ".ps1", ".py", ".sh"],
    "allowed_update_dirs": [],      # pastas onde `update` pode gravar
    "monitored_processes": [],      # ex.: ["MsMpEng.exe", "backup.exe"]
    "report_logged_users": True,
    "dry_run": False,               # True = valida tudo, mas não executa nada
    "log_level": "INFO",
}


# --------------------------------------------------------------------------- #
# Configuração
# --------------------------------------------------------------------------- #
def load_config(path: Path) -> dict[str, Any]:
    """Lê e valida a configuração do agente."""
    cfg = {**DEFAULT_CONFIG, **rc.load_json_config(path)}
    cfg["agent_id"] = cfg["agent_id"] or socket.gethostname()
    try:
        rc.safe_id(cfg["agent_id"])
    except ValueError as exc:
        raise rc.ConfigError(f"agent_id inválido (use letras, números, . _ -): {exc}") from exc
    if not cfg["shared_dir"]:
        raise rc.ConfigError("'shared_dir' é obrigatório.")
    cfg["data_dir"] = cfg["data_dir"] or str(rc.default_data_dir("agent"))
    cfg["admin_public_key"] = cfg["admin_public_key"] or str(Path(cfg["data_dir"]) / "admin_pub.pem")
    for key in ("poll_interval_sec", "heartbeat_interval_sec", "max_command_ttl_sec"):
        if not isinstance(cfg[key], (int, float)) or cfg[key] < 1:
            raise rc.ConfigError(f"'{key}' deve ser um número >= 1.")
    return cfg


def _is_within(child: Path, parent: Path) -> bool:
    """True se `child` estiver dentro de `parent` (case-insensitive no Windows)."""
    try:
        c = os.path.normcase(str(child.resolve()))
        p = os.path.normcase(str(parent.resolve()))
        return os.path.commonpath([c, p]) == p
    except ValueError:  # discos diferentes
        return False


# --------------------------------------------------------------------------- #
# Agente
# --------------------------------------------------------------------------- #
class Agent:
    def __init__(self, cfg: dict[str, Any], log) -> None:
        self.cfg = cfg
        self.log = log
        self.agent_id = rc.safe_id(cfg["agent_id"])
        self.shared = Path(cfg["shared_dir"])
        self.data = Path(cfg["data_dir"])
        self.public_key = rc.load_public_key(Path(cfg["admin_public_key"]))

        self.payloads_dir = self.shared / "payloads"
        self.results_dir = self.shared / "results" / self.agent_id
        self.heartbeat_path = self.shared / "heartbeats" / f"{self.agent_id}.json"
        # (pasta, alvo esperado dentro dos comandos daquela pasta)
        self.command_sources = [
            (self.shared / "commands" / self.agent_id, self.agent_id),
            (self.shared / "commands" / "_all", "*"),
        ]
        self.spool_dir = self.data / "spool" / "notify"
        self.staging_dir = self.data / "staging"
        self.state_path = self.data / "state.json"

        self._stop = threading.Event()
        self._rejected_files: set[str] = set()
        self._share_ok: bool | None = None
        self._started = time.time()
        self.state = self._load_state()

        self.handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "ping": self._h_ping,
            "status": self._h_status,
            "notify": self._h_notify,
            "reboot": self._h_reboot,
            "cancel_reboot": self._h_cancel_reboot,
            "run_script": self._h_run_script,
            "update": self._h_update,
        }

    # ------------------------------------------------------------------ estado
    def _load_state(self) -> dict[str, Any]:
        try:
            state = rc.read_json(self.state_path)
            if isinstance(state.get("processed"), list):
                return state
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            self.log.warning("Estado local ilegível (%s); iniciando vazio.", exc)
        return {"processed": []}

    def _mark_processed(self, command_id: str) -> None:
        """Registra o id ANTES de executar: um crash/reboot nunca repete o comando."""
        processed = self.state["processed"]
        processed.append(command_id)
        del processed[:-MAX_PROCESSED_IDS]
        try:
            rc.atomic_write_json(self.state_path, self.state)
        except OSError as exc:
            self.log.error("Falha ao salvar estado local: %s", exc)

    # ------------------------------------------------------------------ ciclo
    def stop(self, *_: Any) -> None:
        self.log.info("Encerramento solicitado.")
        self._stop.set()

    def run(self) -> None:
        self.log.info(
            "Agente %s v%s iniciado | compartilhamento=%s | dry_run=%s",
            self.agent_id, AGENT_VERSION, self.shared, self.cfg["dry_run"],
        )
        next_heartbeat = 0.0
        while not self._stop.is_set():
            try:
                if time.monotonic() >= next_heartbeat:
                    next_heartbeat = time.monotonic() + self.cfg["heartbeat_interval_sec"]
                    self.write_heartbeat()
                self.process_commands()
                self._set_share_state(True)
            except OSError as exc:  # compartilhamento fora do ar, rede, permissões
                self._set_share_state(False, exc)
            except Exception:  # nunca derrubar o agente por um erro inesperado
                self.log.exception("Erro inesperado no ciclo principal")
            self._stop.wait(self.cfg["poll_interval_sec"])
        self.log.info("Agente finalizado.")

    def _set_share_state(self, ok: bool, exc: Exception | None = None) -> None:
        """Loga apenas as transições (evita encher o log quando a rede cai)."""
        if ok and self._share_ok is False:
            self.log.info("Compartilhamento acessível novamente.")
        elif not ok and self._share_ok is not False:
            self.log.warning("Compartilhamento inacessível: %s", exc)
        self._share_ok = ok

    # --------------------------------------------------------------- heartbeat
    def build_heartbeat(self) -> dict[str, Any]:
        hb: dict[str, Any] = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "agent_version": AGENT_VERSION,
            "timestamp": rc.now_ts(),
            "heartbeat_interval_sec": self.cfg["heartbeat_interval_sec"],
            "agent_uptime_sec": int(time.time() - self._started),
            "dry_run": bool(self.cfg["dry_run"]),
        }
        try:
            root = os.path.abspath(os.sep)
            disk = shutil.disk_usage(root)
            hb["disk_percent"] = round(disk.used / disk.total * 100, 1)
        except OSError:
            pass
        if psutil is not None:
            try:
                hb["cpu_percent"] = psutil.cpu_percent(interval=None)
                hb["mem_percent"] = psutil.virtual_memory().percent
                hb["boot_time"] = int(psutil.boot_time())
                if self.cfg["report_logged_users"]:
                    hb["logged_users"] = sorted({u.name for u in psutil.users()})
                wanted = [str(n) for n in self.cfg["monitored_processes"]]
                if wanted:
                    running = {
                        (p.info.get("name") or "").lower()
                        for p in psutil.process_iter(["name"])
                    }
                    hb["monitored_processes"] = {n: n.lower() in running for n in wanted}
            except Exception as exc:  # métricas são "melhor esforço"
                self.log.debug("Falha ao coletar métricas: %s", exc)
        return hb

    def write_heartbeat(self) -> dict[str, Any]:
        hb = self.build_heartbeat()
        rc.atomic_write_json(self.heartbeat_path, hb)
        return hb

    # ---------------------------------------------------------------- comandos
    def process_commands(self) -> None:
        for directory, expected_target in self.command_sources:
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.json")):
                if self._stop.is_set():
                    return
                self._handle_file(path, expected_target)

    def _check_policy(self, cmd: dict[str, Any], expected_target: str) -> str | None:
        """Regras de aceitação. Devolve o motivo da recusa, ou None se aprovado."""
        for field in ("v", "id", "type", "target", "issued_at", "expires_at"):
            if field not in cmd:
                return f"campo obrigatório ausente: {field}"
        if cmd["v"] != 1:
            return "versão de protocolo não suportada"
        try:
            rc.safe_id(cmd["id"])
        except ValueError:
            return "id de comando inválido"
        if cmd["target"] != expected_target:
            return "alvo não corresponde a este agente"
        issued, expires = cmd["issued_at"], cmd["expires_at"]
        if not isinstance(issued, int) or not isinstance(expires, int):
            return "datas inválidas"
        now = rc.now_ts()
        if issued > now + CLOCK_SKEW_SEC:
            return "emitido no futuro (relógio dessincronizado?)"
        if expires - issued > self.cfg["max_command_ttl_sec"]:
            return "validade acima do máximo permitido"
        return None

    def _handle_file(self, path: Path, expected_target: str) -> None:
        # 1) autenticidade ------------------------------------------------
        try:
            cmd = rc.verify_envelope(self.public_key, rc.read_json(path))
        except (OSError, ValueError, rc.SecurityError) as exc:
            if path.name not in self._rejected_files:
                self._rejected_files.add(path.name)
                self.log.warning("Comando %s descartado: %s", path.name, exc)
            return

        # 2) política (alvo, validade) e anti-replay ----------------------
        reason = self._check_policy(cmd, expected_target)
        command_id = cmd.get("id")
        if reason is None and command_id in self.state["processed"]:
            return  # já executado
        if reason is None and cmd["expires_at"] < rc.now_ts():
            self._mark_processed(command_id)
            self.log.info("Comando %s expirado; ignorado.", command_id)
            return
        if reason is not None:
            if isinstance(command_id, str) and rc.ID_PATTERN.fullmatch(command_id):
                if command_id in self.state["processed"]:
                    return
                self._mark_processed(command_id)
                self.log.warning("Comando %s rejeitado: %s", command_id, reason)
                self._write_result(cmd, {"status": "rejected", "detail": reason}, time.time())
            return

        # 3) execução -----------------------------------------------------
        self._mark_processed(command_id)
        started = time.time()
        self.log.info(
            "Executando %s (id=%s, emitido por %s)", cmd["type"], command_id, cmd.get("issuer", "?")
        )
        handler = self.handlers.get(cmd["type"])
        try:
            result = handler(cmd) if handler else {"status": "error", "detail": "tipo de comando desconhecido"}
        except (rc.SecurityError, ValueError) as exc:
            self.log.warning("Comando %s recusado: %s", command_id, exc)
            result = {"status": "rejected", "detail": str(exc)}
        except Exception as exc:
            self.log.exception("Falha ao executar %s", command_id)
            result = {"status": "error", "detail": f"{type(exc).__name__}: {exc}"}
        self._write_result(cmd, result, started)
        self.log.info("Comando %s finalizado: %s", command_id, result.get("status"))

    def _write_result(self, cmd: dict[str, Any], result: dict[str, Any], started: float) -> None:
        command_id = cmd.get("id")
        if not isinstance(command_id, str) or not rc.ID_PATTERN.fullmatch(command_id):
            return
        payload = {
            "command_id": command_id,
            "agent_id": self.agent_id,
            "type": cmd.get("type"),
            "started_at": rc.iso_utc(started),
            "finished_at": rc.iso_utc(),
            **result,
        }
        try:
            rc.atomic_write_json(self.results_dir / f"{command_id}.json", payload)
        except OSError as exc:
            self.log.error("Não foi possível gravar o resultado de %s: %s", command_id, exc)

    # -------------------------------------------------------- utilitários
    def _spool_notice(self, title: str, message: str, priority: str = "info", ticket_ref: str = "") -> None:
        """Entrega um aviso ao ticket_notifier (que roda na sessão do usuário)."""
        notice = {
            "id": uuid.uuid4().hex,
            "created_at": rc.now_ts(),
            "title": str(title)[:120],
            "message": str(message)[:1500],
            "priority": priority if priority in ("info", "warning", "urgent") else "info",
            "ticket_ref": str(ticket_ref)[:64],
        }
        rc.atomic_write_json(self.spool_dir / f"{notice['created_at']}-{notice['id']}.json", notice)

    def _run(self, argv: list[str], timeout: int) -> dict[str, Any]:
        """Executa um processo SEM shell, com timeout e saída limitada."""
        if self.cfg["dry_run"]:
            self.log.info("[dry-run] %s", argv)
            return {"status": "ok", "detail": "dry-run: nada foi executado", "exit_code": 0}
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, errors="replace",
                timeout=timeout, check=False, **kwargs,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "detail": f"excedeu {timeout}s"}
        except OSError as exc:
            return {"status": "error", "detail": f"não foi possível iniciar o processo: {exc}"}
        output = ((proc.stdout or "") + (proc.stderr or ""))[-MAX_OUTPUT_CHARS:]
        return {
            "status": "ok" if proc.returncode == 0 else "failed",
            "exit_code": proc.returncode,
            "output": output,
        }

    def _stage_payload(self, command_id: str, name: str, expected_sha: str, allowed_exts: set[str] | None) -> Path:
        """Copia o payload para a área local e confere o SHA-256 assinado.

        Copiar primeiro e conferir DEPOIS evita TOCTOU: o arquivo executado é
        exatamente o que foi verificado, mesmo que o share seja alterado.
        """
        name = rc.safe_id(name)
        if allowed_exts is not None and Path(name).suffix.lower() not in allowed_exts:
            raise rc.SecurityError(f"extensão não permitida: {Path(name).suffix or '(nenhuma)'}")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha or ""):
            raise rc.SecurityError("sha256 ausente ou malformado no comando")
        source = self.payloads_dir / name
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        staged = self.staging_dir / f"{command_id}-{name}"
        shutil.copy2(source, staged)
        if not hmac.compare_digest(rc.sha256_file(staged).lower(), expected_sha.lower()):
            staged.unlink(missing_ok=True)
            raise rc.SecurityError("SHA-256 do payload não confere com o comando assinado")
        return staged

    @staticmethod
    def _script_argv(path: Path, args: list[str]) -> list[str]:
        ext = path.suffix.lower()
        if ext in (".bat", ".cmd"):
            if os.name != "nt":
                raise ValueError("scripts .bat/.cmd só rodam no Windows")
            return ["cmd.exe", "/c", str(path), *args]
        if ext == ".ps1":
            shell = "powershell.exe" if os.name == "nt" else "pwsh"
            return [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-File", str(path), *args]
        if ext == ".py":
            return [sys.executable, str(path), *args]
        if ext == ".sh":
            if os.name == "nt":
                raise ValueError("scripts .sh não são suportados no Windows")
            return ["/bin/sh", str(path), *args]
        raise ValueError(f"extensão sem interpretador: {ext}")

    # ----------------------------------------------------------- executores
    def _h_ping(self, cmd: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "detail": "pong", "agent_version": AGENT_VERSION}

    def _h_status(self, cmd: dict[str, Any]) -> dict[str, Any]:
        return {"status": "ok", "data": self.write_heartbeat()}

    def _h_notify(self, cmd: dict[str, Any]) -> dict[str, Any]:
        p = cmd.get("params") or {}
        self._spool_notice(p.get("title", "Aviso da TI"), p.get("message", ""),
                           p.get("priority", "info"), p.get("ticket_ref", ""))
        return {"status": "ok", "detail": "aviso entregue ao notificador local"}

    def _h_reboot(self, cmd: dict[str, Any]) -> dict[str, Any]:
        p = cmd.get("params") or {}
        delay = int(p.get("delay_sec", self.cfg["reboot_delay_sec"]))
        delay = max(MIN_REBOOT_DELAY, min(delay, MAX_REBOOT_DELAY))
        reason = str(p.get("message") or "Reinício solicitado pela equipe de TI.")[:200]
        self._spool_notice(
            "Reinício programado",
            f"{reason}\nO computador será reiniciado em {delay} segundos. Salve seu trabalho.",
            "urgent",
        )
        if os.name == "nt":
            argv = ["shutdown", "/r", "/t", str(delay), "/c", reason]
        else:
            argv = ["shutdown", "-r", f"+{max(1, delay // 60)}", reason]
        return self._run(argv, timeout=30)

    def _h_cancel_reboot(self, cmd: dict[str, Any]) -> dict[str, Any]:
        argv = ["shutdown", "/a"] if os.name == "nt" else ["shutdown", "-c"]
        self._spool_notice("Reinício cancelado", "O reinício programado pela TI foi cancelado.", "info")
        return self._run(argv, timeout=30)

    def _h_run_script(self, cmd: dict[str, Any]) -> dict[str, Any]:
        p = cmd.get("params") or {}
        args = p.get("args", [])
        if not isinstance(args, list) or len(args) > 16:
            raise ValueError("'args' deve ser uma lista com até 16 itens")
        for arg in args:
            if not isinstance(arg, str) or not SAFE_ARG.fullmatch(arg):
                raise rc.SecurityError("argumento contém caracteres não permitidos")
        timeout = max(1, min(int(p.get("timeout_sec", self.cfg["script_timeout_sec"])),
                             int(self.cfg["script_timeout_sec"])))
        exts = {e.lower() for e in self.cfg["allowed_script_exts"]}
        staged = self._stage_payload(cmd["id"], str(p.get("name", "")), str(p.get("sha256", "")), exts)
        try:
            return self._run(self._script_argv(staged, args), timeout)
        finally:
            staged.unlink(missing_ok=True)

    def _h_update(self, cmd: dict[str, Any]) -> dict[str, Any]:
        p = cmd.get("params") or {}
        dest = Path(str(p.get("dest", ""))).expanduser()
        if not dest.is_absolute():
            raise ValueError("'dest' deve ser um caminho absoluto")
        allowed = [Path(d) for d in self.cfg["allowed_update_dirs"]]
        if not any(_is_within(dest, base) for base in allowed):
            raise rc.SecurityError(f"destino fora de allowed_update_dirs: {dest}")
        staged = self._stage_payload(cmd["id"], str(p.get("name", "")), str(p.get("sha256", "")), None)
        try:
            if self.cfg["dry_run"]:
                self.log.info("[dry-run] atualizaria %s", dest)
                return {"status": "ok", "detail": "dry-run: nada foi alterado"}
            dest.parent.mkdir(parents=True, exist_ok=True)
            backup = None
            if dest.exists():
                backup = dest.with_name(dest.name + ".bak")
                shutil.copy2(dest, backup)
            temp = dest.with_name(dest.name + ".new")
            shutil.copy2(staged, temp)
            os.replace(temp, dest)  # troca atômica: nunca fica meio gravado
            return {"status": "ok", "detail": f"atualizado: {dest}",
                    "backup": str(backup) if backup else None}
        finally:
            staged.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Entrada
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agente PyEndpoint-RMM")
    parser.add_argument(
        "--config",
        default=os.environ.get("PYENDPOINT_AGENT_CONFIG", str(rc.default_data_dir("agent") / "agent.json")),
        help="caminho do agent.json",
    )
    args = parser.parse_args(argv)

    try:
        cfg = load_config(Path(args.config))
    except rc.ConfigError as exc:
        print(f"[ERRO DE CONFIGURAÇÃO] {exc}", file=sys.stderr)
        return EXIT_CONFIG

    log = rc.setup_logging("agent", Path(cfg["data_dir"]) / "logs", cfg["log_level"])
    try:
        agent = Agent(cfg, log)
    except (rc.ConfigError, rc.SecurityError, ValueError, OSError) as exc:
        log.error("Falha ao iniciar o agente: %s", exc)
        return EXIT_CONFIG

    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, agent.stop)
            except (ValueError, OSError):  # fora da thread principal etc.
                pass
    agent.run()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
