#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dashboard.py — Painel ADM (CLI) do PyEndpoint-RMM.

Fluxo de autenticação:
  1. `init` gera um par Ed25519. A chave privada fica cifrada (scrypt + AES-GCM)
     em admin_key.json; a pública (admin_pub.pem) vai para os agentes.
  2. Todo comando exige a SENHA do ADM para destravar a chave privada.
  3. O destravamento vale por uma sessão com timeout por inatividade
     (padrão: 15 min); depois disso a senha é pedida novamente.
  4. Cada comando emitido é assinado e registrado em audit.jsonl.

Exemplos:
  python dashboard.py init --shared-dir \\\\SERVIDOR\\rmm_share
  python dashboard.py agents
  python dashboard.py reboot --target PC-FINANCEIRO-01 --delay 120
  python dashboard.py shell            # sessão interativa
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import rmm_common as rc

DEFAULT_TTL_SEC = 600
DEFAULT_SESSION_TIMEOUT_SEC = 900
MAX_LOGIN_ATTEMPTS = 3
SHARED_SUBDIRS = ("commands/_all", "results", "heartbeats", "payloads", "tickets")


# --------------------------------------------------------------------------- #
# Núcleo (funções puras, reutilizadas pelos testes)
# --------------------------------------------------------------------------- #
def build_command(
    private_key,
    ctype: str,
    target: str,
    params: dict[str, Any] | None = None,
    ttl: int = DEFAULT_TTL_SEC,
    issuer: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Monta e assina um comando. `target` é um agent_id ou '*' (todos)."""
    now = rc.now_ts() if now is None else now
    command = {
        "v": 1,
        "id": uuid.uuid4().hex,
        "type": ctype,
        "target": target,
        "issued_at": now,
        "expires_at": now + int(ttl),
        "issuer": issuer or getpass.getuser(),
        "params": params or {},
    }
    return rc.sign_command(private_key, command)


def write_envelope(shared_dir: Path, envelope: dict[str, Any]) -> Path:
    """Grava o envelope na pasta do agente alvo (ou em _all)."""
    command = envelope["command"]
    folder = "_all" if command["target"] == "*" else rc.safe_id(command["target"])
    path = Path(shared_dir) / "commands" / folder / f"{command['issued_at']}-{command['id']}.json"
    rc.atomic_write_json(path, envelope)
    return path


# --------------------------------------------------------------------------- #
# Contexto e sessão autenticada
# --------------------------------------------------------------------------- #
class AdminContext:
    def __init__(self, data_dir: Path, shared_dir: str | None, timeout: int) -> None:
        self.data_dir = Path(data_dir)
        self.shared = Path(shared_dir) if shared_dir else None
        self.timeout = timeout
        self.keystore_path = self.data_dir / "admin_key.json"
        self.audit_path = self.data_dir / "audit.jsonl"
        self.log = rc.setup_logging("dashboard", self.data_dir / "logs")
        self._key = None
        self._last_activity = 0.0

    # -- auditoria --------------------------------------------------------
    def audit(self, event: str, **fields: Any) -> None:
        record = {"ts": rc.iso_utc(), "admin": getpass.getuser(), "event": event, **fields}
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with open(self.audit_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            self.log.error("Falha ao gravar auditoria: %s", exc)

    # -- autenticação -----------------------------------------------------
    def ensure_unlocked(self) -> None:
        """Garante uma sessão válida; pede a senha se necessário."""
        if self._key is not None:
            if time.monotonic() - self._last_activity <= self.timeout:
                self._last_activity = time.monotonic()
                return
            self._key = None
            self.audit("sessao_expirada")
            print("Sessão expirada por inatividade. Autentique-se novamente.")
        if not self.keystore_path.exists():
            raise rc.ConfigError(f"Keystore não encontrado ({self.keystore_path}). Rode: dashboard.py init")
        for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
            password = getpass.getpass("Senha do ADM: ")
            try:
                self._key = rc.unlock_keystore(self.keystore_path, password)
                self._last_activity = time.monotonic()
                self.audit("login_ok")
                return
            except rc.SecurityError as exc:
                self.audit("login_falhou", tentativa=attempt)
                print(f"Falha na autenticação ({exc}).")
                time.sleep(2 ** attempt)  # atraso crescente contra força bruta interativa
        raise rc.SecurityError("Número máximo de tentativas excedido.")

    @property
    def private_key(self):
        self.ensure_unlocked()
        return self._key

    def require_shared(self) -> Path:
        if self.shared is None:
            raise rc.ConfigError("Defina 'shared_dir' em dashboard.json ou use --shared-dir.")
        return self.shared


def issue(ctx: AdminContext, ctype: str, target: str, params: dict[str, Any], ttl: int) -> int:
    envelope = build_command(ctx.private_key, ctype, target, params, ttl)
    path = write_envelope(ctx.require_shared(), envelope)
    command = envelope["command"]
    ctx.audit("comando_emitido", id=command["id"], type=ctype, target=target, params=params)
    print(f"[OK] {ctype} → {target} | id={command['id']} | válido por {ttl}s")
    ctx.log.debug("Arquivo: %s", path)
    return 0


def _confirm(args: argparse.Namespace, action: str) -> bool:
    """Exige confirmação explícita para ações destrutivas em TODOS os agentes."""
    if not getattr(args, "all", False) or getattr(args, "yes", False):
        return True
    answer = input(f"Enviar '{action}' para TODOS os agentes? Digite SIM para confirmar: ")
    return answer.strip() == "SIM"


def _target(args: argparse.Namespace) -> str:
    return "*" if args.all else rc.safe_id(args.target)


# --------------------------------------------------------------------------- #
# Subcomandos
# --------------------------------------------------------------------------- #
def cmd_init(ctx: AdminContext, args: argparse.Namespace) -> int:
    if ctx.keystore_path.exists() and not args.force:
        print(f"Já existe um keystore em {ctx.keystore_path}. Use --force para recriar (invalida os agentes atuais).")
        return 1
    if not args.shared_dir:
        print("Informe --shared-dir (pasta/UNC compartilhada com os agentes).")
        return 1
    password = getpass.getpass(f"Defina a senha do ADM (mín. {rc.MIN_PASSWORD_LEN} caracteres): ")
    if password != getpass.getpass("Confirme a senha: "):
        print("As senhas não conferem.")
        return 1
    ctx.data_dir.mkdir(parents=True, exist_ok=True)
    public_pem = rc.create_keystore(ctx.keystore_path, password)
    (ctx.data_dir / "admin_pub.pem").write_bytes(public_pem)
    rc.atomic_write_json(
        ctx.data_dir / "dashboard.json",
        {"shared_dir": args.shared_dir, "session_timeout_sec": DEFAULT_SESSION_TIMEOUT_SEC},
    )
    for sub in SHARED_SUBDIRS:
        try:
            (Path(args.shared_dir) / sub).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(f"[AVISO] Não foi possível criar {sub} no compartilhamento: {exc}")
    ctx.audit("init", shared_dir=args.shared_dir)
    print(f"\n[OK] Chave privada cifrada: {ctx.keystore_path}")
    print(f"[OK] Chave pública p/ agentes: {ctx.data_dir / 'admin_pub.pem'}")
    print("     Copie admin_pub.pem para o data_dir de cada agente. NUNCA distribua admin_key.json.")
    return 0


def cmd_agents(ctx: AdminContext, args: argparse.Namespace) -> int:
    folder = ctx.require_shared() / "heartbeats"
    rows = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            rows.append(rc.read_json(path))
        except (OSError, ValueError) as exc:
            ctx.log.warning("Heartbeat ilegível %s: %s", path.name, exc)
    if not rows:
        print("Nenhum agente reportou ainda.")
        return 0
    now = rc.now_ts()
    print(f"{'AGENTE':<22}{'STATUS':<9}{'VISTO':<10}{'CPU%':<7}{'MEM%':<7}{'DISCO%':<8}SO")
    for hb in rows:
        age = now - int(hb.get("timestamp", 0))
        online = age <= 3 * int(hb.get("heartbeat_interval_sec", 30))
        print(
            f"{str(hb.get('agent_id', '?')):<22}{'ONLINE' if online else 'OFFLINE':<9}"
            f"{_age(age):<10}{str(hb.get('cpu_percent', '-')):<7}{str(hb.get('mem_percent', '-')):<7}"
            f"{str(hb.get('disk_percent', '-')):<8}{str(hb.get('os', ''))[:40]}"
        )
    return 0


def _age(seconds: int) -> str:
    if seconds < 90:
        return f"{max(seconds, 0)}s"
    if seconds < 5400:
        return f"{seconds // 60}min"
    return f"{seconds // 3600}h"


def cmd_ping(ctx, args):
    return issue(ctx, "ping", _target(args), {}, args.ttl)


def cmd_status(ctx, args):
    return issue(ctx, "status", _target(args), {}, args.ttl)


def cmd_notify(ctx, args):
    params = {"title": args.title, "message": args.message, "priority": args.priority,
              "ticket_ref": args.ticket or ""}
    return issue(ctx, "notify", _target(args), params, args.ttl)


def cmd_reboot(ctx, args):
    if not _confirm(args, "reboot"):
        print("Cancelado.")
        return 1
    params = {"delay_sec": args.delay, "message": args.message}
    return issue(ctx, "reboot", _target(args), params, args.ttl)


def cmd_cancel_reboot(ctx, args):
    return issue(ctx, "cancel_reboot", _target(args), {}, args.ttl)


def _payload_hash(ctx: AdminContext, name: str) -> str:
    path = ctx.require_shared() / "payloads" / rc.safe_id(name)
    if not path.is_file():
        raise rc.ConfigError(f"Payload não encontrado: {path} (use 'payload-add')")
    return rc.sha256_file(path)


def cmd_run_script(ctx, args):
    if not _confirm(args, f"run-script {args.name}"):
        print("Cancelado.")
        return 1
    params = {"name": args.name, "sha256": _payload_hash(ctx, args.name),
              "args": args.args, "timeout_sec": args.timeout}
    return issue(ctx, "run_script", _target(args), params, args.ttl)


def cmd_update(ctx, args):
    if not _confirm(args, f"update {args.name}"):
        print("Cancelado.")
        return 1
    params = {"name": args.name, "sha256": _payload_hash(ctx, args.name), "dest": args.dest}
    return issue(ctx, "update", _target(args), params, args.ttl)


def cmd_payload_add(ctx, args):
    source = Path(args.file)
    name = rc.safe_id(args.name or source.name)
    target_dir = ctx.require_shared() / "payloads"
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target_dir / name)
    digest = rc.sha256_file(target_dir / name)
    ctx.audit("payload_adicionado", name=name, sha256=digest)
    print(f"[OK] {name} publicado em payloads/ | sha256={digest}")
    return 0


def cmd_results(ctx, args):
    base = ctx.require_shared() / "results"
    files = []
    pattern = args.agent if args.agent else "*"
    for path in base.glob(f"{pattern}/*.json") if base.is_dir() else []:
        files.append((path.stat().st_mtime, path))
    files.sort(reverse=True)
    if not files:
        print("Nenhum resultado.")
        return 0
    for _, path in files[: args.n]:
        try:
            res = rc.read_json(path)
        except (OSError, ValueError):
            continue
        print(f"{res.get('finished_at', '?')}  {res.get('agent_id', '?'):<20} {res.get('type', '?'):<14} "
              f"{res.get('status', '?'):<9} {str(res.get('command_id', ''))[:8]}  {res.get('detail', '')}")
        if args.verbose and res.get("output"):
            print("    " + str(res["output"]).strip().replace("\n", "\n    "))
    return 0


def cmd_tickets(ctx, args):
    base = ctx.require_shared() / "tickets"
    pattern = args.agent if args.agent else "*"
    found = sorted(base.glob(f"{pattern}/*.json")) if base.is_dir() else []
    if not found:
        print("Nenhum chamado aberto.")
        return 0
    for path in found[-args.n:]:
        try:
            t = rc.read_json(path)
        except (OSError, ValueError):
            continue
        print(f"[{t.get('created_at', '?')}] {t.get('agent_id', '?')} / {t.get('user', '?')}: "
              f"{t.get('title', '')}\n    {str(t.get('description', ''))[:300]}")
    return 0


def cmd_shell(ctx, args):  # tratado em run_shell(); aqui só por completude do parser
    return run_shell(ctx)


# --------------------------------------------------------------------------- #
# Parser e shell interativo
# --------------------------------------------------------------------------- #
def _add_target(p: argparse.ArgumentParser) -> None:
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="agent_id de destino")
    group.add_argument("--all", action="store_true", help="enviar para todos os agentes")
    p.add_argument("--ttl", type=int, default=DEFAULT_TTL_SEC, help="validade do comando em segundos")
    p.add_argument("--yes", action="store_true", help="não pedir confirmação em envios --all")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dashboard.py", description="Painel ADM do PyEndpoint-RMM")
    parser.add_argument("--data-dir", help="pasta de dados do ADM (chaves, logs, auditoria)")
    parser.add_argument("--shared-dir", help="pasta compartilhada com os agentes")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="gera chaves e prepara o compartilhamento")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    sub.add_parser("agents", help="lista agentes e estado").set_defaults(func=cmd_agents)
    sub.add_parser("shell", help="sessão interativa").set_defaults(func=cmd_shell)

    p = sub.add_parser("ping", help="testa comunicação")
    _add_target(p); p.set_defaults(func=cmd_ping)

    p = sub.add_parser("status", help="força coleta de status imediata")
    _add_target(p); p.set_defaults(func=cmd_status)

    p = sub.add_parser("notify", help="exibe um aviso ao usuário")
    _add_target(p)
    p.add_argument("--title", default="Aviso da TI")
    p.add_argument("--message", required=True)
    p.add_argument("--priority", choices=("info", "warning", "urgent"), default="info")
    p.add_argument("--ticket", help="referência de chamado associada")
    p.set_defaults(func=cmd_notify)

    p = sub.add_parser("reboot", help="reinicia a máquina (com aviso ao usuário)")
    _add_target(p)
    p.add_argument("--delay", type=int, default=60, help="segundos até reiniciar (30–3600)")
    p.add_argument("--message", default="Reinício solicitado pela equipe de TI.")
    p.set_defaults(func=cmd_reboot)

    p = sub.add_parser("cancel-reboot", help="cancela um reinício programado")
    _add_target(p); p.set_defaults(func=cmd_cancel_reboot)

    p = sub.add_parser("payload-add", help="publica um script/executável em payloads/")
    p.add_argument("file")
    p.add_argument("--name", help="nome no compartilhamento (padrão: nome do arquivo)")
    p.set_defaults(func=cmd_payload_add)

    p = sub.add_parser("run-script", help="executa um payload já publicado")
    _add_target(p)
    p.add_argument("name", help="nome do arquivo em payloads/")
    p.add_argument("--args", nargs="*", default=[], help="argumentos simples (sem metacaracteres de shell)")
    p.add_argument("--timeout", type=int, default=300)
    p.set_defaults(func=cmd_run_script)

    p = sub.add_parser("update", help="substitui um executável local por um payload")
    _add_target(p)
    p.add_argument("name", help="nome do arquivo em payloads/")
    p.add_argument("--dest", required=True, help="caminho absoluto de destino (precisa estar em allowed_update_dirs)")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("results", help="resultados recentes dos comandos")
    p.add_argument("--agent"); p.add_argument("-n", type=int, default=15)
    p.add_argument("-v", "--verbose", action="store_true", help="mostra a saída dos scripts")
    p.set_defaults(func=cmd_results)

    p = sub.add_parser("tickets", help="chamados abertos pelos usuários")
    p.add_argument("--agent"); p.add_argument("-n", type=int, default=15)
    p.set_defaults(func=cmd_tickets)
    return parser


def run_shell(ctx: AdminContext) -> int:
    parser = build_parser()
    ctx.ensure_unlocked()
    print("Shell PyEndpoint-RMM — 'help' lista os comandos, 'exit' encerra.")
    while True:
        try:
            line = input("rmm> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in ("exit", "quit", "sair"):
            break
        if line in ("help", "?"):
            parser.print_help()
            continue
        try:
            argv = shlex.split(line, posix=(os.name != "nt"))
            if os.name == "nt":
                argv = [a.strip("\"'") for a in argv]
            args = parser.parse_args(argv)
            if args.command in ("shell", "init"):
                print("Comando indisponível dentro do shell.")
                continue
            ctx.ensure_unlocked()  # renova a sessão ou pede a senha após o timeout
            args.func(ctx, args)
        except SystemExit:
            continue  # argparse já exibiu o erro de uso
        except (rc.ConfigError, rc.SecurityError, ValueError, OSError) as exc:
            print(f"[ERRO] {exc}")
        except Exception:
            ctx.log.exception("Erro inesperado")
    ctx.audit("logout")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir) if args.data_dir else rc.default_data_dir("admin")
    shared, timeout = args.shared_dir, DEFAULT_SESSION_TIMEOUT_SEC
    try:
        cfg = rc.load_json_config(data_dir / "dashboard.json")
        shared = shared or cfg.get("shared_dir")
        timeout = int(cfg.get("session_timeout_sec", timeout))
    except rc.ConfigError:
        pass  # normal antes do `init`
    ctx = AdminContext(data_dir, shared, timeout)

    try:
        if args.command == "init":
            return cmd_init(ctx, args)
        ctx.ensure_unlocked()  # porta única de autenticação
        if args.command == "shell":
            return run_shell(ctx)
        return args.func(ctx, args)
    except (rc.ConfigError, rc.SecurityError, ValueError, OSError) as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrompido.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
