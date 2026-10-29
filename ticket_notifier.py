#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ticket_notifier.py — Módulo de suporte ao usuário do PyEndpoint-RMM.

Roda na SESSÃO DO USUÁRIO (o agente roda como serviço e não consegue exibir
janelas). Responsabilidades:

* exibir avisos que o agente deposita em <data_dir>/spool/notify/;
* permitir que o usuário abra um chamado técnico (grava um JSON em
  <shared>/tickets/<agent_id>/ e, opcionalmente, abre a URL do helpdesk);
* se o compartilhamento estiver indisponível, guarda o chamado numa caixa de
  saída local e reenvia depois.

Chamados são apenas DADOS informativos: nunca são interpretados como comandos.

Uso:
  python ticket_notifier.py                 # daemon com GUI (janelas de aviso)
  python ticket_notifier.py --new-ticket    # abre direto o formulário de chamado
  python ticket_notifier.py --list          # lista os chamados desta máquina
  python ticket_notifier.py --no-gui --once # modo console (teste/headless)
"""
from __future__ import annotations

import argparse
import getpass
import os
import socket
import sys
import uuid
import webbrowser
from pathlib import Path
from typing import Any

import rmm_common as rc

try:
    import tkinter as tk
    from tkinter import messagebox, simpledialog
except ImportError:  # Linux sem python3-tk, ambientes headless
    tk = None

POLL_INTERVAL_MS = 3000
MAX_TITLE = 120
MAX_DESCRIPTION = 2000
PRIORITY_COLORS = {"info": "#1f6feb", "warning": "#d29922", "urgent": "#da3633"}

DEFAULT_CONFIG: dict[str, Any] = {
    "agent_id": "",
    "shared_dir": "",
    "data_dir": "",
    "helpdesk_url": "",   # opcional: aberto no navegador após criar o chamado
    "log_level": "INFO",
}


def load_config(path: Path) -> dict[str, Any]:
    """Reaproveita o mesmo agent.json do agente (chaves extras são ignoradas)."""
    cfg = {**DEFAULT_CONFIG, **rc.load_json_config(path)}
    cfg["agent_id"] = cfg["agent_id"] or socket.gethostname()
    rc.safe_id(cfg["agent_id"])
    cfg["data_dir"] = cfg["data_dir"] or str(rc.default_data_dir("agent"))
    if not cfg["shared_dir"]:
        raise rc.ConfigError("'shared_dir' é obrigatório.")
    return cfg


class Notifier:
    def __init__(self, cfg: dict[str, Any], log) -> None:
        self.cfg, self.log = cfg, log
        self.agent_id = rc.safe_id(cfg["agent_id"])
        self.spool_dir = Path(cfg["data_dir"]) / "spool" / "notify"
        self.tickets_dir = Path(cfg["shared_dir"]) / "tickets" / self.agent_id
        # Caixa de saída na pasta do USUÁRIO (o usuário comum não escreve em ProgramData).
        self.outbox_dir = Path.home() / ".pyendpoint-rmm" / "outbox"

    # ------------------------------------------------------------- chamados
    def build_ticket(self, title: str, description: str, ref: str = "") -> dict[str, Any]:
        title = title.strip()[:MAX_TITLE]
        if not title:
            raise ValueError("O resumo do chamado não pode ficar vazio.")
        return {
            "id": uuid.uuid4().hex,
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "user": getpass.getuser(),
            "title": title,
            "description": description.strip()[:MAX_DESCRIPTION],
            "ref": ref[:64],
            "created_at": rc.iso_utc(),
            "status": "open",
        }

    def submit_ticket(self, ticket: dict[str, Any]) -> bool:
        """Envia ao compartilhamento; em caso de falha, guarda na caixa de saída."""
        name = f"{ticket['created_at'].replace(':', '')}-{ticket['id']}.json"
        try:
            rc.atomic_write_json(self.tickets_dir / name, ticket)
            self.log.info("Chamado %s enviado.", ticket["id"])
            return True
        except OSError as exc:
            self.log.warning("Compartilhamento indisponível (%s); chamado guardado na caixa de saída.", exc)
            try:
                rc.atomic_write_json(self.outbox_dir / name, ticket)
            except OSError as exc2:
                self.log.error("Não foi possível guardar o chamado localmente: %s", exc2)
                raise
            return False

    def flush_outbox(self) -> None:
        if not self.outbox_dir.is_dir():
            return
        for path in sorted(self.outbox_dir.glob("*.json")):
            try:
                rc.atomic_write_json(self.tickets_dir / path.name, rc.read_json(path))
                path.unlink()
                self.log.info("Chamado pendente %s reenviado.", path.name)
            except (OSError, ValueError):
                return  # tenta de novo no próximo ciclo

    def list_tickets(self) -> list[dict[str, Any]]:
        tickets = []
        for path in sorted(self.tickets_dir.glob("*.json")) if self.tickets_dir.is_dir() else []:
            try:
                tickets.append(rc.read_json(path))
            except (OSError, ValueError):
                continue
        return tickets

    # --------------------------------------------------------------- avisos
    def pop_notices(self) -> list[dict[str, Any]]:
        """Lê e consome os avisos pendentes (remove o arquivo ao ler)."""
        notices = []
        if not self.spool_dir.is_dir():
            return notices
        for path in sorted(self.spool_dir.glob("*.json")):
            try:
                notice = rc.read_json(path)
                path.unlink()
            except (OSError, ValueError) as exc:
                self.log.warning("Aviso %s ignorado: %s", path.name, exc)
                continue
            if isinstance(notice, dict):
                notices.append(notice)
        return notices

    def open_helpdesk(self) -> None:
        url = self.cfg.get("helpdesk_url")
        if url and str(url).lower().startswith(("http://", "https://")):
            webbrowser.open(url)

    # ------------------------------------------------------------------ GUI
    def _ask_ticket(self, root, ref: str = "") -> None:
        title = simpledialog.askstring("Novo chamado", "Resumo do problema:", parent=root)
        if not title:
            return
        description = simpledialog.askstring("Novo chamado", "Descreva o que está acontecendo:", parent=root) or ""
        try:
            sent = self.submit_ticket(self.build_ticket(title, description, ref))
        except (ValueError, OSError) as exc:
            messagebox.showerror("Chamado não enviado", str(exc), parent=root)
            return
        messagebox.showinfo(
            "Chamado registrado",
            "Seu chamado foi enviado à equipe de TI." if sent
            else "Sem conexão com o servidor: o chamado será enviado automaticamente mais tarde.",
            parent=root,
        )
        self.open_helpdesk()

    def _show_notice(self, root, notice: dict[str, Any]) -> None:
        priority = notice.get("priority", "info")
        win = tk.Toplevel(root)
        win.title(str(notice.get("title", "Aviso da TI")))
        win.attributes("-topmost", True)
        win.resizable(False, False)
        tk.Label(win, text=str(notice.get("title", "Aviso da TI")), fg="white",
                 bg=PRIORITY_COLORS.get(priority, "#1f6feb"), font=("Segoe UI", 12, "bold"),
                 padx=14, pady=8, anchor="w").pack(fill="x")
        tk.Label(win, text=str(notice.get("message", "")), justify="left", wraplength=420,
                 padx=14, pady=12).pack()
        if notice.get("ticket_ref"):
            tk.Label(win, text=f"Chamado: {notice['ticket_ref']}", fg="#555", padx=14).pack(anchor="w")
        buttons = tk.Frame(win, pady=10)
        buttons.pack()
        tk.Button(buttons, text="Entendi", width=12, command=win.destroy).pack(side="left", padx=6)
        tk.Button(
            buttons, text="Abrir chamado", width=14,
            command=lambda: (win.destroy(), self._ask_ticket(root, str(notice.get("ticket_ref", "")))),
        ).pack(side="left", padx=6)
        win.grab_set()
        root.wait_window(win)

    def run_gui(self, once: bool = False) -> None:
        root = tk.Tk()
        root.withdraw()

        def tick() -> None:
            try:
                self.flush_outbox()
                for notice in self.pop_notices():
                    self._show_notice(root, notice)
            except Exception:  # a GUI nunca deve morrer por causa de um aviso ruim
                self.log.exception("Erro ao processar avisos")
            if once:
                root.destroy()
            else:
                root.after(POLL_INTERVAL_MS, tick)

        root.after(300, tick)
        root.mainloop()

    def run_new_ticket_gui(self) -> None:
        root = tk.Tk()
        root.withdraw()
        self._ask_ticket(root)
        root.destroy()

    # -------------------------------------------------------------- console
    def run_console(self, once: bool = False) -> None:
        import time
        self.log.info("Notificador em modo console (Ctrl+C para sair).")
        try:
            while True:
                self.flush_outbox()
                for n in self.pop_notices():
                    print(f"\n=== [{str(n.get('priority', 'info')).upper()}] {n.get('title', '')} ===\n{n.get('message', '')}\n")
                if once:
                    return
                time.sleep(POLL_INTERVAL_MS / 1000)
        except KeyboardInterrupt:
            pass

    def run_new_ticket_console(self) -> None:
        title = input("Resumo do problema: ")
        description = input("Descrição: ")
        try:
            sent = self.submit_ticket(self.build_ticket(title, description))
        except (ValueError, OSError) as exc:
            print(f"[ERRO] {exc}")
            return
        print("Chamado enviado." if sent else "Sem conexão: chamado guardado para envio posterior.")
        self.open_helpdesk()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Notificador de chamados do PyEndpoint-RMM")
    parser.add_argument(
        "--config",
        default=os.environ.get("PYENDPOINT_AGENT_CONFIG", str(rc.default_data_dir("agent") / "agent.json")),
    )
    parser.add_argument("--new-ticket", action="store_true", help="abre o formulário de chamado e sai")
    parser.add_argument("--list", action="store_true", help="lista os chamados desta máquina e sai")
    parser.add_argument("--no-gui", action="store_true", help="força o modo console")
    parser.add_argument("--once", action="store_true", help="processa os avisos pendentes uma vez e sai")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(Path(args.config))
    except (rc.ConfigError, ValueError) as exc:
        print(f"[ERRO DE CONFIGURAÇÃO] {exc}", file=sys.stderr)
        return 2

    # O log fica na pasta do usuário: o usuário comum não grava em ProgramData\logs.
    log = rc.setup_logging("ticket_notifier", Path.home() / ".pyendpoint-rmm" / "logs", cfg["log_level"])
    notifier = Notifier(cfg, log)
    use_gui = tk is not None and not args.no_gui

    try:
        if args.list:
            for t in notifier.list_tickets():
                print(f"[{t.get('created_at')}] {t.get('title')} ({t.get('status', 'open')})")
            return 0
        if args.new_ticket:
            notifier.run_new_ticket_gui() if use_gui else notifier.run_new_ticket_console()
            return 0
        notifier.run_gui(args.once) if use_gui else notifier.run_console(args.once)
    except Exception:
        log.exception("Falha fatal no notificador")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
