# -*- coding: utf-8 -*-
"""Testes de ponta a ponta (ADM → diretório compartilhado → agente) em modo seguro.

Executar:  python -m unittest discover -s tests -v
"""
import hashlib
import logging
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agent as agent_mod  # noqa: E402
import dashboard  # noqa: E402
import rmm_common as rc  # noqa: E402

AGENT_ID = "PC-TESTE"
PASSWORD = "senha-de-teste-bem-longa"


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.root = root
        cls.shared = root / "share"
        for sub in (f"commands/{AGENT_ID}", "commands/_all", "results", "heartbeats", "payloads", "tickets"):
            (cls.shared / sub).mkdir(parents=True)

        pub = rc.create_keystore(root / "admin" / "admin_key.json", PASSWORD)
        (root / "admin_pub.pem").write_bytes(pub)
        cls.key = rc.unlock_keystore(root / "admin" / "admin_key.json", PASSWORD)

        # Chave de um atacante (não confiada pelo agente).
        rc.create_keystore(root / "evil" / "admin_key.json", PASSWORD)
        cls.evil_key = rc.unlock_keystore(root / "evil" / "admin_key.json", PASSWORD)

        cls.apps = root / "apps"
        cls.apps.mkdir()
        cfg = {
            **agent_mod.DEFAULT_CONFIG,
            "agent_id": AGENT_ID,
            "shared_dir": str(cls.shared),
            "data_dir": str(root / "data"),
            "admin_public_key": str(root / "admin_pub.pem"),
            "allowed_update_dirs": [str(cls.apps)],
            "dry_run": True,
        }
        log = logging.getLogger("test-agent")
        log.addHandler(logging.NullHandler())
        cls.agent = agent_mod.Agent(cfg, log)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # ------------------------------------------------------------ helpers
    def send(self, ctype, params=None, target=AGENT_ID, key=None, **kwargs):
        envelope = dashboard.build_command(key or self.key, ctype, target, params, issuer="teste", **kwargs)
        path = dashboard.write_envelope(self.shared, envelope)
        return envelope["command"]["id"], path

    def result(self, command_id):
        path = self.shared / "results" / AGENT_ID / f"{command_id}.json"
        return rc.read_json(path) if path.exists() else None

    def run_agent(self):
        self.agent.process_commands()

    def payload(self, name, content=b"print('ok')\n"):
        (self.shared / "payloads" / name).write_bytes(content)
        return hashlib.sha256(content).hexdigest()

    # -------------------------------------------------------------- testes
    def test_ping_ok(self):
        cid, _ = self.send("ping")
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "ok")

    def test_broadcast_reaches_agent(self):
        cid, _ = self.send("ping", target="*")
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "ok")

    def test_replay_is_ignored(self):
        cid, _ = self.send("ping")
        self.run_agent()
        (self.shared / "results" / AGENT_ID / f"{cid}.json").unlink()
        self.run_agent()  # o mesmo arquivo ainda está lá
        self.assertIsNone(self.result(cid), "comando repetido não pode ser reexecutado")

    def test_tampered_command_is_rejected(self):
        cid, path = self.send("ping")
        envelope = rc.read_json(path)
        envelope["command"]["type"] = "reboot"  # adulteração após a assinatura
        rc.atomic_write_json(path, envelope)
        self.run_agent()
        self.assertIsNone(self.result(cid))

    def test_unknown_signer_is_rejected(self):
        cid, _ = self.send("reboot", key=self.evil_key)
        self.run_agent()
        self.assertIsNone(self.result(cid))

    def test_expired_command_is_ignored(self):
        cid, _ = self.send("ping", now=rc.now_ts() - 1000, ttl=60)
        self.run_agent()
        self.assertIsNone(self.result(cid))

    def test_excessive_ttl_is_rejected(self):
        cid, _ = self.send("ping", ttl=10 * 24 * 3600)
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "rejected")

    def test_wrong_target_in_folder_is_rejected(self):
        cid, path = self.send("ping", target="OUTRO-PC")
        # Move para a pasta do agente: o alvo assinado não confere com a pasta.
        moved = self.shared / "commands" / AGENT_ID / path.name
        path.rename(moved)
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "rejected")

    def test_reboot_dry_run_warns_user(self):
        cid, _ = self.send("reboot", {"delay_sec": 5, "message": "Manutenção"})
        spool = Path(self.agent.cfg["data_dir"]) / "spool" / "notify"
        before = len(list(spool.glob("*.json"))) if spool.exists() else 0
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "ok")
        self.assertEqual(len(list(spool.glob("*.json"))), before + 1)

    def test_script_with_valid_hash_runs_in_dry_run(self):
        sha = self.payload("ok.py")
        cid, _ = self.send("run_script", {"name": "ok.py", "sha256": sha, "args": ["--x=1"]})
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "ok")

    def test_script_with_wrong_hash_is_rejected(self):
        self.payload("tampered.py")
        cid, _ = self.send("run_script", {"name": "tampered.py", "sha256": "0" * 64})
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "rejected")

    def test_script_path_traversal_is_rejected(self):
        cid, _ = self.send("run_script", {"name": "../evil.py", "sha256": "0" * 64})
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "rejected")

    def test_script_shell_metacharacters_are_rejected(self):
        sha = self.payload("args.py")
        cid, _ = self.send("run_script", {"name": "args.py", "sha256": sha, "args": ["a&calc"]})
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "rejected")

    def test_script_extension_not_allowed(self):
        sha = self.payload("tool.exe", b"MZ")
        cid, _ = self.send("run_script", {"name": "tool.exe", "sha256": sha})
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "rejected")

    def test_update_outside_allowed_dir_is_rejected(self):
        sha = self.payload("app.bin", b"v2")
        cid, _ = self.send("update", {"name": "app.bin", "sha256": sha, "dest": str(self.root / "fora" / "app.bin")})
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "rejected")

    def test_update_traversal_out_of_allowed_dir_is_rejected(self):
        sha = self.payload("app2.bin", b"v2")
        dest = str(self.apps / ".." / "escape.bin")
        cid, _ = self.send("update", {"name": "app2.bin", "sha256": sha, "dest": dest})
        self.run_agent()
        self.assertEqual(self.result(cid)["status"], "rejected")

    def test_update_real_replace_with_backup(self):
        # Em dry_run o update não grava; testa o caminho real com outra instância.
        cfg = {**self.agent.cfg, "dry_run": False}
        log = logging.getLogger("test-agent-real")
        log.addHandler(logging.NullHandler())
        real = agent_mod.Agent(cfg, log)
        target = self.apps / "tool.dat"
        target.write_bytes(b"v1")
        sha = self.payload("tool.dat", b"v2")
        cid, _ = self.send("update", {"name": "tool.dat", "sha256": sha, "dest": str(target)})
        real.process_commands()
        self.assertEqual(self.result(cid)["status"], "ok")
        self.assertEqual(target.read_bytes(), b"v2")
        self.assertEqual((self.apps / "tool.dat.bak").read_bytes(), b"v1")

    def test_heartbeat_is_written(self):
        self.agent.write_heartbeat()
        hb = rc.read_json(self.shared / "heartbeats" / f"{AGENT_ID}.json")
        self.assertEqual(hb["agent_id"], AGENT_ID)
        self.assertIn("timestamp", hb)

    def test_keystore_wrong_password(self):
        with self.assertRaises(rc.SecurityError):
            rc.unlock_keystore(self.root / "admin" / "admin_key.json", "senha-errada-123456")

    def test_safe_id(self):
        for bad in ("..", ".", "a/b", "a\\b", "", "x" * 65, "c:evil"):
            with self.assertRaises(ValueError):
                rc.safe_id(bad)
        self.assertEqual(rc.safe_id("PC-01.empresa_local"), "PC-01.empresa_local")


if __name__ == "__main__":
    unittest.main()
