# -*- coding: utf-8 -*-
"""
rmm_common.py — utilitários compartilhados do PyEndpoint-RMM.

Contém tudo o que agente, painel ADM e notificador precisam em comum:

* logging com rotação de arquivos;
* leitura/escrita atômica de JSON (seguro em diretórios de rede);
* assinatura e verificação de comandos com Ed25519;
* "keystore" da chave privada do ADM, cifrada com senha (scrypt + AES-GCM);
* validação de identificadores (evita path traversal).

Modelo de confiança: somente o painel ADM possui a chave PRIVADA. Os agentes
guardam apenas a chave PÚBLICA, então o comprometimento de um agente (ou do
diretório compartilhado) não permite forjar comandos.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__version__ = "0.1.0"

# Identificadores (agent_id, nomes de payload, ids de comando) só podem conter
# estes caracteres. Isso elimina "..", barras e outros truques de caminho.
ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
KEYSTORE_AAD = b"pyendpoint-rmm-keystore-v1"
MIN_PASSWORD_LEN = 12


# --------------------------------------------------------------------------- #
# Exceções
# --------------------------------------------------------------------------- #
class SecurityError(Exception):
    """Falha de autenticação, assinatura ou política de segurança."""


class ConfigError(Exception):
    """Configuração ausente ou inválida."""


# --------------------------------------------------------------------------- #
# Helpers gerais
# --------------------------------------------------------------------------- #
def safe_id(value: Any) -> str:
    """Valida um identificador e o devolve; levanta ValueError se for inseguro."""
    if (
        not isinstance(value, str)
        or not ID_PATTERN.fullmatch(value)
        or value in (".", "..")
    ):
        raise ValueError(f"Identificador inválido: {value!r}")
    return value


def now_ts() -> int:
    """Timestamp UNIX (UTC) em segundos."""
    return int(time.time())


def iso_utc(ts: float | None = None) -> str:
    """Formata um timestamp como ISO-8601 em UTC."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


def default_data_dir(role: str = "agent") -> Path:
    """Diretório local padrão de dados (config, logs, estado) por papel."""
    if os.name == "nt":
        if role == "agent":
            return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "PyEndpointRMM"
        return Path(os.environ.get("APPDATA", str(Path.home()))) / "PyEndpointRMM-Admin"
    if role == "agent":
        if os.geteuid() == 0:
            return Path("/var/lib/pyendpoint-rmm")
        return Path.home() / ".pyendpoint-rmm"
    return Path.home() / ".pyendpoint-rmm-admin"


def setup_logging(name: str, log_dir: Path, level: str = "INFO") -> logging.Logger:
    """Cria um logger com saída no console e em arquivo rotativo (2 MB x 5)."""
    logger = logging.getLogger(name)
    if logger.handlers:  # já configurado
        return logger
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)
    try:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            Path(log_dir) / f"{name}.log",
            maxBytes=2_000_000,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:  # sem permissão de escrita: segue só com o console
        logger.warning("Log em arquivo indisponível (%s); usando apenas console.", exc)
    return logger


def atomic_write_json(path: Path, data: Any) -> None:
    """Grava JSON de forma atômica: escreve em .part e renomeia.

    Leitores nunca enxergam um arquivo pela metade, e a extensão .part garante
    que ele não seja confundido com um comando/resultado válido (*.json).
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def read_json(path: Path) -> Any:
    """Lê um arquivo JSON (UTF-8, tolerando BOM do Bloco de Notas)."""
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def load_json_config(path: Path) -> dict[str, Any]:
    """Carrega um JSON de configuração ignorando chaves de comentário ("_...")."""
    try:
        raw = read_json(path)
    except FileNotFoundError as exc:
        raise ConfigError(f"Arquivo de configuração não encontrado: {path}") from exc
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Não foi possível ler {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} deve conter um objeto JSON.")
    return {k: v for k, v in raw.items() if not str(k).startswith("_")}


def sha256_file(path: Path) -> str:
    """SHA-256 (hex) de um arquivo, lido em blocos."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Assinatura de comandos
# --------------------------------------------------------------------------- #
def canonical_bytes(obj: Any) -> bytes:
    """Serialização canônica (chaves ordenadas, sem espaços) usada na assinatura."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_command(private_key: Ed25519PrivateKey, command: dict[str, Any]) -> dict[str, Any]:
    """Assina um comando e devolve o 'envelope' pronto para gravar em disco."""
    signature = private_key.sign(canonical_bytes(command))
    return {"command": command, "signature": base64.b64encode(signature).decode("ascii")}


def verify_envelope(public_key: Ed25519PublicKey, envelope: Any) -> dict[str, Any]:
    """Valida a assinatura do envelope e devolve o comando; senão SecurityError."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("command"), dict):
        raise SecurityError("Envelope malformado")
    try:
        signature = base64.b64decode(str(envelope.get("signature", "")), validate=True)
        public_key.verify(signature, canonical_bytes(envelope["command"]))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise SecurityError("Assinatura inválida") from exc
    return envelope["command"]


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Carrega a chave pública do ADM (PEM)."""
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Chave pública inválida ou ausente em {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ConfigError("A chave pública precisa ser Ed25519.")
    return key


# --------------------------------------------------------------------------- #
# Keystore da chave privada do ADM (cifrada por senha)
# --------------------------------------------------------------------------- #
def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def _derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def create_keystore(path: Path, password: str) -> bytes:
    """Gera um par Ed25519, grava a privada cifrada em `path` e devolve a pública (PEM)."""
    if len(password) < MIN_PASSWORD_LEN:
        raise SecurityError(f"A senha deve ter ao menos {MIN_PASSWORD_LEN} caracteres.")
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    kdf = {"name": "scrypt", "n": 2**15, "r": 8, "p": 1, "salt": _b64e(os.urandom(16))}
    nonce = os.urandom(12)
    key = _derive_key(password, _b64d(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])
    ciphertext = AESGCM(key).encrypt(nonce, raw, KEYSTORE_AAD)
    atomic_write_json(
        Path(path),
        {"version": 1, "kdf": kdf, "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)},
    )
    if os.name != "nt":
        os.chmod(path, 0o600)
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def unlock_keystore(path: Path, password: str) -> Ed25519PrivateKey:
    """Decifra a chave privada do ADM. Senha errada → SecurityError."""
    try:
        data = read_json(path)
        kdf = data["kdf"]
        key = _derive_key(
            password, _b64d(kdf["salt"]), int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        )
        nonce, ciphertext = _b64d(data["nonce"]), _b64d(data["ciphertext"])
    except (OSError, KeyError, ValueError, TypeError) as exc:
        raise SecurityError(f"Keystore ilegível ou corrompido: {exc}") from exc
    try:
        raw = AESGCM(key).decrypt(nonce, ciphertext, KEYSTORE_AAD)
    except InvalidTag as exc:
        raise SecurityError("Senha incorreta") from exc
    return Ed25519PrivateKey.from_private_bytes(raw)
