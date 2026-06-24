"""Small utility helpers for serialization, randomness and integrity."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


def now_ts() -> int:
    return int(time.time())


def random_bytes(size: int) -> bytes:
    return secrets.token_bytes(size)


def random_nonce_hex(size: int = 8) -> str:
    return secrets.token_hex(size)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def json_dumps_canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def json_loads_bytes(data: bytes) -> dict[str, Any]:
    return json.loads(data.decode("utf-8"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
