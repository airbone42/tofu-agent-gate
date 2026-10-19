"""Generische Redaction für alles, was das Gate nach außen gibt.

Greift auf Text (Telegram, Logs) und auf verschachtelte Daten (Ergebnisdateien).
Werte, die OpenTofu im Plan als sensibel markiert, maskiert bereits plan.py.
Hier geht es um das, was trotzdem durchrutschen kann: Private Keys, Tokens,
Felder mit verräterischen Namen. Eine zusätzliche, domänenspezifische Funktion
lässt sich per gate.yaml (redaction.extra) einhängen.
"""

from __future__ import annotations

import base64
import importlib
import re
from collections.abc import Callable
from typing import Any

MASK = "<redacted>"

SECRET_KEY_RE = re.compile(
    r"(pass(word|phrase)?|secret|token|private[_-]?key|psk|api[_-]?key|x_passphrase|"
    r"x_password|wpa|radius_secret|preshared|credential)",
    re.I,
)

_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
    re.S,
)
# Telegram-Bot-Token, GitHub-Token, generische "Bearer"-Werte
_TOKEN_RES = [
    re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"(?i)\b(bearer|x-api-key:?)\s+[A-Za-z0-9._~+/=-]{16,}"),
]
_B64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


def _b64_private_key(chunk: str) -> bool:
    try:
        decoded = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=False)
    except ValueError:
        return False
    return b"PRIVATE KEY-----" in decoded


def redact_text(text: str) -> str:
    """Private Keys (auch base64-verpackt) und Tokens in Freitext maskieren."""
    text = _PEM_RE.sub(MASK, text)
    for rx in _TOKEN_RES:
        text = rx.sub(MASK, text)
    return _B64_RE.sub(lambda m: MASK if _b64_private_key(m.group(0)) else m.group(0), text)


def redact_data(obj: Any, _key: str | None = None) -> Any:
    """Verschachtelte Daten: Felder mit Secret-Namen maskieren, Strings prüfen."""
    if _key is not None and SECRET_KEY_RE.search(_key) and obj not in (None, "", [], {}):
        return MASK
    if isinstance(obj, dict):
        return {k: redact_data(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_data(v, _key) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def load_extra(spec: str | None) -> Callable[[str], str] | None:
    """'modul:funktion' importieren, z. B. eine domänenspezifische Redaction."""
    if not spec:
        return None
    module, _, name = spec.partition(":")
    fn = getattr(importlib.import_module(module), name)
    if not callable(fn):
        raise TypeError(f"{spec} ist nicht aufrufbar")
    return fn


def make_redactor(extra: str | None = None) -> Callable[[str], str]:
    """Kombinierte Text-Redaction für Telegram und Logs."""
    fn = load_extra(extra)

    def _redact(text: str) -> str:
        text = redact_text(text)
        return fn(text) if fn else text

    return _redact
