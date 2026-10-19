"""Dünner Client für die Telegram-Bot-API.

Der Transport ist austauschbar, damit Tests ohne Netz laufen. Das Bot-Token
taucht nie in Exceptions, Logs oder repr auf.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "https://api.telegram.org"

# transport(method, params) -> vollständige API-Antwort inkl. "ok"
Transport = Callable[[str, dict[str, Any]], dict[str, Any]]

_METHOD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TOKEN_MASK = "<token>"


class TelegramError(Exception):
    """Fehler der Bot-API oder der Übertragung. Enthält nie das Token."""

    def __init__(
        self,
        message: str,
        *,
        method: str | None = None,
        error_code: int | None = None,
        description: str | None = None,
        retry_after: int | float | None = None,
    ) -> None:
        super().__init__(message)
        self.method = method
        self.error_code = error_code
        self.description = description
        self.retry_after = retry_after


class TelegramConfigError(ValueError):
    """Ungültige oder unvollständige Telegram-Konfiguration."""


class TelegramApi:
    """Aufrufe der Bot-API: call(method, **params) liefert das Feld "result"."""

    def __init__(
        self,
        token: str,
        base_url: str = DEFAULT_BASE_URL,
        transport: Transport | None = None,
        timeout: float = 60,
    ) -> None:
        if not isinstance(token, str) or not token.strip():
            raise TelegramConfigError("Telegram-Token fehlt")
        self._token = token.strip()
        self.base_url = base_url.rstrip("/")
        self._transport = transport
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"TelegramApi(base_url={self.base_url!r}, token=<redacted>)"

    __str__ = __repr__

    def _scrub(self, text: object) -> str:
        """Token (roh und URL-kodiert) aus einem Text entfernen."""
        text = str(text)
        for variant in {self._token, urllib.parse.quote(self._token, safe="")}:
            text = text.replace(variant, _TOKEN_MASK)
        return text

    def call(self, method: str, **params: Any) -> Any:
        """Methode aufrufen. Parameter mit Wert None werden weggelassen."""
        if not _METHOD_RE.fullmatch(method):
            raise TelegramError("ungültiger Methodenname", method=None)
        params = {k: v for k, v in params.items() if v is not None}
        transport = self._transport or self._http
        failure: str | None = None
        try:
            resp = transport(method, params)
        except TelegramError as exc:
            failure = self._scrub(exc)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            failure = f"{method}: Übertragungsfehler ({type(exc).__name__}: {self._scrub(exc)})"
        # Außerhalb des except-Blocks werfen, damit keine Ursache mit Token-URL anhängt
        if failure is not None:
            raise TelegramError(failure, method=method)
        if not isinstance(resp, dict):
            raise TelegramError(f"{method}: ungültige Antwort", method=method)
        if not resp.get("ok"):
            desc = self._scrub(resp.get("description") or "unbekannter Fehler")
            extra = resp.get("parameters") if isinstance(resp.get("parameters"), dict) else {}
            code = resp.get("error_code")
            raise TelegramError(
                f"{method}: {desc}",
                method=method,
                error_code=code if isinstance(code, int) else None,
                description=desc,
                retry_after=extra.get("retry_after"),
            )
        return resp.get("result")

    def _http(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Default-Transport: POST JSON per urllib, TLS mit Standard-Verifikation."""
        url = f"{self.base_url}/bot{self._token}/{method}"
        body = json.dumps(params).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        timeout = self.timeout
        if method == "getUpdates":
            # Long Polling: HTTP-Timeout muss über dem Poll-Timeout liegen
            timeout = max(timeout, float(params.get("timeout", 0)) + 10)
        status = 200
        try:
            with urllib.request.urlopen(
                req, timeout=timeout, context=ssl.create_default_context()
            ) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            # Telegram liefert auch bei 4xx/5xx ein JSON mit description
            status = exc.code
            try:
                raw = exc.read()
            finally:
                exc.close()
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise ValueError(f"keine JSON-Antwort (HTTP {status})")
        return data


def load_env_file(path: str | Path) -> dict[str, str]:
    """KEY=VALUE-Datei lesen: Kommentare, optionales export, Anführungszeichen.

    Fehlermeldungen nennen nur die Zeilennummer, nie den Inhalt.
    """
    result: dict[str, str] = {}
    text = Path(path).read_text(encoding="utf-8-sig")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not _KEY_RE.fullmatch(key):
            raise TelegramConfigError(f"{path}: Zeile {lineno} ist kein KEY=VALUE")
        result[key] = _parse_value(value.strip(), path, lineno)
    return result


_DQ_ESCAPES = {"n": "\n", "t": "\t", '"': '"', "\\": "\\", "$": "$", "`": "`"}


def _parse_value(value: str, path: str | Path, lineno: int) -> str:
    if value[:1] in ("'", '"'):
        quote = value[0]
        out: list[str] = []
        i = 1
        while i < len(value):
            ch = value[i]
            if quote == '"' and ch == "\\" and i + 1 < len(value):
                nxt = value[i + 1]
                out.append(_DQ_ESCAPES.get(nxt, "\\" + nxt))
                i += 2
                continue
            if ch == quote:
                rest = value[i + 1 :].strip()
                if rest and not rest.startswith("#"):
                    raise TelegramConfigError(
                        f"{path}: Zeile {lineno}: Zeichen nach dem schließenden Anführungszeichen"
                    )
                return "".join(out)
            out.append(ch)
            i += 1
        raise TelegramConfigError(f"{path}: Zeile {lineno}: Anführungszeichen nicht geschlossen")
    # ohne Anführungszeichen: Kommentar beginnt bei Leerraum + '#'
    m = re.search(r"\s#", value)
    if m:
        value = value[: m.start()]
    return value.strip()


@dataclass(frozen=True)
class TelegramConfig:
    """Token, Owner und Chat aus der Env-Datei. Token nicht im repr."""

    token: str = field(repr=False)
    owner_id: int
    chat_id: int

    def api(self, **kwargs: Any) -> TelegramApi:
        """TelegramApi mit diesem Token, kwargs wie bei TelegramApi."""
        return TelegramApi(self.token, **kwargs)


def _int_value(env: dict[str, str], key: str, path: str | Path) -> int:
    try:
        return int(env[key])
    except ValueError:
        pass
    raise TelegramConfigError(f"{path}: {key} ist keine Ganzzahl")


def from_env_file(path: str | Path) -> TelegramConfig:
    """TELEGRAM_BOT_TOKEN, TELEGRAM_OWNER_ID und TELEGRAM_CHAT_ID lesen."""
    env = load_env_file(path)
    keys = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_OWNER_ID", "TELEGRAM_CHAT_ID")
    missing = [k for k in keys if not env.get(k, "").strip()]
    if missing:
        raise TelegramConfigError(f"{path}: fehlende Werte: {', '.join(missing)}")
    return TelegramConfig(
        token=env["TELEGRAM_BOT_TOKEN"].strip(),
        owner_id=_int_value(env, "TELEGRAM_OWNER_ID", path),
        chat_id=_int_value(env, "TELEGRAM_CHAT_ID", path),
    )
