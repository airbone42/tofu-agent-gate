"""Plan-JSON von `tofu show -json` lesen und zusammenfassen."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SENSITIVE = "<sensitive>"
UNKNOWN = "<unknown>"


@dataclass
class Change:
    address: str
    type: str
    mode: str
    provider: str
    action: str  # create, update, delete, replace, import, read, no-op
    before: Any
    after: Any
    after_unknown: Any = field(default_factory=dict)
    before_sensitive: Any = False
    after_sensitive: Any = False
    importing: bool = False

    def values(self) -> list[Any]:
        """Seiten, die für Prüfungen zählen (vorher und/oder nachher)."""
        sides = []
        if self.action in ("update", "replace", "delete", "import"):
            sides.append(self.before if self.before is not None else self.after)
        if self.action in ("create", "update", "replace", "import"):
            sides.append(self.after)
        return [s for s in sides if s is not None]


def action_name(actions: list[str], importing: bool = False) -> str:
    a = list(actions)
    if a in (["delete", "create"], ["create", "delete"]):
        return "replace"
    if a == ["no-op"]:
        return "import" if importing else "no-op"
    if len(a) == 1:
        return a[0]
    return "+".join(a)


def load(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def file_hash(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def changes(plan: dict, include_noop: bool = False) -> list[Change]:
    """Alle Ressourcenänderungen, ohne reine No-ops und ohne Datenquellen-Reads."""
    out = []
    for rc in plan.get("resource_changes") or []:
        ch = rc.get("change") or {}
        act = action_name(ch.get("actions") or [], bool(ch.get("importing")))
        if not include_noop and act in ("no-op", "read"):
            continue
        out.append(
            Change(
                address=rc.get("address", "?"),
                type=rc.get("type", "?"),
                mode=rc.get("mode", "?"),
                provider=rc.get("provider_name", ""),
                action=act,
                before=ch.get("before"),
                after=ch.get("after"),
                after_unknown=ch.get("after_unknown") or {},
                before_sensitive=ch.get("before_sensitive", False),
                after_sensitive=ch.get("after_sensitive", False),
                importing=bool(ch.get("importing")),
            )
        )
    return out


def mask(value: Any, sensitive: Any, unknown: Any = None) -> Any:
    """Sensible Werte durch Platzhalter ersetzen, unbekannte markieren."""
    if sensitive is True:
        return SENSITIVE
    if unknown is True:
        return UNKNOWN
    if isinstance(value, dict):
        s = sensitive if isinstance(sensitive, dict) else {}
        u = unknown if isinstance(unknown, dict) else {}
        keys = set(value) | {k for k, v in u.items() if v is True}
        return {k: mask(value.get(k), s.get(k), u.get(k)) for k in sorted(keys)}
    if isinstance(value, list):
        s = sensitive if isinstance(sensitive, list) else []
        u = unknown if isinstance(unknown, list) else []
        return [
            mask(v, s[i] if i < len(s) else None, u[i] if i < len(u) else None)
            for i, v in enumerate(value)
        ]
    return value


def get_path(obj: Any, path: str) -> tuple[bool, Any]:
    """Wert per Punkt-Pfad holen. (gefunden, wert). Listen per Index."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return False, None
    return True, cur


def is_unknown(change: Change, path: str) -> bool:
    found, val = get_path(change.after_unknown, path)
    if found and val is True:
        return True
    # Ein unbekannter Elternknoten macht auch das Kind unbekannt.
    parts = path.split(".")
    for i in range(1, len(parts)):
        found, val = get_path(change.after_unknown, ".".join(parts[:i]))
        if found and val is True:
            return True
    return False


def leaves(obj: Any):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from leaves(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from leaves(v)
    else:
        yield obj


def _flat(obj: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            out.update(_flat(v, f"{prefix}{k}."))
        return out
    return {prefix[:-1]: obj} if prefix else {"": obj}


def diff_fields(change: Change) -> list[tuple[str, Any, Any]]:
    """Geänderte Felder (Pfad, vorher, nachher), sensible Werte maskiert."""
    before = _flat(mask(change.before or {}, change.before_sensitive))
    after = _flat(mask(change.after or {}, change.after_sensitive, change.after_unknown))
    # Rohwerte nur zum Erkennen geänderter sensibler Felder, nie zur Ausgabe.
    raw_b, raw_a = _flat(change.before or {}), _flat(change.after or {})
    out = []
    for key in sorted(set(before) | set(after)):
        b, a = before.get(key), after.get(key)
        if SENSITIVE in (b, a):
            if raw_b.get(key) != raw_a.get(key):
                out.append((key, b, a))
            continue
        if b != a and not (b in (None, [], "") and a in (None, [], "")):
            out.append((key, b, a))
    return out


def label(change: Change) -> str:
    """Kurzer Name des Objekts für Menschen (name-Attribut, falls vorhanden)."""
    for side in (change.after, change.before):
        if isinstance(side, dict) and isinstance(side.get("name"), str):
            return side["name"]
    return ""


def summarize(chs: list[Change], max_fields: int = 8) -> str:
    """Kompakte Textzusammenfassung, erzeugt aus dem Plan, nicht vom Agenten."""
    if not chs:
        return "Keine Änderungen."
    lines = []
    for c in chs:
        name = label(c)
        lines.append(f"{c.action} {c.address}" + (f" ({name})" if name else ""))
        if c.action in ("update", "replace"):
            all_fields = diff_fields(c)
            # Erst nach dem Apply bekannte Werte (z. B. index) nur zählen.
            fields = [f for f in all_fields if f[2] != UNKNOWN]
            computed = len(all_fields) - len(fields)
            for key, b, a in fields[:max_fields]:
                lines.append(f"  {key}: {_short(b)} -> {_short(a)}")
            if len(fields) > max_fields:
                lines.append(f"  ... {len(fields) - max_fields} weitere Felder")
            if computed:
                lines.append(f"  ({computed} Felder werden erst beim Apply berechnet)")
        elif c.action == "create":
            fields = [f for f in diff_fields(c) if f[2] not in (None, "", [], False)]
            for key, _, a in fields[:max_fields]:
                lines.append(f"  {key} = {_short(a)}")
    return "\n".join(lines)


def _short(v: Any, n: int = 60) -> str:
    s = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
    return s if len(s) <= n else s[: n - 3] + "..."
