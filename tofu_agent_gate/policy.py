"""Policy-Engine: ordnet einen Plan einer Autonomie-Stufe zu.

Stufen: auto < approval < reject. Das Gesamtergebnis ist die strengste Stufe
aller Einzeländerungen. Die Policy-Datei liegt beim Runner, nie im Repo.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import plan as planlib

LEVELS = ("auto", "approval", "reject")
ACTIONS = {"create", "update", "delete", "replace", "import"}


class PolicyError(ValueError):
    pass


@dataclass
class Item:
    address: str
    action: str
    level: str
    reason: str


@dataclass
class Decision:
    level: str
    reasons: list[str] = field(default_factory=list)
    items: list[Item] = field(default_factory=list)
    changes: list[planlib.Change] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "reasons": self.reasons,
            "items": [vars(i) for i in self.items],
        }


def _max(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


def _subst(obj: Any, vars_: dict[str, Any]) -> Any:
    """"$name" durch vars ersetzen. Unbekannte Variablen sind ein Fehler."""
    if isinstance(obj, str) and obj.startswith("$"):
        name = obj[1:]
        if name not in vars_:
            raise PolicyError(f"Unbekannte Variable {obj}")
        return vars_[name]
    if isinstance(obj, list):
        out = []
        for v in obj:
            r = _subst(v, vars_)
            # Variablen mit Listenwert werden in Listen eingeflacht.
            out.extend(r) if isinstance(v, str) and v.startswith("$") and isinstance(r, list) else out.append(r)
        return out
    if isinstance(obj, dict):
        return {k: _subst(v, vars_) for k, v in obj.items()}
    return obj


@dataclass
class Matcher:
    """Gemeinsame Felder von Regeln und forbidden-Einträgen."""

    type: str | None = None
    address: str | None = None
    actions: list[str] | None = None
    where: dict[str, dict] | None = None
    references: list[str] | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Matcher:
        unknown = set(d) - {"type", "address", "actions", "where", "references", "level", "reason"}
        if unknown:
            raise PolicyError(f"Unbekannte Schlüssel {sorted(unknown)}")
        if d.get("actions") and not set(d["actions"]) <= ACTIONS:
            raise PolicyError(f"Unbekannte Aktion in {d['actions']}")
        for path, cond in (d.get("where") or {}).items():
            if not isinstance(cond, dict) or not set(cond) <= {"in", "not_in", "equals", "regex"}:
                raise PolicyError(f"Ungültige Bedingung für {path}: {cond}")
        refs = d.get("references")
        return cls(
            type=d.get("type"),
            address=d.get("address"),
            actions=d.get("actions"),
            where=d.get("where"),
            references=[str(r) for r in refs] if refs is not None else None,
        )

    def _cond(self, value: Any, cond: dict) -> bool:
        vals = value if isinstance(value, list) else [value]
        ok = True
        if "in" in cond:
            allowed = {str(x) for x in cond["in"]}
            ok &= bool(vals) and all(str(v) in allowed for v in vals)
        if "not_in" in cond:
            banned = {str(x) for x in cond["not_in"]}
            ok &= not any(str(v) in banned for v in vals)
        if "equals" in cond:
            ok &= value == cond["equals"]
        if "regex" in cond:
            ok &= all(re.fullmatch(cond["regex"], str(v)) is not None for v in vals)
        return ok

    def matches(self, c: planlib.Change, unknown_matches: bool) -> bool:
        """unknown_matches: Wie ein unbekannter Wert zählt (forbidden: True)."""
        if self.type and not fnmatch.fnmatchcase(c.type, self.type):
            return False
        if self.address and not fnmatch.fnmatchcase(c.address, self.address):
            return False
        if self.actions and c.action not in self.actions:
            return False
        if self.where:
            sides = c.values()
            if not sides:
                return False
            for path, cond in self.where.items():
                if c.action in ("create", "update", "replace", "import") and planlib.is_unknown(c, path):
                    if not unknown_matches:
                        return False
                    continue
                for side in sides:
                    found, val = planlib.get_path(side, path)
                    if not found or not self._cond(val, cond):
                        return False
        if self.references is not None:
            refs = set(self.references)
            hit = any(str(v) in refs for side in c.values() for v in planlib.leaves(side))
            if not hit:
                return False
        return True


@dataclass
class Rule(Matcher):
    level: str = "approval"

    @classmethod
    def from_dict(cls, d: dict) -> Rule:
        m = Matcher.from_dict(d)
        level = d.get("level", "approval")
        if level not in LEVELS:
            raise PolicyError(f"Unbekannte Stufe {level}")
        return cls(**vars(m), level=level)


@dataclass
class Policy:
    rules: list[Rule]
    forbidden: list[Matcher]
    default: str = "approval"
    max_changes: int = 10
    allow_delete: list[str] = field(default_factory=list)
    allow_replace: list[str] = field(default_factory=list)
    allowed_types: list[str] | None = None
    providers_allowed: list[str] | None = None
    providers_forbidden_args: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict) -> Policy:
        if raw.get("version") != 1:
            raise PolicyError("version: 1 erwartet")
        unknown = set(raw) - {"version", "vars", "limits", "forbidden", "rules", "default", "providers"}
        if unknown:
            raise PolicyError(f"Unbekannte Schlüssel {sorted(unknown)}")
        d = _subst({k: v for k, v in raw.items() if k != "vars"}, raw.get("vars") or {})
        limits = d.get("limits") or {}
        providers = d.get("providers") or {}
        default = d.get("default", "approval")
        if default not in LEVELS:
            raise PolicyError(f"Unbekannte Stufe {default}")
        return cls(
            rules=[Rule.from_dict(r) for r in d.get("rules") or []],
            forbidden=[Matcher.from_dict(f) for f in d.get("forbidden") or []],
            default=default,
            max_changes=int(limits.get("max_changes", 10)),
            allow_delete=list(limits.get("allow_delete") or []),
            allow_replace=list(limits.get("allow_replace") or []),
            allowed_types=limits.get("allowed_types"),
            providers_allowed=providers.get("allowed"),
            providers_forbidden_args=list(providers.get("forbidden_arguments") or []),
        )

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(yaml.safe_load(f) or {})


def _type_in(t: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(t, p) for p in patterns)


def _check_providers(plan: dict, pol: Policy) -> list[str]:
    reasons = []
    cfg = (plan.get("configuration") or {}).get("provider_config") or {}
    for key, pc in cfg.items():
        full = pc.get("full_name", key)
        if pol.providers_allowed is not None and full not in pol.providers_allowed:
            reasons.append(f"Provider {full} nicht erlaubt")
        for arg in pol.providers_forbidden_args:
            if arg in (pc.get("expressions") or {}):
                reasons.append(f"Provider {full}: Argument {arg} darf nicht in der Konfiguration stehen")
    # Provisioner sind nie erlaubt (Code-Ausführung im Runner).
    for res in _config_resources(plan.get("configuration") or {}):
        if res.get("provisioners"):
            reasons.append(f"Provisioner in {res.get('address')} nicht erlaubt")
    return reasons


def _config_resources(cfg: dict):
    root = cfg.get("root_module") or {}
    stack = [root]
    while stack:
        mod = stack.pop()
        yield from mod.get("resources") or []
        for call in (mod.get("module_calls") or {}).values():
            stack.append(call.get("module") or {})


def classify(plan: dict, pol: Policy, rollback: bool = False) -> Decision:
    """Plan bewerten. Im Rollback-Modus zählen nur forbidden und Provider."""
    dec = Decision(level="auto")

    if plan.get("errored"):
        dec.level = "reject"
        dec.reasons.append("Plan enthält Fehler")

    for r in _check_providers(plan, pol):
        dec.level = "reject"
        dec.reasons.append(r)

    chs = planlib.changes(plan)
    dec.changes = chs

    if not rollback and len(chs) > pol.max_changes:
        dec.level = "reject"
        dec.reasons.append(f"{len(chs)} Änderungen, erlaubt sind {pol.max_changes}")

    for c in chs:
        level, reason = _classify_change(c, pol, rollback)
        dec.items.append(Item(c.address, c.action, level, reason))
        dec.level = _max(dec.level, level)
        if level == "reject":
            dec.reasons.append(f"{c.address}: {reason}")

    if not chs and dec.level == "auto":
        dec.reasons.append("Keine Änderungen")
    return dec


def _classify_change(c: planlib.Change, pol: Policy, rollback: bool) -> tuple[str, str]:
    if c.mode != "managed":
        return "reject", f"unerwarteter Modus {c.mode}"
    if c.action not in ACTIONS:
        return "reject", f"unbekannte Aktion {c.action}"
    for i, f in enumerate(pol.forbidden):
        if f.matches(c, unknown_matches=True):
            return "reject", f"forbidden (Eintrag {i + 1})"
    if rollback:
        return "auto", "Rollback, vorab genehmigt"
    if pol.allowed_types is not None and not _type_in(c.type, pol.allowed_types):
        return "reject", f"Typ {c.type} nicht in allowed_types"
    if c.action == "delete" and not _type_in(c.type, pol.allow_delete):
        return "reject", "delete für diesen Typ nicht erlaubt"
    if c.action == "replace" and not _type_in(c.type, pol.allow_replace):
        return "reject", "replace für diesen Typ nicht erlaubt"
    for i, r in enumerate(pol.rules):
        if r.matches(c, unknown_matches=False):
            return r.level, f"Regel {i + 1}"
    return pol.default, "Default"
