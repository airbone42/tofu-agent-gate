"""Dreiwege-Merge für *.tfvars.json, wenn git zeilenweise einen Konflikt sieht.

Zwei Agenten hängen in derselben Datei je einen eigenen Eintrag an (z. B. eine Firewall-Regel
unter einem neuen Schlüssel). git meldet das als Konflikt, inhaltlich berühren sich die
Änderungen nicht. Hier wird nach Schlüsseln zusammengeführt:

- Objekte: Schlüssel für Schlüssel. Hat nur eine Seite einen Wert geändert, gilt diese Seite.
- Listen aus einfachen Werten (z. B. Zonen-Namen): wie Mengen, Hinzufügen und Entfernen beider
  Seiten werden übernommen, die Reihenfolge von main bleibt.
- Haben beide Seiten denselben Wert unterschiedlich geändert: MergeConflict mit dem Pfad.

Ausgabe im Format der main-Seite (Einrückung, sortierte Schlüssel, ensure_ascii).
"""

from __future__ import annotations

import json
from typing import Any

MISSING = object()


class MergeConflict(ValueError):
    def __init__(self, path: str):
        super().__init__(path or "/")
        self.path = path or "/"


def _scalar_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) or x is None for x in v)


def merge3(base: Any, ours: Any, theirs: Any, path: str = "") -> Any:
    """ours = main, theirs = Branch. MISSING = Schlüssel gibt es auf dieser Seite nicht."""
    if ours == theirs:
        return ours
    if base == ours:
        return theirs
    if base == theirs:
        return ours
    if isinstance(ours, dict) and isinstance(theirs, dict) and (base is MISSING or isinstance(base, dict)):
        b = base if isinstance(base, dict) else {}
        out = {}
        for key in list(ours) + [k for k in theirs if k not in ours]:
            v = merge3(b.get(key, MISSING), ours.get(key, MISSING), theirs.get(key, MISSING), f"{path}/{key}")
            if v is not MISSING:
                out[key] = v
        return out
    if _scalar_list(ours) and _scalar_list(theirs) and (base is MISSING or _scalar_list(base)):
        b = base if isinstance(base, list) else []
        removed = {json.dumps(x) for x in b if x not in theirs} | {json.dumps(x) for x in b if x not in ours}
        out = [x for x in ours if json.dumps(x) not in removed]
        out += [x for x in theirs if x not in out and json.dumps(x) not in removed]
        return out
    raise MergeConflict(path)


def style_of(text: str) -> dict:
    """Format der Datei erkennen, damit der Diff nach dem Merge klein bleibt."""
    data = json.loads(text)
    for sort_keys in (True, False):  # bereits sortiert: sortiert bleiben, neue Schlüssel einsortieren
        for ensure_ascii in (False, True):
            if json.dumps(data, indent=2, sort_keys=sort_keys, ensure_ascii=ensure_ascii) + "\n" == text:
                return {"indent": 2, "sort_keys": sort_keys, "ensure_ascii": ensure_ascii}
    return {"indent": 2, "sort_keys": False, "ensure_ascii": False}


def merge_texts(base: str | None, ours: str, theirs: str) -> str:
    """Drei Dateistände (base None = Datei auf beiden Seiten neu) zu einem Text."""
    merged = merge3(json.loads(base) if base is not None else MISSING, json.loads(ours), json.loads(theirs))
    return json.dumps(merged, **style_of(ours)) + "\n"
