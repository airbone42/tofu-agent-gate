"""Baut Plan-JSONs wie `tofu show -json` für Tests. Generische Testdaten."""

from __future__ import annotations

import copy

ZONES = {"lan": "a1" * 12, "iot": "b2" * 12, "guest": "c3" * 12, "isolated": "d4" * 12, "mgmt": "e5" * 12}
PROVIDER = "registry.opentofu.org/ubiquiti-community/unifi"


def policy_obj(pid: str, name: str, src: str, dst: str, action: str = "ALLOW", **extra) -> dict:
    obj = {
        "id": pid,
        "name": name,
        "action": action,
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": ZONES[src], "matching_target": "ANY"},
        "destination": {"zone_id": ZONES[dst], "matching_target": "ANY"},
    }
    obj.update(extra)
    return obj


def dns_obj(rid: str, name: str, value: str = "198.51.100.10") -> dict:
    return {"id": rid, "name": name, "record_type": "A", "value": value, "enabled": True, "ttl": None}


def rc(address: str, actions: list[str], before=None, after=None, *, rtype=None, mode="managed",
       after_unknown=None, after_sensitive=None, importing=None) -> dict:
    rtype = rtype or address.split(".")[0]
    change = {
        "actions": actions,
        "before": copy.deepcopy(before),
        "after": copy.deepcopy(after),
        "after_unknown": after_unknown or {},
        "before_sensitive": False,
        "after_sensitive": after_sensitive or False,
    }
    if importing:
        change["importing"] = {"id": importing}
    return {
        "address": address,
        "mode": mode,
        "type": rtype,
        "name": address.split(".")[1].split("[")[0],
        "provider_name": PROVIDER,
        "change": change,
    }


def plan(*changes: dict, provider_expressions: dict | None = None, provisioners: bool = False,
         errored: bool = False) -> dict:
    res_cfg = []
    if provisioners:
        res_cfg.append({"address": "terraform_data.x", "provisioners": [{"type": "local-exec"}]})
    return {
        "format_version": "1.2",
        "errored": errored,
        "resource_changes": list(changes),
        "configuration": {
            "provider_config": {
                "unifi": {"name": "unifi", "full_name": PROVIDER, "expressions": provider_expressions or {}}
            },
            "root_module": {"resources": res_cfg},
        },
    }
