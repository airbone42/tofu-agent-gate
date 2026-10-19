"""Kommandozeile: python -m tofu_agent_gate <befehl>."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import config as configlib
from . import plan as planlib
from .deadman import Systemd
from .gitops import Git
from .hooks import Hooks
from .policy import Policy, classify
from .redact import make_redactor
from .runner import Deps, Run, Runner
from .tofu import Tofu


def build_approver(cfg: configlib.Config, redact):
    if not cfg.telegram_env or not cfg.telegram_env.exists():
        return None
    from .approve import Approver
    from .telegram import from_env_file

    tg = from_env_file(cfg.telegram_env)
    return Approver(tg.api(), tg.owner_id, tg.chat_id, cfg.state_dir / "approvals", redact=redact)


def build_runner(cfg: configlib.Config) -> Runner:
    redact = make_redactor(cfg.redaction_extra)
    deps = Deps(
        git=Git(cfg),
        tofu_factory=lambda wd: Tofu(cfg, wd),
        hooks=Hooks(cfg),
        policy=Policy.load(cfg.policy),
        deadman=Systemd(cfg),
        approver=build_approver(cfg, redact),
        redact=redact,
    )
    return Runner(cfg, deps)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tofu-agent-gate")
    ap.add_argument("--config", help="Pfad zu gate.yaml (sonst GATE_CONFIG oder Default)")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run-once", help="Neue desired/*-Branches abarbeiten")
    rb = sub.add_parser("rollback", help="Lauf zurückrollen (Dead-Man-Timer)")
    rb.add_argument("run_id")
    cl = sub.add_parser("classify", help="Plan-JSON gegen die Policy prüfen, ohne etwas zu tun")
    cl.add_argument("plan_json")
    cl.add_argument("--policy", help="statt der Policy aus gate.yaml")
    cl.add_argument("--rollback", action="store_true")
    st = sub.add_parser("status", help="Letzte Läufe anzeigen")
    st.add_argument("-n", type=int, default=10)
    sub.add_parser("check-config", help="gate.yaml und Policy laden und prüfen")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.cmd == "classify" and args.policy:
        pol = Policy.load(args.policy)
    else:
        cfg = configlib.load(args.config)
        pol = None

    if args.cmd == "classify":
        pol = pol or Policy.load(cfg.policy)
        plan_json = planlib.load(args.plan_json)
        dec = classify(plan_json, pol, rollback=args.rollback)
        print(json.dumps(dec.to_dict(), indent=2, ensure_ascii=False))
        print(planlib.summarize(dec.changes), file=sys.stderr)
        return {"auto": 0, "approval": 10, "reject": 20}[dec.level]

    if args.cmd == "check-config":
        Policy.load(cfg.policy)
        print(f"Konfiguration ok: {cfg.source}")
        return 0

    if args.cmd == "status":
        runs = sorted(cfg.runs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)[-args.n:]
        for p in runs:
            r = Run.load(cfg.runs_dir, p.stem)
            print(f"{r.run_id}  {r.status:16} {r.level or '-':9} {r.branch}")
        return 0

    runner = build_runner(cfg)
    if args.cmd == "run-once":
        results = runner.run_once()
        bad = [r for r in results if r.status in ("error", "rollback_failed")]
        return 1 if bad else 0
    if args.cmd == "rollback":
        r = runner.rollback(args.run_id)
        return 0 if r.status in ("rolled_back", "applied", "rejected", "declined", "noop") else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
