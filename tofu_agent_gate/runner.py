"""Ablauf je Agenten-Branch: Plan, Policy, Freigabe, Apply, Prüfung, Rollback."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from . import plan as planlib
from . import proc
from .config import Config
from .gitops import Branch, Git, GitError
from .hooks import Hooks
from .policy import Decision, Policy, classify
from .redact import redact_data

log = logging.getLogger(__name__)

# Abgeschlossene Läufe, deren Arbeitsordner weg darf. Nicht dabei: started, applying,
# rolling_back (Dead-Man braucht den Ordner) und rollback_failed (Diagnose).
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}-")
# Erste Zeile der STOP-Datei, die ein fehlgeschlagener Rollback schreibt (recover erkennt sie daran).
STOP_RE = re.compile(r"^Rollback (\S+) fehlgeschlagen")
FINISHED = {"applied", "applied_unmerged", "noop", "rejected", "declined", "rolled_back", "error", "discarded"}


def short_reason(text: str | None, limit: int = 300) -> str:
    """Technische Fehlertexte auf eine verständliche Zeile kürzen."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return ""
    head = lines[0].rstrip(":")
    api = next((m.group(0) for ln in lines if (m := re.search(r"api\.err\.\w+", ln))), None)
    if api:
        out = f"{head}: UniFi lehnt ab ({api})"
    else:
        err = next((ln for ln in lines if ln.startswith("Error:")), None)
        out = f"{head}: {err[6:].strip()}" if err and err != lines[0] else head
    return out if len(out) <= limit else out[: limit - 1] + "…"


class Approver(Protocol):
    def request(self, *, plan_hash: str, summary: str, agent_reason: str | None = None,
                link: str | None = None, timeout_s: int = 1800, delegate: bool = False,
                direct: bool = False, context: dict | None = None) -> Any: ...

    def notify(self, text: str) -> None: ...


class Deadman(Protocol):
    def schedule(self, run_id: str) -> None: ...

    def cancel(self, run_id: str) -> None: ...


@dataclass
class Run:
    run_id: str
    branch: str
    head: str
    status: str = "started"
    level: str | None = None
    reasons: list[str] = field(default_factory=list)
    plan_hash: str | None = None
    last_good: str | None = None
    merge_commit: str | None = None
    pid: int | None = None
    started: float = 0.0
    finished: float | None = None
    summary: str = ""

    def save(self, runs_dir: Path) -> None:
        runs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = runs_dir / f"{self.run_id}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(redact_data(asdict(self)), indent=2, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    @classmethod
    def load(cls, runs_dir: Path, run_id: str) -> Run:
        data = json.loads((runs_dir / f"{run_id}.json").read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class Deps:
    git: Git
    tofu_factory: Callable[[Path], Any]
    hooks: Hooks
    policy: Policy
    deadman: Deadman
    approver: Approver | None = None
    redact: Callable[[str], str] = lambda s: s
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    statvfs: Callable[[str], Any] = os.statvfs


class Runner:
    def __init__(self, cfg: Config, deps: Deps):
        self.cfg = cfg
        self.d = deps
        # Nach _run_locked: True, wenn wegen max_branches_per_run noch Branches offen sind.
        self.pending = False

    # ------------------------------------------------------------ Hilfen

    def _notify(self, text: str) -> None:
        text = self.d.redact(text)
        log.info("Meldung: %s", text)
        if self.d.approver:
            try:
                self.d.approver.notify(text)
            except Exception as e:  # Meldungen dürfen den Ablauf nie abbrechen
                log.warning("Meldung fehlgeschlagen: %s", type(e).__name__)

    def _run_dir(self, run_id: str) -> Path:
        p = self.cfg.state_dir / "work" / run_id
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        return p

    def _seen_path(self) -> Path:
        return self.cfg.state_dir / "seen.json"

    def _seen(self) -> dict[str, str]:
        try:
            return json.loads(self._seen_path().read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _mark_seen(self, branch: Branch, run_id: str) -> None:
        seen = self._seen()
        seen[f"{branch.name}@{branch.head}"] = run_id
        tmp = self._seen_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(seen, indent=2), encoding="utf-8")
        os.replace(tmp, self._seen_path())

    def _run_id(self, branch: Branch) -> str:
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(self.d.clock()))
        slug = branch.name[len(self.cfg.repo.branch_prefix):].replace(".", "-")[:40]
        return f"{stamp}-{slug}-{branch.head[:8]}"

    def _tofu_in(self, wt: Path):
        tofu = self.d.tofu_factory(wt / self.cfg.tofu.dir)
        tofu.prepare()
        return tofu

    def _finish(self, run: Run, status: str, reason: str | None = None) -> Run:
        run.status = status
        if reason:
            run.reasons.append(reason)
        run.finished = self.d.clock()
        run.pid = None
        run.save(self.cfg.runs_dir)
        return run

    def _backup_state(self, run_id: str) -> None:
        src = self.cfg.tofu.state_path
        if not src.exists():
            return
        bdir = src.parent / "backups"
        bdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        dst = bdir / f"{run_id}.tfstate"
        shutil.copy2(src, dst)
        os.chmod(dst, 0o600)
        backups = sorted(bdir.glob("*.tfstate"), key=lambda p: p.stat().st_mtime)
        for old in backups[: max(0, len(backups) - self.cfg.tofu.state_backups)]:
            old.unlink(missing_ok=True)

    # ------------------------------------------------------------ Einstieg

    def run_once(self) -> list[Run]:
        """Neue desired/*-Branches abarbeiten. Für den systemd-Timer.

        Mit max_branches_per_run > 0 höchstens so viele, danach gibt der Lauf den Lock frei.
        Ein Branch mit zwei Exporten hält den Lock eine Viertelstunde, andere Dienste am
        selben Lock sollen nicht hinter einer ganzen Warteschlange hängen.

        Mit drain_minutes > 0 endet der Lauf dann nicht, sondern wartet drain_pause_seconds
        ohne Lock (Zeit für die anderen Dienste) und nimmt den nächsten Branch, solange der
        Lauf jünger als drain_minutes ist. Sonst bliebe nach jedem Branch die Pause des Timers.
        """
        started = self.d.clock()
        results: list[Run] = []
        while True:
            if self.cfg.stop_file.exists():
                if not results:
                    log.warning("STOP-Datei vorhanden, nichts zu tun.")
                return results
            try:
                with proc.file_lock(self.cfg.lock_file):
                    results += self._run_locked()
            except proc.LockBusy:
                log.info("Lock belegt, später erneut.")
                return results
            if not self.pending:
                return results
            if self.d.clock() - started >= self.cfg.drain_minutes * 60:
                log.info("%s Branch(es) abgearbeitet, Rest im nächsten Lauf.", len(results))
                return results
            log.info("Noch Branches offen, Lock %s s frei, dann weiter.", self.cfg.drain_pause_seconds)
            self.d.sleep(self.cfg.drain_pause_seconds)

    def _run_locked(self) -> list[Run]:
        self.pending = False
        self.d.git.ensure_clone()
        self.d.git.fetch()
        seen = self._seen()
        results = []
        for br in self.d.git.desired_branches():
            if f"{br.name}@{br.head}" in seen:
                continue
            if self.cfg.stop_file.exists():
                break
            if not self._space_ok():
                break  # Branch bleibt ungesehen, nächster Lauf versucht es wieder
            run = self.process(br)
            self._mark_seen(br, run.run_id)
            results.append(run)
            if run.status == "rollback_failed":
                break
            if 0 < self.cfg.max_branches_per_run <= len(results):
                self.pending = self._has_unseen()
                break
        self._prune_work_dirs()
        return results

    def _has_unseen(self) -> bool:
        """Neu holen: Auch Branches, die während einer Freigabe gepusht wurden, zählen."""
        if self.cfg.stop_file.exists():
            return False
        self.d.git.fetch()
        seen = self._seen()
        return any(f"{br.name}@{br.head}" not in seen for br in self.d.git.desired_branches())

    def _free_percent(self) -> float:
        """Freier Anteil im state_dir, das Knappere von Platz und Inodes."""
        st = self.d.statvfs(str(self.cfg.state_dir))
        space = 100 * st.f_bavail / st.f_blocks if st.f_blocks else 100.0
        inodes = 100 * st.f_favail / st.f_files if st.f_files else 100.0
        return min(space, inodes)

    def _space_ok(self) -> bool:
        """Genug Platz für Worktree, zwei Snapshots und einen Rollback?

        Sonst gar nicht erst anwenden: Am 23.10.2026 lief ein Apply noch durch, Snapshot und
        Rollback scheiterten danach an vollen Inodes, das Gate stand mit rollback_failed.
        Bei Knappheit zuerst ältere Arbeitsordner bis auf drei aufräumen.
        """
        need = self.cfg.min_free_percent
        if need <= 0:
            return True
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        marker = self.cfg.state_dir / "low-space"
        free = self._free_percent()
        if free < need:
            self._prune_work_dirs(keep=min(self.cfg.keep_work_dirs, 3))
            free = self._free_percent()
        if free >= need:
            if marker.exists():
                marker.unlink()
                self._notify(f"✅ **Gate**: wieder {free:.0f} % frei, Branches werden weiter abgearbeitet.")
            return True
        log.warning("Nur %.1f %% frei in %s (Platz oder Inodes), Branch wartet.", free, self.cfg.state_dir)
        if not marker.exists():
            marker.write_text(f"{free:.1f}\n", encoding="utf-8")
            self._notify(f"⏸️ **Gate wartet**: nur {free:.0f} % frei in {self.cfg.state_dir} (Platz oder "
                         f"Inodes, nötig {need} %). Nichts angewendet, Branches bleiben in der Warteschlange.")
        return False

    def _prune_work_dirs(self, keep: int | None = None) -> None:
        """Nur die letzten keep_work_dirs Arbeitsordner behalten (je Lauf mehrere MB Snapshots).

        Gelöscht werden nur Ordner abgeschlossener Läufe. Laufende, zurückrollende und
        fehlgeschlagene Rollbacks bleiben: Dead-Man und Diagnose brauchen snapshot-before.
        Die Lauf-Dateien unter runs/ bleiben immer.
        """
        keep = self.cfg.keep_work_dirs if keep is None else keep
        wdir = self.cfg.state_dir / "work"
        if keep <= 0 or not wdir.is_dir():
            return
        # Nur Ordner mit Lauf-ID (beginnt mit der UTC-Zeit), sortiert = zeitlich.
        dirs = sorted((p for p in wdir.iterdir() if p.is_dir() and RUN_ID_RE.match(p.name)), key=lambda p: p.name)
        for p in dirs[: max(0, len(dirs) - keep)]:
            try:
                status = Run.load(self.cfg.runs_dir, p.name).status
            except (OSError, ValueError, TypeError):
                continue  # unbekannter Ordner: lieber stehen lassen
            if status in FINISHED:
                shutil.rmtree(p, ignore_errors=True)

    # ------------------------------------------------------------ ein Branch

    def process(self, br: Branch) -> Run:
        run = Run(run_id=self._run_id(br), branch=br.name, head=br.head, pid=os.getpid(), started=self.d.clock())
        run.save(self.cfg.runs_dir)
        rdir = self._run_dir(run.run_id)
        wt = rdir / "tree"
        try:
            return self._process(run, br, rdir, wt)
        except Exception as e:
            log.exception("Lauf %s abgebrochen", run.run_id)
            self._notify(f"⚠️ **Fehler im Gate**: {br.name}\n{short_reason(f'{type(e).__name__}: {e}')}")
            return self._finish(run, "error", f"{type(e).__name__}: {e}")
        finally:
            self.d.git.remove_worktree(wt)

    def _process(self, run: Run, br: Branch, rdir: Path, wt: Path) -> Run:
        git = self.d.git
        if not git.valid_name(br.name):
            return self._reject(run, f"Ungültiger Branch-Name {br.name}")

        main_ref = f"origin/{self.cfg.repo.main}"
        # main kann sich seit dem Fetch in _run_locked bewegt haben (voriger Branch, Snapshot-Commit).
        git.fetch()
        run.last_good = git.rev(main_ref)
        bad = git.disallowed_paths(main_ref, br.head)
        if bad:
            return self._reject(run, "Nicht erlaubte Pfade: " + ", ".join(bad[:10]))

        git.worktree(wt, run.last_good)
        try:
            run.merge_commit = git.merge_into(wt, br.head, f"gate: {br.name} ({run.run_id})")
        except GitError as e:
            return self._reject(run, str(e))
        bad_vars = self._check_variables(wt, git.changed_paths(main_ref, br.head))
        if bad_vars:
            return self._reject(run, bad_vars)

        tofu = self._tofu_in(wt)
        r = tofu.init()
        if not r.ok:
            return self._reject(run, f"tofu init fehlgeschlagen:\n{r.tail(8)}")
        planfile = rdir / "plan.bin"
        r = tofu.plan(planfile)
        if not r.ok:
            return self._reject(run, f"tofu plan fehlgeschlagen:\n{r.tail(8)}")
        plan_json = tofu.show_json(planfile)
        plan_path = rdir / "plan.json"
        plan_path.write_text(json.dumps(plan_json), encoding="utf-8")
        os.chmod(plan_path, 0o600)
        run.plan_hash = planlib.file_hash(planfile)

        dec = classify(plan_json, self.d.policy)
        run.level = dec.level
        run.summary = (self.d.hooks.text("summary", run.run_id, plan_json=plan_path, repo_dir=wt)
                       or planlib.summarize(dec.changes))
        run.reasons += dec.reasons
        run.save(self.cfg.runs_dir)

        if dec.level == "reject":
            return self._reject(run, None)

        if not dec.changes:
            git.push_main(run.merge_commit)
            git.delete_branch(br.name)
            self._notify(f"☑️ **Ohne Änderung übernommen**: {br.name}")
            return self._finish(run, "noop")

        snap_before = None
        if self.d.hooks.configured("snapshot"):
            snap_before = rdir / "snapshot-before"
            hr = self.d.hooks.snapshot(run.run_id, snap_before)
            if not hr.ok:
                return self._reject(run, "Snapshot vor dem Apply fehlgeschlagen: " + "; ".join(hr.messages()))

        hr = self.d.hooks.run("pre_apply", run.run_id, plan_json=plan_path, repo_dir=wt,
                              snapshot_before=snap_before)
        if not hr.ok:
            return self._reject(run, "Invarianten verletzt: " + "; ".join(hr.messages()))
        warnings = hr.warnings
        if warnings:
            # Freigebbarer Verstoß: nie automatisch, immer mit Warnung in der Freigabe.
            run.level = "approval"
            run.reasons += ["Freigabe mit Warnung: " + w.get("id", "?") for w in warnings]
            run.save(self.cfg.runs_dir)

        approved_warnings = None
        if run.level in ("review", "approval"):
            if not self.d.approver:
                return self._reject(run, "Freigabe nötig, aber kein Freigabekanal konfiguriert")
            link = self.cfg.repo.commit_url.format(sha=br.head) if self.cfg.repo.commit_url else None
            texts = dict.fromkeys(w.get("title") or w.get("message", "") for w in warnings)  # ohne Dopplungen
            warn = "".join(f"\n\n⚠️ **Achtung:** {t}" for t in texts)
            res = self.d.approver.request(
                plan_hash=run.plan_hash, summary=f"{run.summary}{warn}\n\nBranch {br.name}",
                agent_reason=git.message(br.head), link=link,
                timeout_s=self.cfg.approval_timeout_minutes * 60, delegate=run.level == "review",
            )
            if not getattr(res, "approved", False):
                why = {"declined": "abgelehnt", "timeout": "keine Antwort",
                       "delegate_denied": "vom Prüfer abgelehnt"}.get(getattr(res, "reason", ""), "")
                note = getattr(res, "note", "") or ""
                self._notify(f"🚫 **Nicht freigegeben**: {br.name}" + (f" ({why})" if why else "")
                             + (f"\n{short_reason(note)}" if note else ""))
                reason = getattr(res, "reason", None)
                return self._finish(run, "declined", f"{reason}: {note}" if note else reason)
            if warnings:
                approved_warnings = rdir / "approved-warnings.json"
                approved_warnings.write_text(json.dumps(warnings, ensure_ascii=False), encoding="utf-8")
                os.chmod(approved_warnings, 0o600)

        return self._apply(run, br, rdir, wt, tofu, planfile, plan_path, snap_before, approved_warnings)

    def _check_variables(self, wt: Path, paths: list[str]) -> str | None:
        """Agenten dürfen nur freigegebene Variablen setzen (nicht z. B. Passphrasen)."""
        allowed = self.cfg.repo.allowed_variables
        if allowed is None:
            return None
        for rel in paths:
            if not rel.endswith(".tfvars.json"):
                continue
            path = wt / rel
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return f"{rel}: kein gültiges JSON ({type(e).__name__})"
            if not isinstance(data, dict):
                return f"{rel}: Objekt erwartet"
            extra = sorted(set(data) - set(allowed))
            if extra:
                return f"{rel}: Variablen nicht erlaubt: {', '.join(extra)}"
        return None

    def _reject(self, run: Run, reason: str | None) -> Run:
        self._finish(run, "rejected", reason)
        why = short_reason(run.reasons[-1] if run.reasons else "") or "ohne Grund"
        self._notify(f"❌ **Abgelehnt**: {run.branch}\n{why}")
        return run

    # ------------------------------------------------------------ Apply

    def _apply(self, run: Run, br: Branch, rdir: Path, wt: Path, tofu, planfile: Path,
               plan_path: Path, snap_before: Path | None, approved_warnings: Path | None = None) -> Run:
        self._backup_state(run.run_id)
        run.status = "applying"
        run.pid = os.getpid()
        run.save(self.cfg.runs_dir)
        self.d.deadman.schedule(run.run_id)

        if planlib.file_hash(planfile) != run.plan_hash:
            self.d.deadman.cancel(run.run_id)
            return self._reject(run, "Plan-Datei hat sich seit der Prüfung geändert")

        r = tofu.apply(planfile)
        problem = None if r.ok else f"tofu apply fehlgeschlagen:\n{r.tail(8)}"
        if not problem:
            problem = self._health(run, wt, tofu, plan_path, snap_before, rdir, approved_warnings)

        if problem:
            run.reasons.append(problem)
            run.save(self.cfg.runs_dir)
            return self._rollback_locked(run, cause=problem, rearm=True)

        self.d.deadman.cancel(run.run_id)
        try:
            self._push_merge(run, br, wt)
        except GitError as e:
            # Änderung ist live und geprüft, nur der Merge fehlt. Kein Rollback.
            self._notify(f"⚠️ **Angewendet, aber nicht gemergt**: {br.name}\n{short_reason(str(e))}")
            return self._finish(run, "applied_unmerged", str(e))
        # Erfolg ist der Normalfall, auch ohne Freigabe. Gemeldet werden nur Fehler.
        return self._finish(run, "applied")

    def _health(self, run: Run, wt: Path, tofu, plan_path: Path, snap_before: Path | None,
                rdir: Path, approved_warnings: Path | None = None) -> str | None:
        r = tofu.plan_detailed()
        if r.rc != 0:
            return f"Plan nach dem Apply nicht leer (rc={r.rc}):\n{r.tail(8)}"
        snap_after = None
        if self.d.hooks.configured("snapshot"):
            snap_after = rdir / "snapshot-after"
            hr = self.d.hooks.snapshot(run.run_id, snap_after)
            if not hr.ok:
                return "Snapshot nach dem Apply fehlgeschlagen: " + "; ".join(hr.messages())
        hr = self.d.hooks.run("post_apply", run.run_id, plan_json=plan_path, repo_dir=wt,
                              snapshot_before=snap_before, snapshot_after=snap_after,
                              approved_warnings=approved_warnings)
        if not hr.ok:
            return "Health-Check fehlgeschlagen: " + "; ".join(hr.messages())
        return None

    def _push_merge(self, run: Run, br: Branch, wt: Path) -> None:
        git = self.d.git
        try:
            git.push_main(run.merge_commit)
        except GitError:
            # main hat sich bewegt (z. B. Snapshot-Commit): neu mergen und erneut pushen.
            git.fetch()
            git.checkout(wt, git.rev(f"origin/{self.cfg.repo.main}"))
            run.merge_commit = git.merge_into(wt, br.head, f"gate: {br.name} ({run.run_id})")
            git.push_main(run.merge_commit)
        git.delete_branch(br.name)

    # ------------------------------------------------------------ Rollback

    def rollback(self, run_id: str) -> Run:
        """Einstieg für Dead-Man-Timer und Hand: hängenden Lauf beenden, zurückrollen."""
        run = Run.load(self.cfg.runs_dir, run_id)
        if run.status not in ("applying", "rolling_back"):
            log.info("Lauf %s hat Status %s, kein Rollback nötig.", run_id, run.status)
            return run
        if run.pid and proc.alive(run.pid):
            log.warning("Lauf %s hängt (pid %s), wird beendet.", run_id, run.pid)
            proc.terminate(run.pid)
        with proc.file_lock(self.cfg.lock_file, wait=120):
            return self._rollback_locked(run, cause="Dead-Man-Timer abgelaufen")

    def _rollback_locked(self, run: Run, cause: str, rearm: bool = False) -> Run:
        run.status = "rolling_back"
        run.pid = os.getpid()
        run.save(self.cfg.runs_dir)
        if rearm:
            # Rollback im Lauf selbst: Der Timer läuft seit dem Apply. Apply, Health-Checks
            # und Rollback mit zweitem Snapshot können zusammen länger dauern. Ohne neuen
            # Timer würde der Dead-Man einen gesunden Rollback mittendrin beenden.
            self.d.deadman.cancel(run.run_id)
            try:
                self.d.deadman.schedule(run.run_id)
            except Exception as e:  # noqa: BLE001, Rollback geht trotzdem weiter
                log.warning("Dead-Man für Rollback %s nicht neu geplant: %s", run.run_id, e)
        rdir = self._run_dir(run.run_id)
        wt = rdir / "rollback-tree"
        try:
            problem = self._do_rollback(run, rdir, wt)
        except Exception as e:
            log.exception("Rollback %s abgebrochen", run.run_id)
            problem = f"{type(e).__name__}: {e}"
        finally:
            self.d.git.remove_worktree(wt)
        self.d.deadman.cancel(run.run_id)
        if problem:
            self.cfg.stop_file.parent.mkdir(parents=True, exist_ok=True)
            self.cfg.stop_file.write_text(f"Rollback {run.run_id} fehlgeschlagen: {problem}\n", encoding="utf-8")
            discarded = self._discard_pending(run) if self.cfg.discard_pending_on_stop else []
            text = (f"🛑 **Rollback fehlgeschlagen, Gate gestoppt**: {run.branch}\n"
                    f"Grund: {short_reason(cause)}\nRollback: {short_reason(problem)}")
            if discarded:
                text += "\nVerworfen (nach dem STOP neuer Commit nötig): " + ", ".join(discarded)
            self._notify(text)
            return self._finish(run, "rollback_failed", problem)
        self._notify(f"↩️ **Zurückgerollt**: {run.branch}\nGrund: {short_reason(cause)}")
        return self._finish(run, "rolled_back")

    def _discard_pending(self, cause: Run) -> list[str]:
        """Nach rollback_failed: alle wartenden Branches als verworfen abschließen.

        Sie wurden gegen einen Stand geschrieben, der nach dem gescheiterten Rollback nicht mehr
        gilt, manche bauen sogar auf der gescheiterten Änderung auf (live 23.10.2026). Liefen sie
        nach dem Aufheben von STOP einfach weiter, käme die ganze Warteschlange ungeprüft durch.
        Neuer Versuch = neuer Commit auf demselben Branch.
        """
        names: list[str] = []
        try:
            try:
                self.d.git.fetch()
            except GitError as e:
                log.warning("Fetch vor dem Verwerfen fehlgeschlagen, nehme den letzten Stand: %s", e)
            seen = self._seen()
            for br in self.d.git.desired_branches():
                if f"{br.name}@{br.head}" in seen or (br.name, br.head) == (cause.branch, cause.head):
                    continue
                run = Run(run_id=self._run_id(br), branch=br.name, head=br.head, started=self.d.clock())
                self._finish(run, "discarded",
                             f"Verworfen: Gate gestoppt, Rollback von {cause.branch} ({cause.run_id}) "
                             "fehlgeschlagen. Nach dem Aufheben des STOP neuen Commit pushen.")
                self._mark_seen(br, run.run_id)
                names.append(br.name)
        except Exception:  # noqa: BLE001, STOP steht schon, das Verwerfen ist nur Zugabe
            log.exception("Wartende Branches nicht verworfen")
        return names

    def _do_rollback(self, run: Run, rdir: Path, wt: Path) -> str | None:
        if not run.last_good:
            return "kein last-good-Commit bekannt"
        self.d.git.worktree(wt, run.last_good)
        tofu = self._tofu_in(wt)
        r = tofu.init()
        if not r.ok:
            return f"tofu init fehlgeschlagen:\n{r.tail(8)}"
        planfile = rdir / "rollback.bin"
        r = tofu.plan(planfile)
        if not r.ok:
            return f"tofu plan fehlgeschlagen:\n{r.tail(8)}"
        plan_json = tofu.show_json(planfile)
        dec: Decision = classify(plan_json, self.d.policy, rollback=True)
        if dec.level == "reject":
            return "Rollback-Plan verletzt forbidden: " + "; ".join(dec.reasons)
        r = tofu.apply(planfile)
        if not r.ok:
            return f"tofu apply fehlgeschlagen:\n{r.tail(8)}"
        r = tofu.plan_detailed()
        if r.rc != 0:
            return f"Plan nach dem Rollback nicht leer (rc={r.rc})"
        return self._check_rollback(run, rdir, wt)

    def _check_rollback(self, run: Run, rdir: Path, wt: Path) -> str | None:
        """Frischen Snapshot mit dem Stand vor dem Apply vergleichen.

        Ein leerer Plan reicht nicht: Behandelt der Provider null als "nicht anfassen",
        bleibt ein gerade gesetztes Feld nach dem Rollback stehen.
        """
        if not self.d.hooks.configured("post_rollback"):
            return None
        snap_before = snap_after = None
        if self.d.hooks.configured("snapshot"):
            snap_before = rdir / "snapshot-before"
            if not snap_before.is_dir():
                return "Snapshot vor dem Apply fehlt, Vergleich nach dem Rollback nicht möglich"
            snap_after = rdir / "snapshot-after-rollback"
            shutil.rmtree(snap_after, ignore_errors=True)  # Rest eines abgebrochenen Rollbacks
            hr = self.d.hooks.snapshot(run.run_id, snap_after)
            if not hr.ok:
                return "Snapshot nach dem Rollback fehlgeschlagen: " + "; ".join(hr.messages())
        # Nach dem Rollback ist keine Änderung erwartet, daher ein leerer Plan.
        plan_path = rdir / "rollback-check.json"
        plan_path.write_text(json.dumps({"format_version": "1.2", "resource_changes": []}), encoding="utf-8")
        os.chmod(plan_path, 0o600)
        hr = self.d.hooks.run("post_rollback", run.run_id, plan_json=plan_path, repo_dir=wt,
                              snapshot_before=snap_before, snapshot_after=snap_after)
        if not hr.ok:
            return "Stand nach dem Rollback weicht ab: " + "; ".join(hr.messages())
        return None

    # ------------------------------------------------------------ Wiederanlauf nach STOP

    def recover(self) -> str:
        """STOP nach einem fehlgeschlagenen Rollback selbst aufheben, wenn alles wieder stimmt.

        Für einen Timer, solange STOP steht. Angefasst wird nur die STOP-Datei, die das Gate
        nach rollback_failed selbst schreibt ("Rollback <run_id> fehlgeschlagen"), nie eine
        von Hand oder vom Deploy gesetzte. Geprüft wird je STOP einmal, danach frühestens nach
        recover_reask_hours (Plan und Snapshot kosten viele API-Abfragen).

        Grün (Plan von main leer, recover-Hook auf frischem Snapshot ohne Verstoß): STOP weg,
        Kopie unter state_dir, Meldung. Sonst eine Freigabe: Accept wendet main bei Bedarf
        erneut an und hebt den STOP auf, Decline lässt ihn stehen, ohne erneut zu fragen.

        Ergebnis: no_stop, manual, declined, waiting, busy, changed, resumed, kept, error.
        """
        try:
            stop_text = self.cfg.stop_file.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return "no_stop"
        m = STOP_RE.match(stop_text)
        run = None
        if m:
            try:
                run = Run.load(self.cfg.runs_dir, m.group(1))
            except (OSError, ValueError, TypeError):
                run = None
        if run is None or run.status != "rollback_failed":
            log.info("STOP stammt nicht von einem fehlgeschlagenen Rollback, bleibt unberührt.")
            return "manual"
        key = hashlib.sha256(stop_text.encode()).hexdigest()
        state = self._recover_state()
        if state.get("key") == key:
            if state.get("decision") == "declined":
                return "declined"
            if self.d.clock() - float(state.get("checked_at") or 0) < self.cfg.recover_reask_hours * 3600:
                return "waiting"
        try:
            with proc.file_lock(self.cfg.lock_file, wait=120):
                if self._stop_key() != key:
                    return "changed"
                self._save_recover_state(key, "checking")
                return self._recover_locked(run, stop_text, key)
        except proc.LockBusy:
            log.info("Lock belegt, Wiederanlauf später.")
            return "busy"

    def _stop_key(self) -> str | None:
        try:
            text = self.cfg.stop_file.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return None
        return hashlib.sha256(text.encode()).hexdigest()

    def _recover_state_path(self) -> Path:
        return self.cfg.state_dir / "recover.json"

    def _recover_state(self) -> dict:
        try:
            return json.loads(self._recover_state_path().read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_recover_state(self, key: str, decision: str) -> None:
        state = self._recover_state()
        if state.get("key") != key:
            state = {"key": key}
        if decision == "checking":
            state["checked_at"] = self.d.clock()
        state["decision"] = decision
        path = self._recover_state_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.replace(tmp, path)

    def _recover_locked(self, run: Run, stop_text: str, key: str) -> str:
        rdir = self._run_dir(run.run_id)
        wt = rdir / "recover-tree"
        fwt = rdir / "recover-forward-tree"
        try:
            tofu, changes, problems, info, forward = self._recover_check(run, rdir, wt, fwt)
            if self._stop_key() != key:
                return "changed"
            if not changes and not problems:
                if not forward:
                    return self._resume(run, stop_text, key, "UDM gleich main, Prüfung bestanden", info)
                err = self._roll_forward(run, fwt)
                if not err:
                    return self._resume(run, stop_text, key, "UDM gleich Branch, nach main übernommen", info)
                problems = [err]
            return self._recover_ask(run, stop_text, key, tofu, changes, problems, info, forward, fwt)
        except Exception as e:  # noqa: BLE001, STOP bleibt in jedem Fall stehen
            log.exception("Wiederanlauf nach %s abgebrochen", run.run_id)
            self._save_recover_state(key, "error")
            self._notify(f"⚠️ **Gate steht weiter**: Selbstprüfung nach {run.branch} abgebrochen\n"
                         f"{short_reason(f'{type(e).__name__}: {e}')}")
            return "error"
        finally:
            self.d.git.remove_worktree(wt)
            self.d.git.remove_worktree(fwt)

    def _recover_check(self, run: Run, rdir: Path, wt: Path,
                       fwt: Path) -> tuple[Any, list, list[str], list[str], bool]:
        """Plan von main gegen den Controller, bei leerem Plan der recover-Hook.

        Ist der Plan von main nicht leer, der des gescheiterten Laufs (merge_commit) aber schon,
        ging der Apply durch und erst die Prüfung danach schief (live 23.10.2026: Platte voll).
        Dann gilt der schon freigegebene Branch-Stand als Ziel ("forward"), nicht main.

        Ergebnis: tofu (für ein späteres Apply von main), geplante Änderungen, blockierende
        Probleme, Hinweise, forward.
        """
        git = self.d.git
        git.fetch()
        git.worktree(wt, git.rev(f"origin/{self.cfg.repo.main}"))
        tofu = self._tofu_in(wt)
        r = tofu.init()
        if not r.ok:
            return tofu, [], [f"tofu init fehlgeschlagen: {short_reason(r.tail(8))}"], [], False
        planfile = rdir / "recover.bin"
        r = tofu.plan(planfile)
        if not r.ok:
            return tofu, [], [f"tofu plan fehlgeschlagen: {short_reason(r.tail(8))}"], [], False
        dec = classify(tofu.show_json(planfile), self.d.policy, rollback=True)
        if dec.level == "reject":
            return tofu, [], ["Plan von main verletzt forbidden: " + "; ".join(dec.reasons)], [], False
        forward = bool(dec.changes) and self._matches_branch(run, rdir, fwt)
        if dec.changes and not forward:
            return tofu, dec.changes, [], [], False
        if not self.d.hooks.configured("recover"):
            return tofu, [], ["Plan leer, aber kein recover-Hook für den Abgleich mit dem Snapshot"], [], forward
        snap_before = rdir / "snapshot-before"
        snap_after = None
        if self.d.hooks.configured("snapshot"):
            snap_after = rdir / "snapshot-recover"
            shutil.rmtree(snap_after, ignore_errors=True)
            hr = self.d.hooks.snapshot(run.run_id, snap_after)
            if not hr.ok:
                return tofu, [], ["Snapshot fehlgeschlagen: " + "; ".join(hr.messages())], [], forward
        # Erwartet: keine Änderung gegen den Stand vorher, beim Übernehmen die des Laufs.
        plan_path = rdir / "plan.json"
        if not (forward and plan_path.is_file()):
            plan_path = rdir / "recover-check.json"
            plan_path.write_text(json.dumps({"format_version": "1.2", "resource_changes": []}), encoding="utf-8")
            os.chmod(plan_path, 0o600)
        hr = self.d.hooks.run("recover", run.run_id, plan_json=plan_path, repo_dir=fwt if forward else wt,
                              snapshot_before=snap_before if snap_before.is_dir() else None,
                              snapshot_after=snap_after)
        if not hr.ok:
            return tofu, [], hr.messages(), [], forward
        return tofu, [], [], hr.messages(), forward

    def _matches_branch(self, run: Run, rdir: Path, fwt: Path) -> bool:
        """Plant der Stand des gescheiterten Laufs (main + Branch) leer? Dann ist er live."""
        if not run.merge_commit:
            return False
        try:
            self.d.git.worktree(fwt, run.merge_commit)
        except GitError as e:
            log.info("merge_commit %s nicht mehr da: %s", run.merge_commit[:8], e)
            return False
        tofu = self._tofu_in(fwt)
        if not tofu.init().ok:
            return False
        planfile = rdir / "recover-forward.bin"
        if not tofu.plan(planfile).ok:
            return False
        dec = classify(tofu.show_json(planfile), self.d.policy, rollback=True)
        return dec.level != "reject" and not dec.changes

    def _roll_forward(self, run: Run, fwt: Path) -> str | None:
        """Branch-Stand nach main übernehmen, wie nach einem gelungenen Lauf."""
        try:
            self._push_merge(run, Branch(run.branch, run.head), fwt)
        except GitError as e:
            return f"Branch-Stand nicht nach main übernommen: {e}"
        self._finish(run, "applied", "Nach dem STOP übernommen: Die Infrastruktur entsprach schon dem Branch")
        return None

    def _recover_ask(self, run: Run, stop_text: str, key: str, tofu, changes: list,
                     problems: list[str], info: list[str], forward: bool = False,
                     fwt: Path | None = None) -> str:
        since = time.strftime("%d.%m. %H:%M UTC", time.gmtime(self.cfg.stop_file.stat().st_mtime))
        lines = [f"🛑 Gate steht seit {since}, Rollback von {run.branch} fehlgeschlagen.",
                 "Selbstprüfung nicht bestanden:"]
        if forward:
            lines.append("Die Infrastruktur entspricht schon dem Branch (Apply war durch).")
        if changes:
            lines.append("Plan von main nicht leer:\n" + planlib.summarize(changes))
        lines += [f"- {short_reason(p, 200)}" for p in problems[:8]]
        if len(problems) > 8:
            lines.append(f"- … und {len(problems) - 8} weitere")
        accept = ("Accept: Branch-Stand nach main übernehmen und STOP aufheben." if forward
                  else "Accept: main erneut anwenden und STOP aufheben." if changes else "Accept: STOP aufheben.")
        lines.append(accept + " Decline: STOP bleibt, ohne erneute Nachfrage.")
        if not self.d.approver:
            self._save_recover_state(key, "kept")
            self._notify("\n".join(lines))
            return "kept"
        self._save_recover_state(key, "asked")
        detail = "\n".join([*(c.address for c in changes), *problems])
        res = self.d.approver.request(
            plan_hash=hashlib.sha256(f"recover\n{key}\n{detail}".encode()).hexdigest(),
            summary="\n".join(lines), timeout_s=self.cfg.approval_timeout_minutes * 60)
        if self._stop_key() != key:
            return "changed"
        if getattr(res, "approved", False):
            if forward and fwt is not None:
                err = self._roll_forward(run, fwt)
                if err:
                    self._save_recover_state(key, "failed")
                    self._notify(f"🛑 **Gate steht weiter**: {short_reason(err)}")
                    return "kept"
            elif changes:
                err = self._recover_apply(tofu, run, changes)
                if err:
                    self._save_recover_state(key, "failed")
                    self._notify(f"🛑 **Gate steht weiter**: main ließ sich nicht erneut anwenden\n{short_reason(err)}")
                    return "kept"
            return self._resume(run, stop_text, key, "freigegeben", info)
        if getattr(res, "reason", "") == "declined":
            self._save_recover_state(key, "declined")
            self._notify(f"🛑 **STOP bleibt** (nach {run.branch}). Aufheben von Hand: rm {self.cfg.stop_file}")
            return "declined"
        self._save_recover_state(key, "timeout")
        return "waiting"

    def _recover_apply(self, tofu, run: Run, approved: list) -> str | None:
        """Nach Accept: main frisch planen und nur anwenden, wenn der Plan noch der gezeigte ist."""
        planfile = self._run_dir(run.run_id) / "recover-apply.bin"
        r = tofu.plan(planfile)
        if not r.ok:
            return f"tofu plan fehlgeschlagen:\n{r.tail(8)}"
        dec = classify(tofu.show_json(planfile), self.d.policy, rollback=True)
        if dec.level == "reject":
            return "Plan von main verletzt forbidden: " + "; ".join(dec.reasons)
        if sorted((c.address, c.action) for c in dec.changes) != sorted((c.address, c.action) for c in approved):
            return "Plan hat sich seit der Freigabe geändert, neue Prüfung beim nächsten Lauf"
        r = tofu.apply(planfile)
        if not r.ok:
            return f"tofu apply fehlgeschlagen:\n{r.tail(8)}"
        r = tofu.plan_detailed()
        if r.rc != 0:
            return f"Plan nach dem Apply nicht leer (rc={r.rc})"
        return None

    def _resume(self, run: Run, stop_text: str, key: str, why: str, info: list[str]) -> str:
        stamp = time.strftime("%Y%m%d", time.gmtime(self.d.clock()))
        copy = self.cfg.state_dir / f"STOP-{stamp}-{run.run_id}.txt"
        copy.write_text(stop_text, encoding="utf-8")
        os.chmod(copy, 0o600)
        self.cfg.stop_file.unlink()
        self._save_recover_state(key, "resumed")
        text = f"✅ **Gate läuft wieder**: STOP nach {run.branch} aufgehoben ({why})."
        if info:
            text += "\nZur Info, sonst abweichend: " + "; ".join(short_reason(i, 160) for i in info[:5])
            if len(info) > 5:
                text += f" (+{len(info) - 5})"
        self._notify(text)
        return "resumed"
