"""Subprozesse, Lock und Prozess-Hilfen."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows, nur für lokale Tests
    fcntl = None

# Diese Variablen dürfen an Kindprozesse weitergereicht werden. Alles andere
# (z. B. Tokens aus der Umgebung des Aufrufers) bleibt draußen.
BASE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR")


@dataclass
class Result:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def tail(self, n: int = 20) -> str:
        lines = (self.out + "\n" + self.err).strip().splitlines()
        return "\n".join(lines[-n:])


def base_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: os.environ[k] for k in BASE_ENV_KEYS if k in os.environ}
    env.update(extra or {})
    return env


def run(argv: list[str], cwd: str | Path | None = None, env: dict[str, str] | None = None,
        timeout: int = 600, stdin: str | None = None) -> Result:
    try:
        p = subprocess.run(
            argv, cwd=cwd, env=env, input=stdin, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
        return Result(p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, str) else ""
        return Result(124, out, f"Timeout nach {timeout} s")
    except OSError as e:
        return Result(127, "", f"{argv[0]}: {e.strerror}")


@contextlib.contextmanager
def file_lock(path: Path, wait: float = 0):
    """Exklusiver Lock per flock. wait=0: sofort aufgeben, wenn belegt."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl:
            deadline = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise LockBusy(str(path)) from None
                    time.sleep(0.5)
        yield
    finally:
        os.close(fd)


class LockBusy(RuntimeError):
    pass


def alive(pid: int | None) -> bool:
    if not pid or pid == os.getpid():
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def terminate(pid: int, grace: float = 20.0) -> None:
    """Prozessgruppe des Laufs beenden: erst TERM, nach grace Sekunden KILL."""
    if not alive(pid):
        return
    killpg = getattr(os, "killpg", None)
    try:
        pgid = os.getpgid(pid) if hasattr(os, "getpgid") else None
    except ProcessLookupError:
        return
    own = os.getpgid(0) if hasattr(os, "getpgid") else None

    def _send(sig):
        try:
            if killpg and pgid and pgid != own:
                killpg(pgid, sig)
            else:
                os.kill(pid, sig)
        except ProcessLookupError:
            pass

    _send(signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not alive(pid):
            return
        time.sleep(0.5)
    _send(getattr(signal, "SIGKILL", signal.SIGTERM))
