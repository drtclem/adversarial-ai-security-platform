"""Offline regression gate — the CI entry point (CLAUDE.md §4).

Discovers and runs every offline eval (`evals/**/test_*.py`), each of which follows
the repo convention: a `main()` that prints `N/N checks passed.` and exits non-zero
on failure. Aggregates the totals and exits non-zero if ANY file fails.

**No live target, no paid API, ever** (CLAUDE.md §0.6). This forces local-only mode
and asserts it before running, so a stray `PLATFORM_MODE=live` in the environment can
never turn CI into a paid run.

Run:  PYTHONPATH=. ./.venv/bin/python evals/run_regression.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# Belt-and-suspenders: CI is offline and free. Pin local-only for every child eval.
os.environ["PLATFORM_MODE"] = "local-only"
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")

_REPO = Path(__file__).resolve().parents[1]
_COUNT_RE = re.compile(r"(\d+)/(\d+) checks passed")

_TTY = sys.stdout.isatty()
RED = "\033[1;31m" if _TTY else ""
GREEN = "\033[1;32m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def discover() -> list[Path]:
    return sorted(p for p in (_REPO / "evals").rglob("test_*.py"))


def main() -> int:
    # Guard: never let CI spend money.
    from adv_platform.config import Config

    cfg = Config.load()
    if cfg.is_live:
        print("REFUSING: regression gate must run offline, but PLATFORM_MODE=live.")
        return 2

    env = dict(os.environ, PYTHONPATH=str(_REPO))
    files = discover()
    if not files:
        print("No eval files found under evals/.")
        return 1

    failed_files = 0
    total_passed = total_checks = 0
    print(f"Running {len(files)} offline eval file(s) — local-only, $0.\n")
    for f in files:
        rel = f.relative_to(_REPO)
        proc = subprocess.run(
            [sys.executable, str(f)], env=env, capture_output=True, text=True
        )
        tail = (proc.stdout.strip().splitlines() or ["(no output)"])[-1]
        m = _COUNT_RE.search(proc.stdout)
        if m:
            total_passed += int(m.group(1))
            total_checks += int(m.group(2))
        status = "ok  " if proc.returncode == 0 else "FAIL"
        if proc.returncode != 0:
            failed_files += 1
        print(f"[{status}] {rel} :: {tail}")
        if proc.returncode != 0 and proc.stderr.strip():
            print("        " + proc.stderr.strip().splitlines()[-1])

    print(f"\n=== {total_passed}/{total_checks} checks passed across "
          f"{len(files)} file(s); {failed_files} file(s) failing. ===")

    # Invariant-scored regression gate: previously-fixed vulns must stay fixed.
    # (Kept separate from the checks tally above; blocks the gate if any reappears.)
    gate_fail = False
    gate_file = _REPO / "evals" / "regression" / "regression_gate.py"
    if gate_file.exists():
        print("\n--- Regression gate (invariant-scored: previously-fixed vulns must stay fixed) ---")
        sys.stdout.flush()  # deterministic ordering before the inherited-stdio subprocess
        # Inherit stdio so the gate's colored PASS/FAIL renders in the terminal.
        proc = subprocess.run([sys.executable, str(gate_file)], env=env)
        gate_fail = proc.returncode != 0

    overall_fail = bool(failed_files or gate_fail)
    print(f"\n{(RED + 'CI GATE: FAIL' if overall_fail else GREEN + 'CI GATE: PASS')}{RESET}")
    sys.stdout.flush()
    return 1 if overall_fail else 0


if __name__ == "__main__":
    sys.exit(main())
