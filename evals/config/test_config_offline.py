"""Config parsing checks — local-only, $0.

Run:  PYTHONPATH=. ./.venv/bin/python evals/config/test_config_offline.py
"""

from __future__ import annotations

import os
import sys

from adv_platform.config import Config, _env


def check_comment_only_value_is_unset() -> tuple[bool, str]:
    os.environ["JUDGE_MODEL"] = "# cheap frontier for the Judge (e.g. a Haiku-class model)"
    try:
        ok = _env("JUDGE_MODEL") == "" and Config.load().judge_model == ""
    finally:
        del os.environ["JUDGE_MODEL"]
    return ok, "blank value + comment -> unset (not the comment text)"


def check_real_value_kept() -> tuple[bool, str]:
    os.environ["JUDGE_MODEL"] = "claude-haiku-4-5-20251001"
    try:
        got = Config.load().judge_model
    finally:
        del os.environ["JUDGE_MODEL"]
    return got == "claude-haiku-4-5-20251001", f"judge_model={got!r}"


CHECKS = [check_comment_only_value_is_unset, check_real_value_kept]


def main() -> int:
    failed = 0
    for check in CHECKS:
        try:
            passed, detail = check()
        except Exception as e:
            passed, detail = False, f"EXCEPTION {type(e).__name__}: {e}"
        if not passed:
            failed += 1
        print(f"[{'PASS' if passed else 'FAIL'}] {check.__name__}: {detail}")
    total = len(CHECKS)
    print(f"\n{total - failed}/{total} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
