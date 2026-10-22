"""Operational entry point for the target client — ATTACKER ZONE.

This is the ONE command the local Bash allow-rule permits
(`Bash(python adv_platform/target_client/run_client.py:*)`), so every credentialed
call to the live target funnels through here. The `:8420`/`:9300` host allow-list
is enforced in `client.TargetClient`, not by that prefix rule.

Modes:
  --dry-run       Build the client and self-check the host allow-list WITHOUT any
                  network call. $0, no credentials used. (Default if creds absent.)
  --connectivity  Login + ONE benign message ("hello, this is a connectivity test").
  --message TEXT  Login + send TEXT (dev use).

  ⚠️  Any mode other than --dry-run makes a LIVE credentialed round-trip. The FIRST
  such run is gated on Taylor's explicit go-ahead (CLAUDE.md §3).

Run:  PYTHONPATH=. python3 adv_platform/target_client/run_client.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys

try:
    from dotenv import load_dotenv

    load_dotenv(".env")
except Exception:
    pass

import pathlib  # noqa: E402

from adv_platform.redteam import seeds as seed_loader  # noqa: E402
from adv_platform.redteam.redteam import RedTeam  # noqa: E402
from adv_platform.target_client.client import (  # noqa: E402
    AuthError,
    HostBlocked,
    TargetClient,
    TargetUnreachable,
    redact,
)

BENIGN = "hello, this is a connectivity test"

# Raw transcripts are handed off here for the SEPARATE, offline Judge (R7). This
# dir lives under platform_data/ (gitignored) — the one place raw target output is
# persisted, locally and transiently; everything downstream (verdict, events,
# dashboard) is redacted (R4).
_TRANSCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[2] / "platform_data" / "transcripts"


def _write_transcript(tx) -> pathlib.Path:
    _TRANSCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    path = _TRANSCRIPTS_DIR / f"{tx.case_id}-{tx.correlation_id}.json"
    path.write_text(tx.model_dump_json(indent=2))
    return path


def _print_transcript_redacted(tx, password: str, canaries=None) -> None:
    """Print the captured transcript for the human — target turns redacted (R4).
    Our own attacker prompts are shown verbatim (they are our payloads)."""
    for i, turn in enumerate(tx.turns):
        if turn.speaker == "attacker":
            print(f"  [{i}] ATTACKER: {turn.content}")
        else:
            print(f"  [{i}] TARGET (redacted): {redact(turn.content, password, 500, canaries)}")
            sig = {k: turn.meta.get(k) for k in
                   ("verification_passed", "enforced_warnings", "flagged_claims") if turn.meta}
            if sig:
                print(f"      signals: {json.dumps(sig, default=str)}")
    if tx.error is not None:
        print(f"  ERROR STATE: {tx.error.type.value} — {redact(tx.error.message, password)}")


def _self_check(c: TargetClient) -> list[tuple[str, bool, str]]:
    """Offline assertions on the host allow-list — no network."""
    off_hosts = [
        "http://evil.example.com/x",
        "http://localhost:9999/x",     # right IP, wrong port
        "https://203.0.113.9:8420/x",    # wrong IP
    ]
    checks: list[tuple[str, bool, str]] = []
    checks.append(("target host allowed", c._is_allowed(c.base + "/chat"), c.target_host))
    checks.append(("auth host allowed (login only)", c._is_allowed(f"https://{c.auth_host}/oauth2"), c.auth_host))
    for u in off_hosts:
        blocked = False
        try:
            c._guard(u)
        except HostBlocked:
            blocked = True
        checks.append((f"off-host refused: {u}", blocked, "R9"))
    return checks


def main() -> int:
    ap = argparse.ArgumentParser(description="Target client runner (attacker zone).")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", help="offline wiring/allow-list self-check ($0)")
    g.add_argument("--connectivity", action="store_true", help="LIVE: login + one benign message")
    g.add_argument("--message", type=str, help="LIVE: login + send this message")
    g.add_argument("--attack", type=str, metavar="SEED_ID",
                   help="LIVE: login + send one attack seed (e.g. B-001), capture the transcript")
    args = ap.parse_args()

    try:
        client = TargetClient()
    except ValueError as e:
        print(f"config error: {e}")
        return 2

    # Default to the offline self-check when nothing live was requested, or when
    # creds are absent — never silently fire a live call.
    live_requested = args.connectivity or args.message is not None or args.attack is not None
    if args.dry_run or not live_requested:
        print("=== DRY RUN (offline, $0, no credentials used) ===")
        print(f"target={client.base}  allow={sorted(client.allow)}")
        ok_all = True
        for name, ok, note in _self_check(client):
            ok_all &= ok
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}  ({note})")
        creds = bool(client.username and client.password)
        print(f"credentials present in env: {creds}")
        client.close()
        if not live_requested and not args.dry_run:
            print("\n(no live mode requested — showing dry-run. Use --connectivity or --message to go live.)")
        return 0 if ok_all else 1

    # ---- LIVE attack path: send ONE seed, capture the transcript (Judge is separate) --
    if args.attack is not None:
        case = next((c for c in seed_loader.load_all() if c.id == args.attack), None)
        if case is None:
            print(f"unknown seed id: {args.attack!r} (see evals/seeds/*.yaml)")
            client.close()
            return 2
        print(f"=== LIVE ATTACK — seed {case.id} (category {case.category.value}, "
              f"owasp {[o.value for o in case.owasp]}) ===")
        try:
            client.login()
            print(f"authenticated={client.authenticated}")
            tx = RedTeam(client).run_case(case)          # attacker zone only — no judging here (R7)
            print(f"captured transcript: correlation_id={tx.correlation_id} "
                  f"target_correlation_id={tx.target_correlation_id}")
            _print_transcript_redacted(tx, client.password, case.canaries)
            path = _write_transcript(tx)
            print(f"\nraw transcript saved (gitignored, for the offline Judge): {path}")
            print("next: score it offline ($0) with\n"
                  f"  PYTHONPATH=. python3 adv_platform/judge/run_judge.py {path}")
            return 0
        except HostBlocked as e:
            print(f"BLOCKED (R9): {e}")
            return 1
        except AuthError as e:
            print(f"AUTH ERROR: {e}")
            return 1
        except TargetUnreachable as e:
            print(f"TARGET UNREACHABLE: {redact(str(e), client.password)}")
            return 1
        finally:
            client.close()

    # ---- LIVE connectivity / single message -------------------------------------
    print("=== LIVE credentialed round-trip ===")
    try:
        client.login()
        print(f"authenticated={client.authenticated}")
        msg = BENIGN if args.connectivity else args.message
        res = client.chat(msg)
        print(f"POST /chat -> {res.status_code}")
        print("response (redacted):", redact(res.response, client.password, 300))
        print("signals:", json.dumps({
            "conversation_id_present": bool(res.conversation_id),
            "target_correlation_id_present": bool(res.correlation_id),
            "verification_passed": res.verification_passed,
            "enforced_warnings": len(res.enforced_warnings),
            "flagged_claims": len(res.flagged_claims),
        }))
        return 0
    except HostBlocked as e:
        print(f"BLOCKED (R9): {e}")
        return 1
    except AuthError as e:
        print(f"AUTH ERROR: {e}")
        return 1
    except TargetUnreachable as e:
        print(f"TARGET UNREACHABLE: {redact(str(e), client.password)}")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
