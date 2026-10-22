"""Deploy hook: record a new Co-Pilot version and run the regression suite if it changed.

Call this from the Co-Pilot's deploy step (or by hand) with the version just deployed:
  PYTHONPATH=. ./.venv/bin/python scripts/check_target_version.py --marker "$(git rev-parse --short HEAD)" --live
Exit 1 if a previously-fixed vulnerability reappeared, so a deploy pipeline can block.

--live   replay every published VULN's attack against the deployed target (3x each,
         evals/regression/live_replay.py) on top of the stored-fixture check. Needs
         TARGET_USERNAME / TARGET_PASSWORD; sends real traffic; platform spend $0.
without  stored-fixture check only (offline, $0). That proves the scoring logic but
         cannot tell one target version from another.
"""

from __future__ import annotations

import argparse
import sys

from adv_platform.config import Config
from adv_platform.harness.version_trigger import VersionLedger, check_and_trigger, default_gate, live_gate


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--marker", default=None, help="deployed version (default: TARGET_VERSION from .env)")
    ap.add_argument("--live", action="store_true", help="replay published VULNs against the live target")
    a = ap.parse_args()
    cfg = Config.load()
    ledger = VersionLedger(cfg.version_ledger_path)
    if not a.live:
        r = check_and_trigger(a.marker or cfg.target_version, ledger, gate=default_gate)
        print(r.to_dict())
        return 1 if r.blocked else 0

    from adv_platform.target_client.client import TargetClient  # noqa: PLC0415
    with TargetClient(base_url=cfg.target_base_url, username=cfg.target_username,
                      password=cfg.target_password, auth_host=cfg.target_auth_host) as client:
        client.login()
        marker = a.marker or cfg.target_version
        r = check_and_trigger(marker, ledger, gate=live_gate(client.chat_sequence, marker=marker))
    print(r.to_dict())
    if r.action == "regression-run":
        for vid, x in (ledger.load()[-1]["regression"].get("live_replay") or {}).items():
            print(f"  live replay {vid} [{x['status']}]: {x['verdict']} "
                  f"(leaked {x['leaked']}/{x['repeats']}, inconclusive {x['inconclusive']})")
    return 1 if r.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
