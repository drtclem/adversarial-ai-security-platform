"""Contract tests — both sides of every agent boundary against /contracts. Local, $0.

Run:  PYTHONPATH=. ./.venv/bin/python evals/contracts/test_contracts.py
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Optional

from jsonschema.validators import validator_for

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
import export_contracts as ec  # noqa: E402

from adv_platform.documentation.documentation import Documentation  # noqa: E402
from adv_platform.judge.judge import Judge  # noqa: E402
from adv_platform.models import (  # noqa: E402
    AttackCase, CampaignBrief, ErrorType, Event, EventType, Finding, PlatformError,
    Transcript, Verdict,
)
from adv_platform.observability.events import EventSink  # noqa: E402
from adv_platform.orchestrator.orchestrator import Orchestrator  # noqa: E402
from adv_platform.redteam import seeds as seed_loader  # noqa: E402
from adv_platform.redteam.mutator import Mutator  # noqa: E402
from adv_platform.redteam.redteam import RedTeam  # noqa: E402
from adv_platform.target_client.client import ChatResult  # noqa: E402

V = ec.ROOT / ec.CONTRACT_VERSION
SEEDS = seed_loader.load_all()


def _schema(rel: str) -> dict:
    return json.loads((V / rel).read_text())


def _errors(rel: str, obj: dict) -> list[str]:
    s = _schema(rel)
    return [e.message for e in validator_for(s)(s).iter_errors(obj)]


class Fixture:
    def chat(self, message: str, conversation_id: Optional[str] = None) -> ChatResult:
        return ChatResult(status_code=200, response="Patient SSN 123-45-6789.")


class NoLLM:
    def complete(self, *a, **k):
        raise AssertionError("deterministic path only")


def _producers() -> dict[str, list]:
    brief = Orchestrator(SEEDS).decide({}).brief
    case = next(s for s in SEEDS if s.id == "B-001")
    tx = RedTeam(Fixture()).run_case(case)
    v = Judge(NoLLM()).judge(tx, canaries=case.canaries)
    f = Documentation().write_finding(v, tx, case)
    sink = EventSink()
    sink.emit(EventType.VERDICT, correlation_id=tx.correlation_id, payload={"case_id": case.id})
    child = Mutator(lambda *a, **k: "")._child(case, ["reworded"], "llm-test")
    return {"campaign_brief": [brief], "attack_case": SEEDS + [child], "transcript": [tx],
            "verdict": [v], "finding": [f], "event": sink.all(),
            "platform_error": [PlatformError(type=t, message="x") for t in ErrorType]}


CONSUMER = {"campaign_brief": CampaignBrief, "attack_case": AttackCase, "transcript": Transcript,
            "verdict": Verdict, "finding": Finding, "event": Event, "platform_error": PlatformError}


def check_committed_schemas_match_models() -> tuple[bool, str]:
    built = ec.build()
    stale = [rel for rel, s in built.items() if not (V / rel).exists() or json.loads((V / rel).read_text()) != s]
    return not stale, f"{len(built)} files; stale: {stale or 'none'} (fix: scripts/export_contracts.py)"


def check_producers_conform() -> tuple[bool, str]:
    bad, n = [], 0
    for stem, objs in _producers().items():
        for o in objs:
            n += 1
            errs = _errors(f"{stem}.schema.json", o.model_dump(mode="json"))
            if errs:
                bad.append(f"{stem}: {errs[0][:80]}")
    return not bad, f"{n} real producer messages validate; failures: {bad or 'none'}"


def check_consumers_accept_producer_output() -> tuple[bool, str]:
    bad = []
    for stem, objs in _producers().items():
        for o in objs:
            wire = o.model_dump_json()
            back = CONSUMER[stem].model_validate_json(wire)
            if back.model_dump(mode="json") != o.model_dump(mode="json"):
                bad.append(stem)
    return not bad, f"round-trip through the wire format unchanged; mismatches: {sorted(set(bad)) or 'none'}"


def check_schema_and_consumer_agree_on_missing_required() -> tuple[bool, str]:
    bad = []
    for stem, objs in _producers().items():
        req = _schema(f"{stem}.schema.json").get("required", [])
        if not req:
            continue
        msg = objs[0].model_dump(mode="json")
        msg.pop(req[0])
        schema_rejects = bool(_errors(f"{stem}.schema.json", msg))
        try:
            CONSUMER[stem].model_validate(msg)
            consumer_rejects = False
        except Exception:
            consumer_rejects = True
        if not (schema_rejects and consumer_rejects):
            bad.append(f"{stem} (missing {req[0]})")
    return not bad, f"schema and consumer both reject a missing required field; disagreements: {bad or 'none'}"


def check_error_schemas_published_and_typed() -> tuple[bool, str]:
    missing = [e for e in ec.REQUIRED_ERRORS if not (V / "errors" / f"{e}.schema.json").exists()]
    wrong = _errors("errors/target_unreachable.schema.json",
                    PlatformError(type=ErrorType.BUDGET_EXCEEDED).model_dump(mode="json"))
    right = _errors("errors/budget_exceeded.schema.json",
                    PlatformError(type=ErrorType.BUDGET_EXCEEDED).model_dump(mode="json"))
    ok = not missing and wrong and not right
    return ok, f"spec's 5 error schemas present (missing: {missing or 'none'}); mislabeled error rejected: {bool(wrong)}"


def check_drift_classifier() -> tuple[bool, str]:
    base = {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"},
            "b": {"type": "string", "enum": ["x", "y"]}}}
    add_opt = json.loads(json.dumps(base)); add_opt["properties"]["c"] = {"type": "integer"}
    add_req = json.loads(json.dumps(add_opt)); add_req["required"].append("c")
    removed = json.loads(json.dumps(base)); del removed["properties"]["b"]
    enum_cut = json.loads(json.dumps(base)); enum_cut["properties"]["b"]["enum"] = ["x"]
    got = [ec.classify(base, base), ec.classify(base, add_opt), ec.classify(base, add_req),
           ec.classify(base, removed), ec.classify(base, enum_cut)]
    want = ["same", "additive", "breaking", "breaking", "breaking"]
    return got == want, f"same/optional/required/removed/enum-cut -> {got}"


def check_every_schema_is_versioned() -> tuple[bool, str]:
    bad = [p.name for p in V.rglob("*.schema.json")
           if json.loads(p.read_text()).get("x-contract-version") != ec.CONTRACT_VERSION]
    return not bad, f"all schemas carry x-contract-version={ec.CONTRACT_VERSION}; unversioned: {bad or 'none'}"


CHECKS = [
    check_committed_schemas_match_models,
    check_producers_conform,
    check_consumers_accept_producer_output,
    check_schema_and_consumer_agree_on_missing_required,
    check_error_schemas_published_and_typed,
    check_drift_classifier,
    check_every_schema_is_versioned,
]


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
