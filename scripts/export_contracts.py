"""Publish the inter-agent message contracts as versioned JSON Schema in /contracts.

The Pydantic models in adv_platform/models.py are the source of truth; this script
mirrors them as JSON Schema (draft 2020-12) so any agent, in any language, can
validate a message without importing our code.

  PYTHONPATH=. ./.venv/bin/python scripts/export_contracts.py          # (re)write contracts/<version>/
  PYTHONPATH=. ./.venv/bin/python scripts/export_contracts.py --check  # exit 1 if committed != models

--check also classifies any drift as ADDITIVE (new optional field / new enum value)
or BREAKING (field removed, new required field, type changed, enum value removed).
Breaking drift must ship as a new version directory plus a MIGRATIONS.md entry.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

from adv_platform import models as m

CONTRACT_VERSION = "v1"
ROOT = pathlib.Path(__file__).resolve().parents[1] / "contracts"

# file stem -> (model, producer, consumer, what it is)
MESSAGES = {
    "campaign_brief": (m.CampaignBrief, "Orchestrator", "Red Team", "what to attack next, cap, stop conditions, rationale"),
    "attack_case": (m.AttackCase, "seed suite / Red Team mutator", "Red Team", "one seed or mutated attack, with its ratings"),
    "transcript": (m.Transcript, "Red Team", "Judge", "attacker turns + target replies + the invariant (no Red Team reasoning, R7)"),
    "verdict": (m.Verdict, "Judge", "Documentation, regression harness, Orchestrator", "pass/fail/partial/error + evidence"),
    "finding": (m.Finding, "Documentation", "exploit DB, D4 human-approval gate", "drafted vulnerability record"),
    "event": (m.Event, "every agent", "event store, Orchestrator, dashboard", "PHI-redacted observability row"),
    "platform_error": (m.PlatformError, "any agent", "any agent, event store", "typed error; never scored as a pass (R11)"),
}
# The five failure modes the spec names, each published as its own error schema.
REQUIRED_ERRORS = ["target_unreachable", "budget_exceeded", "judge_timeout", "no_findings", "regression_detected"]


def build() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for stem, (model, producer, consumer, what) in MESSAGES.items():
        schema = model.model_json_schema(mode="validation")
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
                  "$id": f"contracts/{CONTRACT_VERSION}/{stem}.schema.json",
                  "x-contract-version": CONTRACT_VERSION,
                  "x-producer": producer, "x-consumer": consumer, "description": what, **schema}
        out[f"{stem}.schema.json"] = schema
    base = out["platform_error.schema.json"]
    for et in m.ErrorType:
        s = copy.deepcopy(base)
        s["$id"] = f"contracts/{CONTRACT_VERSION}/errors/{et.value}.schema.json"
        s["title"] = f"PlatformError[{et.value}]"
        s["description"] = f"Typed error '{et.value}'. Never scored as a pass (R11)."
        s["properties"]["type"] = {"const": et.value}
        s["required"] = sorted(set(s.get("required", [])) | {"type"})
        out[f"errors/{et.value}.schema.json"] = s
    out["index.json"] = {
        "version": CONTRACT_VERSION,
        "source_of_truth": "adv_platform/models.py (Pydantic v2)",
        "messages": [{"name": stem, "file": f"{stem}.schema.json", "producer": p, "consumer": c}
                     for stem, (_, p, c, _) in MESSAGES.items()],
        "errors": [f"errors/{et.value}.schema.json" for et in m.ErrorType],
        "required_errors": REQUIRED_ERRORS,
    }
    return out


def _props(schema: dict, defs: dict, seen=None) -> dict:
    """Flatten a schema to {path: (types, enum, required)} for drift classification."""
    seen = seen or set()
    out = {}

    def walk(node, path, required):
        if "$ref" in node:
            ref = node["$ref"].split("/")[-1]
            if ref in seen:
                return
            node = defs.get(ref, {})
            seen.add(ref)
        types = tuple(sorted(str(x.get("type", x.get("$ref", ""))) for x in node.get("anyOf", [node])))
        out[path] = (types, tuple(node.get("enum", ())), required)
        for k, v in node.get("properties", {}).items():
            walk(v, f"{path}.{k}", k in node.get("required", []))
    walk(schema, "", True)
    return out


def classify(old: dict, new: dict) -> str:
    """'same' | 'additive' | 'breaking' between two versions of one schema."""
    if old == new:
        return "same"
    o, n = _props(old, old.get("$defs", {})), _props(new, new.get("$defs", {}))
    for path, (types, enum, _req) in o.items():
        if path not in n:
            return "breaking"                                  # field removed
        ntypes, nenum, _ = n[path]
        if ntypes != types and not set(types) <= set(ntypes):
            return "breaking"                                  # type changed/narrowed
        if enum and not set(enum) <= set(nenum):
            return "breaking"                                  # enum value removed
    for path, (_t, _e, req) in n.items():
        if path not in o and req:
            return "breaking"                                  # new required field
    return "additive"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    target = ROOT / CONTRACT_VERSION
    built = build()
    if a.check:
        worst = "same"
        for rel, schema in built.items():
            f = target / rel
            old = json.loads(f.read_text()) if f.exists() else None
            kind = "additive" if old is None else classify(old, schema)
            if kind != "same":
                print(f"{kind.upper():9} {rel}")
                worst = "breaking" if "breaking" in (worst, kind) else "additive"
        if worst == "same":
            print(f"contracts/{CONTRACT_VERSION} matches the models")
            return 0
        print(f"\ncontracts/{CONTRACT_VERSION} is stale ({worst}). "
              + ("Bump CONTRACT_VERSION and add a MIGRATIONS.md entry." if worst == "breaking"
                 else "Re-run without --check and note it in MIGRATIONS.md."))
        return 1
    for rel, schema in built.items():
        f = target / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(built)} files to contracts/{CONTRACT_VERSION}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
