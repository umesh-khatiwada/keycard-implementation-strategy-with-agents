"""Lab 09: Cedar policies as code, tested OFFLINE (no server needed).

Evaluates mockzone/policies/active/*.cedar (plus optional extra files) with the
Cedar engine against a decision matrix: principal, action, resource, context
-> expected decision. Same idea as Console > Policies > Testing.

  python labs/09_policies/policy_matrix.py
  python labs/09_policies/policy_matrix.py --with 91_freeze-issue-creation   # add a policy from available/
  python labs/09_policies/policy_matrix.py --with 92_default-user-grants     # see what a new zone allows

Edit a .cedar file or add rows below and re-run: a failing row prints what matched.
Entity/attribute names follow the Keycard policy schema docs (Keycard::User,
Group, Application, Resource; context.on_behalf / impersonate / subject).
"""
import argparse
import json
import sys
from pathlib import Path

import cedarpy

ROOT = Path(__file__).resolve().parents[2]
POL = ROOT / "mockzone" / "policies"
ZONE = json.loads((ROOT / "mockzone" / "zone.json").read_text())

GH, MCP, ORCH, TRIAGE = "https://api.github.com", "http://localhost:8000/mcp", "http://localhost:8001", "http://localhost:8002"
TOOL = lambda t: f"mcp::tools/call::{t}"  # noqa: E731

# (description, principal, action, resource, context, expected_allow)
MATRIX = [
    ("alice (oncall) may use the orchestrator", ("User", "alice"), "any", ORCH, {}, True),
    ("carol (no groups) is denied: default deny", ("User", "carol"), "any", ORCH, {}, False),
    ("cli may sign users in to orchestrator", ("Application", "oncall-cli"), "any", ORCH, {"on_behalf": True, "subject": "alice"}, True),
    ("orchestrator may delegate to triage FOR a user", ("Application", "incident-orchestrator"), "any", TRIAGE, {"on_behalf": True, "subject": "alice"}, True),
    ("orchestrator may NOT call triage as itself", ("Application", "incident-orchestrator"), "any", TRIAGE, {"on_behalf": False}, False),
    ("orchestrator may NOT reach GitHub directly", ("Application", "incident-orchestrator"), "any", GH, {"on_behalf": True, "subject": "alice"}, False),
    ("triage may reach GitHub for a user", ("Application", "triage-agent"), "any", GH, {"on_behalf": True, "subject": "alice"}, True),
    ("nightly digest as itself -> GitHub", ("Application", "nightly-digest"), "any", GH, {}, True),
    ("nightly digest may NOT impersonate (default)", ("Application", "nightly-digest"), "any", GH, {"impersonate": True, "subject": "alice"}, False),
    ("egress proxy may impersonate alice", ("Application", "egress-proxy"), "any", GH, {"impersonate": True, "subject": "alice"}, True),
    ("egress proxy may NOT impersonate bob", ("Application", "egress-proxy"), "any", GH, {"impersonate": True, "subject": "bob"}, False),
    ("bob may list MCP tools", ("User", "bob"), "mcp::tools/list", MCP, {"on_behalf": True, "subject": "bob"}, True),
    ("bob may call a read tool", ("User", "bob"), TOOL("list_incident_issues"), MCP, {"on_behalf": True, "subject": "bob"}, True),
    ("bob may NOT open issues (commanders only)", ("User", "bob"), TOOL("open_incident_issue"), MCP, {"on_behalf": True, "subject": "bob"}, False),
    ("alice (commander) may open issues", ("User", "alice"), TOOL("open_incident_issue"), MCP, {"on_behalf": True, "subject": "alice"}, True),
    ("unknown tool is denied", ("User", "alice"), TOOL("delete_repo"), MCP, {"on_behalf": True, "subject": "alice"}, False),
]


def entities(group_members):
    ents = []
    for u, d in ZONE["users"].items():
        ents.append({"uid": {"type": "Keycard::User", "id": u},
                     "attrs": {"identifier": d["email"], "email": d["email"]},
                     "parents": [{"type": "Keycard::Group", "id": g} for g, m in group_members.items() if u in m]})
    for a, d in ZONE["applications"].items():
        ents.append({"uid": {"type": "Keycard::Application", "id": a},
                     "attrs": {"identifier": a, "name": d["name"], "credential_type": d["credential_type"],
                               "traits": d.get("traits", [])}, "parents": []})
    for r, d in ZONE["resources"].items():
        ents.append({"uid": {"type": "Keycard::Resource", "id": r},
                     "attrs": {"identifier": r, "name": d["name"], "scopes": d.get("scopes", [])}, "parents": []})
    ents.append({"uid": {"type": "Keycard::Action", "id": "mcp::tools/list"}, "attrs": {},
                 "parents": [{"type": "Keycard::Action", "id": "MCPProtocol"}]})
    return ents


def policy_ids(text):
    js = json.loads(cedarpy.policies_to_json_str(text))
    return {k: v.get("annotations", {}).get("id", k) for k, v in js["staticPolicies"].items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--with", dest="extra", action="append", default=[], help="policy in available/ to add")
    ap.add_argument("--remove-from-group", nargs=2, metavar=("USER", "GROUP"))
    a = ap.parse_args()
    files = sorted((POL / "active").glob("*.cedar")) + [POL / "available" / (e.removesuffix(".cedar") + ".cedar") for e in a.extra]
    text = "\n".join(f.read_text() for f in files)
    ids = policy_ids(text)
    members = {g: [u for u, d in ZONE["users"].items() if g in d["groups"]]
               for g in {g for d in ZONE["users"].values() for g in d["groups"]}}
    if a.remove_from_group:
        u, g = a.remove_from_group
        members[g] = [m for m in members[g] if m != u]
    ents = entities(members)
    print("policy files:", [f.name for f in files], "\n")
    fails = 0
    for desc, (ptype, pid), action, res, ctx, expect in MATRIX:
        c = {"on_behalf": ctx.get("on_behalf", False), "impersonate": ctx.get("impersonate", False),
             "resource": {"__entity": {"type": "Keycard::Resource", "id": res}}}
        if "subject" in ctx:
            c["subject"] = {"__entity": {"type": "Keycard::User", "id": ctx["subject"]}}
        r = cedarpy.is_authorized({"principal": f'Keycard::{ptype}::"{pid}"', "action": f'Keycard::Action::"{action}"',
                                   "resource": f'Keycard::Resource::"{res}"', "context": c}, text, ents)
        got = r.decision == cedarpy.Decision.Allow
        why = [ids.get(p, p) for p in r.diagnostics.reasons]
        mark = "PASS" if got == expect else "FAIL"
        fails += got != expect
        print(f"{mark}  {'ALLOW' if got else 'DENY ':5}  {desc:52} {why or ''}")
        for e in r.diagnostics.errors:
            print("      cedar error:", e)
    print(f"\n{len(MATRIX) - fails}/{len(MATRIX)} rows as expected")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
