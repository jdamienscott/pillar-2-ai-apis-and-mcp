#!/usr/bin/env python3
"""What Still Works — legitimate calls succeed on the guarded server (Chapter 9).

Hiring managers grade this hardest: a server that refuses everything is not a
deliverable. This proves the guarded build still does its real job. A user
requesting their OWN customer, by a valid ID, with a correctly-audience-bound
token, gets the row back.

Run standalone:  python attacks/10_legitimate_calls.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import GuardedServer, MCP_AUDIENCE, EVIDENCE  # noqa: E402


def main():
    server = GuardedServer()
    token_a = {"sub": "user-a", "aud": MCP_AUDIENCE}

    cases = []

    # 1. User A reads their OWN customer by a valid ID — should SUCCEED.
    r1 = server.call_tool("lookup_customer",
                          {"customer_id": "cust_aaaaaaaaaaaaaaaa"},
                          token=token_a)
    cases.append({
        "case": "owner reads own customer by valid ID",
        "expected": "success",
        "result": r1,
        "passed": r1.get("customer") is not None,
    })

    # 2. User A reads their second owned customer — should SUCCEED.
    r2 = server.call_tool("lookup_customer",
                          {"customer_id": "cust_cccccccccccccccc"},
                          token=token_a)
    cases.append({
        "case": "owner reads second owned customer",
        "expected": "success",
        "result": r2,
        "passed": r2.get("customer") is not None,
    })

    all_passed = all(c["passed"] for c in cases)
    out = {"what_still_works": cases, "all_passed": all_passed}
    print(json.dumps(out, indent=2, default=str))
    with open(EVIDENCE / "10-legitimate.json", "w") as f:
        json.dump(out, f, indent=2, default=str)

    print(f"\nLegitimate calls all succeed on guarded server: {all_passed}")
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
