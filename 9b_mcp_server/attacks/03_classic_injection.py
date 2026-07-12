#!/usr/bin/env python3
"""Attack 3: Classic injection through tool args — SQL, command, path (Chapter 9).

The OWASP API injection set delivered through the customer_id tool argument
rather than an HTTP query string. On the baseline the string-interpolated SQL
executes the payload. The guarded build's JSON Schema pattern regex on
customer_id rejects all three payloads with 400 before any SQL is constructed.

Run standalone:  python attacks/03_classic_injection.py [before|after]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import BaselineServer, GuardedServer, attack_03_classic_injection, EVIDENCE  # noqa: E402


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    server = (BaselineServer if label == "before" else GuardedServer)()
    exploited, detail = attack_03_classic_injection(server)
    result = {"attack": "classic_injection", "exploited": exploited, "detail": detail}
    print(json.dumps(result, indent=2, default=str))
    with open(EVIDENCE / f"03-{label}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
