#!/usr/bin/env python3
"""Attack 04: Token Passthrough (Chapter 9).

Baseline: server forwards the caller's bearer to downstream services (principal = user).
Guarded:  server uses its OWN credentials; downstream principal = server role.

Run standalone:  python attacks/04_token_passthrough.py [before|after]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import BaselineServer, GuardedServer, attack_04_token_passthrough, EVIDENCE  # noqa: E402


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    server = (BaselineServer if label == "before" else GuardedServer)()
    exploited, detail = attack_04_token_passthrough(server)
    result = {"attack": "token_passthrough", "exploited": exploited, "detail": detail}
    print(json.dumps(result, indent=2, default=str))
    with open(EVIDENCE / f"04-{label}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
