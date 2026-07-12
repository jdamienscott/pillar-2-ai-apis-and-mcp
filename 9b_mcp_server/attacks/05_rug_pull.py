#!/usr/bin/env python3
"""Attack 05: Rug Pull (Chapter 9).

Baseline: tool definition updated after approval; no hash check.
Guarded:  pin-and-hash rejects the changed definition (409).

Run standalone:  python attacks/05_rug_pull.py [before|after]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import BaselineServer, GuardedServer, attack_05_rug_pull, EVIDENCE  # noqa: E402


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    server = (BaselineServer if label == "before" else GuardedServer)()
    exploited, detail = attack_05_rug_pull(server)
    result = {"attack": "rug_pull", "exploited": exploited, "detail": detail}
    print(json.dumps(result, indent=2, default=str))
    with open(EVIDENCE / f"05-{label}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
