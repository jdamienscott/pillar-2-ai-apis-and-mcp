#!/usr/bin/env python3
"""Attack 07: Cost Bomb (Chapter 9).

Baseline: unbounded tool-call loop runs to completion.
Guarded:  per-token rate cap (60/min) stops the loop with 429.

Run standalone:  python attacks/07_cost_bomb.py [before|after]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import BaselineServer, GuardedServer, attack_07_cost_bomb, EVIDENCE  # noqa: E402


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    server = (BaselineServer if label == "before" else GuardedServer)()
    exploited, detail = attack_07_cost_bomb(server)
    result = {"attack": "cost_bomb", "exploited": exploited, "detail": detail}
    print(json.dumps(result, indent=2, default=str))
    with open(EVIDENCE / f"07-{label}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
