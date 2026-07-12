#!/usr/bin/env python3
"""Attack 08: Identity Confusion (Chapter 9).

Baseline: user A reads user B's row (no per-user scope).
Guarded:  WHERE owner_user_id = ? returns not found for cross-user reads.

Run standalone:  python attacks/08_identity_confusion.py [before|after]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import BaselineServer, GuardedServer, attack_08_identity_confusion, EVIDENCE  # noqa: E402


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    server = (BaselineServer if label == "before" else GuardedServer)()
    exploited, detail = attack_08_identity_confusion(server)
    result = {"attack": "identity_confusion", "exploited": exploited, "detail": detail}
    print(json.dumps(result, indent=2, default=str))
    with open(EVIDENCE / f"08-{label}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
