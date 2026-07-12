#!/usr/bin/env python3
"""Attack 09: Data Exfil (Chapter 9).

Baseline: quote-breaking OR-1=1 payload returns every row.
Guarded:  JSON Schema pattern regex rejects the payload at the schema layer (400).

Run standalone:  python attacks/09_data_exfil.py [before|after]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import BaselineServer, GuardedServer, attack_09_data_exfil, EVIDENCE  # noqa: E402


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    server = (BaselineServer if label == "before" else GuardedServer)()
    exploited, detail = attack_09_data_exfil(server)
    result = {"attack": "data_exfil", "exploited": exploited, "detail": detail}
    print(json.dumps(result, indent=2, default=str))
    with open(EVIDENCE / f"09-{label}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
