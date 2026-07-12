#!/usr/bin/env python3
"""Attack 06: Tool Squatting (Chapter 9).

Baseline: a similar-named tool registers freely.
Guarded:  client-side allowlist rejects the unknown tool name (403).

Run standalone:  python attacks/06_tool_squatting.py [before|after]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import BaselineServer, GuardedServer, attack_06_tool_squatting, EVIDENCE  # noqa: E402


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    server = (BaselineServer if label == "before" else GuardedServer)()
    exploited, detail = attack_06_tool_squatting(server)
    result = {"attack": "tool_squatting", "exploited": exploited, "detail": detail}
    print(json.dumps(result, indent=2, default=str))
    with open(EVIDENCE / f"06-{label}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)


if __name__ == "__main__":
    main()
