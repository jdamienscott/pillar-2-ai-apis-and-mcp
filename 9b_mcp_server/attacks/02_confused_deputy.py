#!/usr/bin/env python3
"""Attack 2: Confused Deputy — replay a token issued for another service (Chapter 9).

A token minted for api://other-service is presented to this server. Without an
audience check the server acts as a "confused deputy" and honors it. The guarded
build binds every token to MCP_AUDIENCE (api://pillar-2-mcp) and rejects the
mismatch with 403.

Run standalone:  python attacks/02_confused_deputy.py [before|after]
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness import BaselineServer, GuardedServer, attack_02_confused_deputy, EVIDENCE  # noqa: E402


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "before"
    server = (BaselineServer if label == "before" else GuardedServer)()
    exploited, detail = attack_02_confused_deputy(server)
    result = {"attack": "confused_deputy", "exploited": exploited, "detail": detail}
    print(json.dumps(result, indent=2, default=str))
    with open(EVIDENCE / f"02-{label}.json", "w") as f:
        json.dump(result, f, indent=2, default=str)
    # Baseline: forged-audience token accepted (no aud check).
    # Guarded:  403, token not bound to this audience.


if __name__ == "__main__":
    main()
