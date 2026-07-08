# 9b_mcp_server/harden.py — five hardening additions (Chapter 9)

import hashlib
from fastapi import HTTPException

# ---------------------------------------------------------------
# 1. Pin and hash-verify tool definitions
#    Detects rug pulls and supply-chain tampering.
# ---------------------------------------------------------------
EXPECTED_DESC   = "Look up a customer by ID. Returns name and plan."
EXPECTED_SCHEMA = '{"type":"object","required":["customer_id"],"additionalProperties":false,"properties":{"customer_id":{"type":"string","pattern":"^cust_[a-z0-9]{16}$"}}}'

PINNED = {
    "lookup_customer": {
        "description_hash": hashlib.sha256(EXPECTED_DESC.encode()).hexdigest(),
        "schema_hash":      hashlib.sha256(EXPECTED_SCHEMA.encode()).hexdigest(),
    }
}


def verify_pinned(name: str, current_desc: str, current_schema: str) -> bool:
    """Return True if the tool's description and schema match the pinned hashes."""
    p = PINNED.get(name)
    if p is None:
        return False  # unknown tool — reject
    desc_ok   = hashlib.sha256(current_desc.encode()).hexdigest()   == p["description_hash"]
    schema_ok = hashlib.sha256(current_schema.encode()).hexdigest() == p["schema_hash"]
    return desc_ok and schema_ok


# ---------------------------------------------------------------
# 2. Client-side tool allowlist
#    Catches squatting and unauthorized tool additions.
# ---------------------------------------------------------------
ALLOWED_TOOLS = {"lookup_customer"}


def check_tool_allowed(tool_name: str) -> None:
    if tool_name not in ALLOWED_TOOLS:
        raise HTTPException(status_code=403, detail=f"Tool not in allowlist: {tool_name}")


# ---------------------------------------------------------------
# 3. Human approval gate for destructive tools
# ---------------------------------------------------------------
DESTRUCTIVE = {"delete_customer", "change_plan", "issue_refund"}


def gate_destructive(tool_name: str, approval_token: str | None) -> None:
    if tool_name in DESTRUCTIVE and not approval_token:
        raise HTTPException(
            status_code=403,
            detail=f"Human approval required for destructive tool: {tool_name}",
        )


# ---------------------------------------------------------------
# 4. Sandbox via egress allowlist
#    Implemented in the Chapter 5 VPC module (ai_egress_allowlist SG).
#    Attach that SG to every EC2 / container running this server.
# ---------------------------------------------------------------

# ---------------------------------------------------------------
# 5. DPoP / sender-constrained token verification (stub)
#    Full implementation in auth/verify_dpop.py (see repo).
#    The DPoP header binds the token to the client's key-pair so
#    a stolen bearer token cannot be replayed by a different client.
# ---------------------------------------------------------------
def verify_dpop_header(dpop_header: str | None, token: str) -> bool:
    """Stub: in production, verify the DPoP JWT signature and nonce."""
    # TODO: implement per RFC 9449
    return dpop_header is not None
