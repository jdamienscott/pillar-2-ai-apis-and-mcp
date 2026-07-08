# 9b_mcp_server/tools/lookup_customer.py — guarded tool (Chapter 9)
# Three changes from the baseline:
# 1. JSON Schema with additionalProperties:false closes mass-assignment
# 2. Pattern regex on customer_id closes format-based injection
# 3. Parameterized SQL with WHERE owner_user_id = ? closes cross-user reads

from jsonschema import validate, ValidationError
from fastapi import HTTPException
import sqlite3

# additionalProperties:false is the line that closes mass-assignment.
SCHEMA = {
    "type": "object",
    "required": ["customer_id"],
    "additionalProperties": False,
    "properties": {
        "customer_id": {
            "type": "string",
            # Pattern: must start with "cust_" followed by 16 lowercase alphanumerics.
            # Cannot carry a SQL fragment, shell command, or path traversal.
            "pattern": r"^cust_[a-z0-9]{16}$",
        }
    },
}


def lookup_customer(args: dict, acting_user_id: str) -> dict:
    """Look up a customer record scoped to the authenticated user.

    Args:
        args:            Validated tool arguments from the MCP client.
        acting_user_id:  The authenticated user's subject claim.

    Returns:
        {"customer": row} if found; {"error": "not found"} if not.
    """
    try:
        validate(instance=args, schema=SCHEMA)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Args invalid: {e.message}")

    db = sqlite3.connect("db/customers.sqlite")

    # Parameterized query — no string interpolation.
    # The WHERE owner_user_id = ? clause closes cross-user reads.
    row = db.execute(
        "SELECT id, name, plan FROM customers "
        "WHERE id = ? AND owner_user_id = ?",
        (args["customer_id"], acting_user_id),
    ).fetchone()

    return {"customer": row} if row else {"error": "not found"}
