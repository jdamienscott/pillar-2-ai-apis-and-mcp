# 9b_mcp_server/auth/verify.py
# Audience-bound token verifier — reused from Chapter 6 page 44.
# The MCP_AUDIENCE claim closes the confused-deputy class.

from fastapi import Header, HTTPException
from jose import jwt, JWTError
import httpx
import os

JWKS_URL          = os.environ["JWKS_URL"]
EXPECTED_AUDIENCE = os.environ["MCP_AUDIENCE"]    # e.g. api://pillar-2-mcp
EXPECTED_ISSUER   = os.environ["TOKEN_ISSUER"]


async def fetch_jwks() -> dict:
    async with httpx.AsyncClient() as c:
        resp = await c.get(JWKS_URL)
        resp.raise_for_status()
        return resp.json()


async def verify_token(authorization: str = Header(...)) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization[7:]

    try:
        claims = jwt.decode(
            token,
            key=await fetch_jwks(),
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            algorithms=["RS256"],
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token invalid: {e}")

    # The audience check is the line that closes the confused-deputy class.
    # A token issued for api://other-service cannot be replayed here.
    if claims.get("aud") != EXPECTED_AUDIENCE:
        raise HTTPException(status_code=403, detail="Token not bound to this audience")

    # IMPORTANT: this server uses its OWN downstream credentials —
    # it does NOT forward the caller's token to downstream services.
    # That is the architectural decision that closes token-passthrough.
    return claims
