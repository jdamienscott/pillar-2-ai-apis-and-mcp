# Pillar 2: AI APIs & MCP — Vulnerable Baseline Analysis

## Deployment Summary

**Vulnerable Version (Baseline):**
- Lambda: `pillar-2-bedrock-api-vulnerable`
- Region: us-east-1
- Invocation: Direct Lambda (attack testing via boto3)
- Status: LIVE ✓

**Architecture:**
```
Caller (no auth)
    ↓
Lambda Handler (direct, no FastAPI)
    ↓
Bedrock Runtime (bedrock:* IAM policy)
    ↓
Claude Sonnet 4.5 Model
```

## Vulnerabilities Discovered

### 1. Model Enumeration (CRITICAL)

**Attack:** POST /models (no authentication)
**Result:** SUCCESS
**Impact:** Attacker discovers all available models in AWS account

```
Status: 200 OK
Response: {
    "models": [
        "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "us.anthropic.claude-3-haiku-20250307-v1:0",
        ...
    ]
}
```

**Root Cause:** No authentication on endpoint; bedrock:ListFoundationModels permission

---

### 2. Cost Bomb Attack (CRITICAL)

**Attack:** POST /complete with max_tokens=8000
**Payload:** User-controlled max_tokens parameter
**Result:** SUCCESS

```
Request:
{
    "prompt": "Write detailed explanation" (repeated 100x),
    "max_tokens": 8000
}

Response:
{
    "status": "success",
    "usage": {"output_tokens": 803},
    "response": "..."
}
```

**Cost Impact:**
- Per request: ~$0.12 (at $15/1M output tokens)
- 10,000 requests/day: ~$1,200/day
- Monthly potential damage: $36,000

**Root Cause:** User controls max_tokens; no per-token cost cap

---

### 3. Token Exhaustion (HIGH)

**Attack:** Rapid-fire requests (3/3 succeeded)
**Rate Limiting:** NONE

```
Request 1: 200 OK | 48 output tokens
Request 2: 200 OK | 100 output tokens
Request 3: 200 OK | 90 output tokens

All 3 succeeded (no throttling, no per-minute limits)
```

**Root Cause:** No rate limiting on endpoints; no request throttling

---

### 4. Unauthenticated Access (CRITICAL)

**Attack:** No API key, OAuth, or JWT required
**All Endpoints:** /health, /models, /complete
**Result:** All accessible without credentials

**Root Cause:** No authentication layer; endpoints accept any caller

---

## Attack Results Summary

| Attack | Endpoint | Method | Auth Required | Result | Severity |
|--------|----------|--------|---|--------|----------|
| Model Enum | /models | POST | NO | ✓ SUCCESS | CRITICAL |
| Cost Bomb | /complete | POST | NO | ✓ SUCCESS | CRITICAL |
| Token Exhaust | /complete | POST | NO | ✓ SUCCESS | HIGH |
| Unauth Access | All | GET/POST | NO | ✓ SUCCESS | CRITICAL |

**Total Vulnerabilities: 4/4 (100% exploitation rate)**

---

## Root Cause Analysis

### Code-Level Issues
1. **No authentication check** in handler
2. **User controls max_tokens** — no upper limit validation
3. **No input validation** on prompt parameter
4. **No rate limiting** logic

### IAM-Level Issues
1. **bedrock:\*** permission (should be bedrock:InvokeModel only)
2. **Resource:\*** scope (should limit to specific models)
3. **No cost limits** in IAM policy
4. **No CloudTrail data events** configured

### Application-Level Issues
1. **No request rate limiting**
2. **No token budget tracking**
3. **No authentication/authorization**
4. **No response filtering**

---

## Mitigation (Next Phase)

**Planned hardened version will implement:**
1. OAuth 2.1 authentication + JWT validation
2. Per-token cost cap (enforce max 2000 tokens/request)
3. Per-user rate limiting (10 requests/minute)
4. Model allowlist (only approved models)
5. Request validation (prompt length, token limits)
6. CloudTrail data events logging
7. Budget alarms and cost controls
8. Audience-bound tokens (prevent token reuse)

---

## Timeline

- **Vulnerable Baseline:** Deployed & attacked (2026-07-10)
- **Hardened Version:** TBD (next session)
- **Comparison Report:** TBD (final metrics)

---

*Pillar 2: AI APIs & MCP — Deployment Layer Security*
