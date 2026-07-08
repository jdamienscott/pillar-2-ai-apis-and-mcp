# 9a_bedrock_api/main.py — naive baseline (deliberately vulnerable)
# bedrock:* on Resource:*, unconstrained max_tokens, no cost cap,
# no model allowlist, no region constraint.

from fastapi import FastAPI
import boto3
import json
import os

app = FastAPI(title="Bedrock API — VULNERABLE BASELINE")

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
MODEL   = os.environ.get("MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0")


@app.post("/complete")
async def complete(prompt: str) -> dict:
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4000,   # unconstrained — cost bomb risk
        "messages": [{"role": "user", "content": prompt}],
    })
    r = bedrock.invoke_model(modelId=MODEL, body=body)
    return json.loads(r["body"].read())

# Weaknesses in this baseline:
# 1. IAM role has bedrock:* on Resource:* (any model, any region)
# 2. max_tokens=4000 per call, no per-token cost cap
# 3. No CloudTrail data events on Bedrock invocations
# 4. No model or region allowlist
