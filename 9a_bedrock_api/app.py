"""
Pillar 2: AI APIs & MCP — Vulnerable Baseline
Bedrock API without cost controls, model allowlists, or token binding
This is deliberately insecure for attack demonstration.
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import boto3
import json
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Bedrock API - VULNERABLE BASELINE", version="1.0.0")

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

class CompleteRequest(BaseModel):
    prompt: str
    max_tokens: int = 4000  # User-controllable; no cap

@app.post("/complete")
async def complete(request: CompleteRequest) -> dict:
    """
    VULNERABLE: 
    - No token limit enforcement
    - No model allowlist
    - No cost cap
    - No input validation
    - No authentication
    """
    try:
        logger.info(f"Prompt: {request.prompt[:100]}... | Tokens: {request.max_tokens}")
        
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": request.max_tokens,  # VULNERABLE: User controls token limit
            "messages": [{"role": "user", "content": request.prompt}],
        })
        
        # VULNERABLE: bedrock:* on Resource:* (any model, any region)
        response = bedrock.invoke_model(
            modelId="us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            body=body
        )
        
        result = json.loads(response["body"].read())
        return {
            "status": "success",
            "response": result.get("content", [{}])[0].get("text", ""),
            "usage": result.get("usage", {}),
            "model": "claude-sonnet-4-5"
        }
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/models")
async def list_models() -> dict:
    """
    VULNERABLE: Exposes all available models
    No authentication or rate limiting
    """
    try:
        response = bedrock.list_foundation_models()
        models = [m["modelId"] for m in response.get("modelSummaries", [])]
        return {
            "status": "success",
            "models": models,
            "count": len(models)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health() -> dict:
    """Health check — no auth required"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
