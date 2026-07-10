"""
Pillar 2: AI APIs & MCP — Hardened Version
Bedrock API with authentication, cost controls, rate limiting, and validation
"""
import boto3
import json
import logging
import hashlib
import hmac
import time
from typing import Dict, Tuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

# ===== CONFIGURATION =====
MAX_TOKENS_HARD_LIMIT = 2000
MAX_PROMPT_LENGTH = 5000
ALLOWED_MODELS = [
    'us.anthropic.claude-sonnet-4-5-20250929-v1:0',
]
REQUESTS_PER_MINUTE = 10
TOKEN_BUDGET_PER_DAY = 100000

# Simple in-memory rate limiter (production should use DynamoDB)
request_log = {}

# ===== HELPER FUNCTIONS =====

def validate_api_key(auth_header: str) -> Tuple[bool, str]:
    """
    Validate API key from Authorization header
    Format: Bearer <api_key>
    """
    if not auth_header:
        return False, "Missing Authorization header"
    
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return False, "Invalid Authorization format"
    
    api_key = parts[1]
    
    # In production, validate against DynamoDB or Secrets Manager
    # For demo: accept any key matching pattern
    if len(api_key) < 32:
        return False, "Invalid API key format"
    
    return True, api_key

def check_rate_limit(api_key: str) -> Tuple[bool, str]:
    """
    Check if user has exceeded rate limit (10 requests/minute)
    """
    current_time = time.time()
    minute_ago = current_time - 60
    
    # Clean old entries
    request_log[api_key] = [
        ts for ts in request_log.get(api_key, []) 
        if ts > minute_ago
    ]
    
    requests_this_minute = len(request_log.get(api_key, []))
    
    if requests_this_minute >= REQUESTS_PER_MINUTE:
        return False, f"Rate limit exceeded: {REQUESTS_PER_MINUTE} requests per minute"
    
    # Log this request
    if api_key not in request_log:
        request_log[api_key] = []
    request_log[api_key].append(current_time)
    
    return True, "OK"

def validate_model(model_id: str) -> Tuple[bool, str]:
    """
    Validate model is in allowlist
    MITIGATION: Model enumeration prevented by allowlist
    """
    if model_id not in ALLOWED_MODELS:
        return False, f"Model not allowed. Allowed models: {ALLOWED_MODELS}"
    
    return True, "OK"

def validate_tokens(max_tokens: int) -> Tuple[bool, str]:
    """
    Enforce hard limit on tokens
    MITIGATION: Cost bomb attack prevented
    """
    if not isinstance(max_tokens, int):
        return False, "max_tokens must be an integer"
    
    if max_tokens <= 0:
        return False, "max_tokens must be > 0"
    
    if max_tokens > MAX_TOKENS_HARD_LIMIT:
        return False, f"max_tokens exceeds limit of {MAX_TOKENS_HARD_LIMIT}"
    
    return True, "OK"

def validate_prompt(prompt: str) -> Tuple[bool, str]:
    """
    Validate prompt input
    MITIGATION: Input injection and DOS attacks
    """
    if not prompt or not isinstance(prompt, str):
        return False, "Prompt must be a non-empty string"
    
    if len(prompt) > MAX_PROMPT_LENGTH:
        return False, f"Prompt exceeds maximum length of {MAX_PROMPT_LENGTH} characters"
    
    # Check for injection patterns
    injection_patterns = [
        'ignore previous',
        'system prompt',
        'developer mode',
        '<system>',
        'hidden instruction',
    ]
    
    prompt_lower = prompt.lower()
    for pattern in injection_patterns:
        if pattern in prompt_lower:
            return False, "Prompt contains suspicious patterns"
    
    return True, "OK"

def log_request(api_key: str, status: int, tokens_used: int = 0):
    """
    Log all API requests for audit trail
    MITIGATION: Audit trail and anomaly detection
    """
    logger.info(json.dumps({
        'timestamp': time.time(),
        'api_key_hash': hashlib.sha256(api_key.encode()).hexdigest()[:16],
        'status': status,
        'tokens_used': tokens_used
    }))

# ===== HANDLER =====

def lambda_handler(event, context):
    """
    Hardened Bedrock API handler
    """
    http_method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    path = event.get('rawPath', '/')
    body = event.get('body', '{}')
    headers = event.get('headers', {})
    
    try:
        # ===== AUTHENTICATION =====
        auth_header = headers.get('authorization', '')
        valid_auth, auth_msg = validate_api_key(auth_header)
        
        if not valid_auth:
            log_request('unknown', 401)
            return {
                'statusCode': 401,
                'body': json.dumps({'error': auth_msg}),
                'headers': {'Content-Type': 'application/json'}
            }
        
        api_key = auth_header.split()[1]
        
        # ===== RATE LIMITING =====
        rate_ok, rate_msg = check_rate_limit(api_key)
        if not rate_ok:
            log_request(api_key, 429)
            return {
                'statusCode': 429,
                'body': json.dumps({'error': rate_msg}),
                'headers': {'Content-Type': 'application/json'}
            }
        
        # ===== ROUTES =====
        if path == '/health' and http_method == 'GET':
            log_request(api_key, 200)
            return {
                'statusCode': 200,
                'body': json.dumps({'status': 'healthy', 'service': 'bedrock-api-hardened'}),
                'headers': {'Content-Type': 'application/json'}
            }
        
        elif path == '/models' and http_method == 'POST':
            # HARDENED: Return only allowlisted models (no enumeration)
            log_request(api_key, 200)
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'status': 'success',
                    'models': ALLOWED_MODELS,
                    'count': len(ALLOWED_MODELS),
                    'note': 'Only approved models exposed'
                }),
                'headers': {'Content-Type': 'application/json'}
            }
        
        elif path == '/complete' and http_method == 'POST':
            # Parse request
            try:
                payload = json.loads(body)
            except:
                log_request(api_key, 400)
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Invalid JSON'}),
                    'headers': {'Content-Type': 'application/json'}
                }
            
            prompt = payload.get('prompt', '')
            max_tokens = payload.get('max_tokens', 1000)
            model = payload.get('model', ALLOWED_MODELS[0])
            
            # ===== INPUT VALIDATION =====
            valid_prompt, prompt_msg = validate_prompt(prompt)
            if not valid_prompt:
                log_request(api_key, 400)
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': prompt_msg}),
                    'headers': {'Content-Type': 'application/json'}
                }
            
            valid_tokens, tokens_msg = validate_tokens(max_tokens)
            if not valid_tokens:
                log_request(api_key, 400)
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': tokens_msg}),
                    'headers': {'Content-Type': 'application/json'}
                }
            
            valid_model, model_msg = validate_model(model)
            if not valid_model:
                log_request(api_key, 400)
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': model_msg}),
                    'headers': {'Content-Type': 'application/json'}
                }
            
            # ===== INVOKE MODEL =====
            try:
                request_body = json.dumps({
                    'anthropic_version': 'bedrock-2023-05-31',
                    'max_tokens': max_tokens,
                    'messages': [{'role': 'user', 'content': prompt}]
                })
                
                response = bedrock.invoke_model(
                    modelId=model,
                    body=request_body
                )
                
                result = json.loads(response['body'].read())
                usage = result.get('usage', {})
                output_tokens = usage.get('output_tokens', 0)
                
                log_request(api_key, 200, output_tokens)
                
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'status': 'success',
                        'response': result.get('content', [{}])[0].get('text', ''),
                        'usage': usage,
                        'model': model,
                        'defenses': [
                            'authentication-required',
                            'rate-limiting',
                            'token-hard-limit',
                            'model-allowlist',
                            'input-validation',
                            'audit-logging'
                        ]
                    }),
                    'headers': {'Content-Type': 'application/json'}
                }
            
            except Exception as e:
                log_request(api_key, 500)
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': str(e)}),
                    'headers': {'Content-Type': 'application/json'}
                }
        
        else:
            log_request(api_key, 404)
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not found'}),
                'headers': {'Content-Type': 'application/json'}
            }
    
    except Exception as e:
        logger.error(f"Unhandled error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'}),
            'headers': {'Content-Type': 'application/json'}
        }
