import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

def lambda_handler(event, context):
    """Direct Lambda handler without FastAPI dependency"""
    
    http_method = event.get('requestContext', {}).get('http', {}).get('method', 'GET')
    path = event.get('rawPath', '/')
    body = event.get('body', '{}')
    
    try:
        if path == '/health' and http_method == 'GET':
            return {
                'statusCode': 200,
                'body': json.dumps({'status': 'healthy', 'service': 'bedrock-api'}),
                'headers': {'Content-Type': 'application/json'}
            }
        
        elif path == '/models' and http_method == 'POST':
            # VULNERABLE: No auth, exposes all models
            response = bedrock.list_foundation_models()
            models = [m['modelId'] for m in response.get('modelSummaries', [])]
            return {
                'statusCode': 200,
                'body': json.dumps({'status': 'success', 'models': models, 'count': len(models)}),
                'headers': {'Content-Type': 'application/json'}
            }
        
        elif path == '/complete' and http_method == 'POST':
            # VULNERABLE: No token limit, no auth
            payload = json.loads(body)
            prompt = payload.get('prompt', '')
            max_tokens = payload.get('max_tokens', 4000)  # User controls this!
            
            if not prompt:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Missing prompt'}),
                    'headers': {'Content-Type': 'application/json'}
                }
            
            logger.info(f"Prompt length: {len(prompt)}, max_tokens: {max_tokens}")
            
            request_body = json.dumps({
                'anthropic_version': 'bedrock-2023-05-31',
                'max_tokens': max_tokens,
                'messages': [{'role': 'user', 'content': prompt}]
            })
            
            response = bedrock.invoke_model(
                modelId='us.anthropic.claude-sonnet-4-5-20250929-v1:0',
                body=request_body
            )
            
            result = json.loads(response['body'].read())
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'status': 'success',
                    'response': result.get('content', [{}])[0].get('text', ''),
                    'usage': result.get('usage', {}),
                    'model': 'claude-sonnet-4-5'
                }),
                'headers': {'Content-Type': 'application/json'}
            }
        
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not found'}),
                'headers': {'Content-Type': 'application/json'}
            }
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)}),
            'headers': {'Content-Type': 'application/json'}
        }
