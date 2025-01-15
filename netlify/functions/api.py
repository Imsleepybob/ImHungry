from flask import Flask
from flask_cors import CORS
import sys
import os

# 상위 디렉토리를 Python 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app import app  # 이제 app.py를 직접 import 할 수 있습니다

def handler(event, context):
    """Netlify Function handler"""
    # 요청 바디와 쿼리 파라미터 처리 추가
    body = event.get('body', '')
    query_params = event.get('queryStringParameters', {})
    
    # Flask 앱의 요청을 처리
    path = event['path'].replace('/.netlify/functions/api', '')
    http_method = event['httpMethod']
    
    with app.test_client() as client:
        response = client.open(
            path,
            method=http_method,
            data=body,
            query_string=query_params
        )
        
    return {
        'statusCode': response.status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',  # CORS 설정
            **dict(response.headers)
        },
        'body': response.get_data(as_text=True)
    }
