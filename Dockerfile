# Python 3.9 이미지를 기반으로 사용
FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 필요한 파일들을 복사
COPY requirements.txt .
COPY app.py .
COPY . .

# 의존성 설치
RUN pip install --no-cache-dir -r requirements.txt

# 포트 설정
EXPOSE 8000

# 실행 명령
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
