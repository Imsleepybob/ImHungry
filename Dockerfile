FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
COPY app.py .
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["gunicorn", "--worker-class", "gthread", "--workers", "1", "--threads", "4", "--timeout", "30", "--bind", "0.0.0.0:8000", "app:app"]
