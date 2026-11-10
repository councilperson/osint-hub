FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p data
ENV OSINT_DB=/app/data/osint.db
# Render injects $PORT (10000 by default); 8077 is the local/docker-run default.
CMD ["sh","-c","exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8077} --proxy-headers --forwarded-allow-ips='*' --timeout-graceful-shutdown 20"]
