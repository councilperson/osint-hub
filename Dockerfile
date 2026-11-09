FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p data
ENV OSINT_DB=/app/data/osint.db
CMD ["sh","-c","uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
