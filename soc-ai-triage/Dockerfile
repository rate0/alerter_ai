FROM python:3.11-slim

LABEL maintainer="SOC AI Triage Service"
LABEL description="AI-powered alert triage for Elastic Defend"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY *.py .
COPY .env .

# Create directories for logs and output
RUN mkdir -p /app/docs /app/logs

# Health check — verify Python can import core deps
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "from elasticsearch import Elasticsearch; print('OK')" || exit 1

# Non-root user for security
RUN useradd -m -u 1001 socuser && chown -R socuser:socuser /app
USER socuser

CMD ["python", "main.py"]
