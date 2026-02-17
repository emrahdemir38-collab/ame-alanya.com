FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    poppler-utils \
    libpq-dev \
    gcc \
    zlib1g-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libpng-dev \
    fonts-dejavu-core \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-5000}/health || exit 1

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --threads 2 --timeout 180 --graceful-timeout 30 --worker-tmp-dir /dev/shm app:app 2>&1"]
