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

ENV PORT=8080

EXPOSE ${PORT}

CMD ["sh", "-c", "python app.py"]
