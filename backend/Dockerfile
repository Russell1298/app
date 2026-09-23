FROM python:3.11-slim

WORKDIR /app

# Install system deps needed by cryptography / asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-dejavu-core \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
