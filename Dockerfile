FROM python:3.11-slim

# Install libtorrent system dep
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-libtorrent \
    libboost-python-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Run as non-root
RUN useradd -m -u 1000 vault
USER vault

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
