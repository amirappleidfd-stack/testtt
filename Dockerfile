FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libssl3 libffi8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /install /usr/local

COPY main.py .
COPY pages.py .
COPY relay_vless.py .
COPY shared.py .
COPY xhttp_siz10.py .
COPY static/ static/

RUN mkdir -p /data /app/static/uploads

EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=10s --start-period=15s --retries=3 \
 CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:'+__import__('os').environ.get('PORT','8080')+'/health')"

CMD ["python", "main.py"]
