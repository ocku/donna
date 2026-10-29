FROM python:3.13-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libsodium23 \
    && rm -rf /var/lib/apt/lists/*

COPY examples/interop/python/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /suite
COPY examples/interop/python ./

ENV CERT_DIR=/certs \
    PYTHONUNBUFFERED=1

CMD ["python", "peers.py"]
