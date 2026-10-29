# Build CacheClient.Dockerfile as donna-interop-cache-client-body:local first.
# Signature verification runs outside native timing; no host dependency install.
ARG NATIVE_CLIENT=donna-interop-cache-client-body:local

FROM ${NATIVE_CLIENT}

# Same cryptography version as the existing independent peer checker image.
RUN pip install --no-cache-dir \
    cffi==2.1.1 \
    cryptography==50.0.2 \
    pycparser==3.12

COPY examples/interop/python/signed_probe.py /suite/signed_probe.py
