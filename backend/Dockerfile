# ==========================================
# STAGE 1: BUILDER
# ==========================================
FROM docker.io/library/python:3.14.6-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a clean, relocatable virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ==========================================
# STAGE 2: RUNNER
# ==========================================
FROM docker.io/library/python:3.14.6-slim AS runner

# Hardening: Install standard CA bundles for trusted outbound SSL handshakes
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged system user to run the API node securely
RUN useradd --create-home --shell /bin/bash sentinel

WORKDIR /workspace/backend

# Copy the entire clean venv environment straight from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Change ownership of the workspace to our non-root account
COPY . .
RUN chown -R sentinel:sentinel /workspace/backend

USER sentinel

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"]

CMD ["python", "-m", "app.main"]