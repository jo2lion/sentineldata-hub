# ==============================================================================
# STAGE 1: Build & Dependency Assembly
# ==============================================================================
FROM python:3.14.6-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# REMOVED --user: Install directly to standard system path for clean copying
RUN pip install --no-cache-dir --target=/build/packages -r requirements.txt

# ==============================================================================
# STAGE 2: Minimal Production Runtime
# ==============================================================================
FROM python:3.14.6-slim AS runner

WORKDIR /workspace/backend

# Copy packages from builder stage directly into Python's global site-packages
COPY --from=builder /build/packages /usr/local/lib/python3.14/site-packages
COPY --from=builder /build/packages/bin /usr/local/bin

COPY requirements.txt .

ENV PYTHONPATH=/workspace/backend

# Copy application source modules securely
COPY app/ ./app/

# Enforce security best-practices: Ensure non-root user owns the workspace
RUN chown -R 1001:1001 /workspace/backend
USER 1001

# Expose the core FastAPI network communication port
EXPOSE 8000

# Set the system entrypoint to initialize our high-throughput server architecture
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]