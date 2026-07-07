# ==============================================================================
# STAGE 1: Build & Dependency Assembly
# ==============================================================================
FROM python:3.14.6-slim AS builder

WORKDIR /build

# Install basic system build dependencies if required by native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only the verified dependency matrix
COPY requirements.txt .

# Compile dependencies directly into a isolated local wheels cache
RUN pip install --no-cache-dir --user -r requirements.txt

# ==============================================================================
# STAGE 2: Minimal Production Runtime
# ==============================================================================
FROM python:3.14.6-slim AS runner

WORKDIR /workspace/backend

# Copy installed packages from the builder stage user space
COPY --from=builder /root/.local /root/.local
COPY requirements.txt .

# Ensure the compiled user-space binaries are on the system executable path
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/workspace/backend

# Copy application source modules securely
COPY app/ ./app/

# Enforce security best-practices: Drop root privileges for runtime execution
USER 1001

# Expose the core FastAPI network communication port
EXPOSE 8000

# Set the system entrypoint to initialize our high-throughput server architecture
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]