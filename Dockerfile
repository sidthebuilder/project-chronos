# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies required for compiling some cryptography packages if wheels are missing
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install dependencies into a specific directory using hashed requirements for supply-chain security
RUN pip install --no-cache-dir --require-hashes -r requirements.txt --target=/app/deps

# Stage 2: Runtime (Google Distroless)
FROM gcr.io/distroless/python3-debian12

WORKDIR /app

# Copy the pre-installed dependencies from the builder stage
COPY --from=builder /app/deps /app/deps

# Copy the CHRONOS agent source code
COPY . /app

# Set PYTHONPATH so python can find the installed dependencies
ENV PYTHONPATH=/app/deps

# Drop privileges completely; run as a non-root user
USER 10001:10001

# Run the agent
CMD ["chronos_agent.py"]
