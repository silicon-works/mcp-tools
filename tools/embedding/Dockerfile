# Embedding MCP Server - BGE-M3 FP16
# Doc 22 §Part 5 (lines 1370-1394)
#
# Uses FP16 to preserve full hybrid (dense + sparse) capability.
# INT8 quantization loses sparse embedding accuracy.
#
# Image size: ~2.5-3.0 GB (compressed)
# Runtime memory: ~1.5-2.0 GB
#
# Build from mcp-tools root:
#   docker build -f tools/embedding/Dockerfile -t ghcr.io/silicon-works/mcp-tools-embedding:latest .

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY tools/embedding/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download model (baked into image for fast startup)
# This adds ~1.5GB to the image but eliminates cold-start download time
RUN python -c "from FlagEmbedding import BGEM3FlagModel; \
    model = BGEM3FlagModel('BAAI/bge-m3', use_fp16=True); \
    print('Model loaded successfully')"

# Copy mcp_common package
COPY packages/mcp-common/src/mcp_common /app/mcp_common

# Copy MCP server
COPY tools/embedding/mcp-server.py .

# Set Python path
ENV PYTHONPATH=/app

# Expose no ports - MCP uses stdio
CMD ["python", "mcp-server.py"]
