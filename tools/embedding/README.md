# Embedding MCP Server

BGE-M3 embedding model for hybrid semantic search in OpenSploit.

## Overview

This MCP server provides text embeddings using the [BAAI/bge-m3](https://huggingface.co/BAAI/bge-m3) model with FP16 precision. It generates both dense and sparse embeddings for hybrid search.

**Doc Reference**: Document 22 §Part 5 (lines 1165-1475)

## Features

- **Dense embeddings**: 1024 dimensions for vector similarity search
- **Sparse embeddings**: Token-weight mappings for keyword fidelity
- **Hybrid scoring**: Combines dense and sparse for best retrieval
- **FP16 precision**: Preserves sparse accuracy (INT8 degrades it)

## Usage

This is an internal infrastructure tool. It is started on-demand by the `EmbeddingService` in the OpenSploit agent when semantic search is first needed.

### Methods

#### `embed`

Generate embeddings for one or more texts.

```json
{
  "texts": ["scan for open ports", "exploit CVE-2024-1234"],
  "return_sparse": true
}
```

Returns:
```json
{
  "dense": [[0.123, 0.456, ...], [0.789, 0.012, ...]],
  "sparse": [{"scan": 0.8, "ports": 0.6}, {"exploit": 0.9, "cve": 0.7}]
}
```

#### `hybrid_score`

Compute hybrid similarity scores between query and corpus.

#### `health`

Health check for fallback detection.

## Building

```bash
docker build -t ghcr.io/silicon-works/mcp-tools-embedding:latest .
```

## Resource Requirements

| Resource | Value |
|----------|-------|
| Image size | ~2.5-3.0 GB compressed |
| Runtime memory | ~1.5-2.0 GB |
| Query latency | ~100-300ms on CPU |

## Why FP16?

INT8 quantization reduces memory but loses sparse embedding accuracy ([known issue](https://huggingface.co/aapot/bge-m3-onnx/discussions/4)). Since sparse embeddings provide +5-15% recall improvement, we prioritize correctness over memory savings.
