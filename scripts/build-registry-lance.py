#!/usr/bin/env python3
"""
Build LanceDB registry artifacts from registry.yaml.

This script:
1. Reads the consolidated registry.yaml (output of build-registry.py)
2. Computes SHA-256 content hash → writes registry.sha256
3. For each tool, builds search_text from name, description, capabilities,
   method descriptions, method when_to_use, and routing.use_for
4. Embeds search_text with BGE-M3 via FlagEmbedding (FP16) → 1024-dim dense vectors
5. Creates LanceDB table 'tools' with plaintext fields + search_text + tool_vector + registry_hash
6. Creates FTS index on search_text column
7. Packages .lance directory → registry.lance.tar.gz

Usage:
    python scripts/build-registry-lance.py
    python scripts/build-registry-lance.py --registry path/to/registry.yaml
    python scripts/build-registry-lance.py --skip-embeddings  # FTS only, no vectors
"""

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

import pyarrow as pa
import yaml

PROJECT_ROOT = Path(__file__).parent.parent
REGISTRY_PATH = PROJECT_ROOT / "registry.yaml"
OUTPUT_DIR = PROJECT_ROOT / "dist"

# BGE-M3 produces 1024-dim dense vectors
VECTOR_DIMENSIONS = 1024


def compute_sha256(content: bytes) -> str:
    """Compute SHA-256 hex digest of content."""
    return hashlib.sha256(content).hexdigest()


def build_search_text(tool: dict) -> str:
    """
    Build concatenated search text for FTS indexing.

    Includes: name, description, capabilities, method descriptions,
    method when_to_use, and routing.use_for phrases.

    IMPORTANT: This logic is duplicated in the TypeScript client at
    packages/opencode/src/memory/tools.ts:buildSearchText().
    Both must stay in sync for consistent FTS results between
    CI-built indexes and YAML-fallback client-built indexes.
    """
    parts: list[str] = []

    # Core fields
    parts.append(tool.get("name", ""))
    parts.append(tool.get("description", ""))

    # Capabilities
    for cap in tool.get("capabilities", []):
        parts.append(cap)

    # Methods
    for method_name, method in tool.get("methods", {}).items():
        parts.append(method_name)
        parts.append(method.get("description", ""))
        if wtu := method.get("when_to_use"):
            parts.append(wtu)

    # Routing use_for phrases
    routing = tool.get("routing", {})
    for phrase in routing.get("use_for", []):
        parts.append(phrase)

    return " ".join(p for p in parts if p)


def load_embedding_model():
    """
    Load BGE-M3 model via FlagEmbedding with FP16.

    Uses the same library and precision as the runtime MCP server
    (tools/embedding/mcp-server.py) to ensure CI-built vectors are in
    the identical embedding space as query-time vectors.
    """
    try:
        from FlagEmbedding import BGEM3FlagModel

        print("Loading BGE-M3 model (FP16, matching runtime MCP server)...")
        model = BGEM3FlagModel("BAAI/bge-m3", use_fp16=True)
        print("Model loaded (dimension: 1024)")
        return model
    except ImportError:
        print("FlagEmbedding not installed, skipping embeddings", file=sys.stderr)
        return None


def embed_texts(model, texts: list[str]) -> list[list[float]]:
    """Embed texts using BGE-M3 model. Returns 1024-dim dense vectors."""
    if model is None:
        return [[] for _ in texts]

    outputs = model.encode(
        texts,
        return_dense=True,
        return_sparse=False,
        return_colbert_vecs=False,
        max_length=8192,
    )
    return [emb.tolist() for emb in outputs["dense_vecs"]]


def build_lance_table(
    tools: dict,
    registry_hash: str,
    embeddings: list[list[float]] | None,
    output_path: Path,
) -> int:
    """
    Build LanceDB table from tools with optional embeddings.

    Returns the number of tools imported.
    """
    import lancedb

    # Prepare rows
    tool_ids = list(tools.keys())
    rows = []

    for i, tool_id in enumerate(tool_ids):
        tool = tools[tool_id]
        search_text = build_search_text(tool)

        row = {
            "id": tool_id,
            "name": tool.get("name", tool_id),
            "description": tool.get("description", ""),
            "version": tool.get("version", ""),
            "image": tool.get("image", ""),
            "phases_json": json.dumps(tool.get("phases", [])),
            "capabilities_json": json.dumps(tool.get("capabilities", [])),
            "routing_json": json.dumps(tool.get("routing", {})),
            "methods_json": json.dumps(tool.get("methods", {})),
            "requirements_json": json.dumps(tool.get("requirements", {})),
            "resources_json": json.dumps(tool.get("resources", {})),
            "raw_json": json.dumps(tool),
            "search_text": search_text,
            "registry_hash": registry_hash,
        }

        # Add embedding vector if available
        if embeddings and embeddings[i]:
            row["tool_vector"] = embeddings[i]

        rows.append(row)

    # Create LanceDB database
    if output_path.exists():
        shutil.rmtree(output_path)

    db = lancedb.connect(str(output_path))

    # Create table from rows
    table = db.create_table("tools", rows)
    print(f"Created tools table with {table.count_rows()} rows")

    # Create FTS index on search_text
    try:
        table.create_fts_index("search_text", replace=True)
        print("Created FTS index on search_text")
    except Exception as e:
        print(f"Warning: FTS index creation failed: {e}", file=sys.stderr)
        print("FTS index will be created by client on first use", file=sys.stderr)

    return len(rows)


def package_lance(lance_dir: Path, output_tar: Path) -> int:
    """Package .lance directory into tar.gz archive. Returns archive size in bytes."""
    with tarfile.open(str(output_tar), "w:gz") as tar:
        tar.add(str(lance_dir), arcname="tools.lance")

    size = output_tar.stat().st_size
    print(f"Packaged {output_tar} ({size:,} bytes)")
    return size


def main():
    parser = argparse.ArgumentParser(description="Build LanceDB registry artifacts")
    parser.add_argument(
        "--registry",
        type=Path,
        default=REGISTRY_PATH,
        help="Path to registry.yaml (default: ./registry.yaml)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_DIR,
        help="Output directory (default: ./dist)",
    )
    parser.add_argument(
        "--skip-embeddings",
        action="store_true",
        help="Skip embedding generation (FTS only, no vectors)",
    )
    args = parser.parse_args()

    # Read registry
    registry_path = args.registry
    if not registry_path.exists():
        print(f"Registry not found: {registry_path}", file=sys.stderr)
        print("Run build-registry.py first", file=sys.stderr)
        sys.exit(1)

    registry_content = registry_path.read_bytes()
    registry = yaml.safe_load(registry_content)
    tools = registry.get("tools", {})

    if not tools:
        print("No tools found in registry", file=sys.stderr)
        sys.exit(1)

    print(f"Loaded {len(tools)} tools from {registry_path}")

    # Compute SHA-256 hash
    registry_hash = compute_sha256(registry_content)
    print(f"Registry SHA-256: {registry_hash}")

    # Ensure output directory exists
    args.output.mkdir(parents=True, exist_ok=True)

    # Note: registry.sha256 sidecar is written by build-registry.py at project root.
    # This script embeds the hash in LanceDB rows but doesn't write a separate file.

    # Build search texts
    search_texts = [build_search_text(tools[tid]) for tid in tools]

    # Embed search texts (unless --skip-embeddings)
    embeddings = None
    if not args.skip_embeddings:
        model = load_embedding_model()
        if model:
            print(f"Embedding {len(search_texts)} tool search texts...")
            embeddings = embed_texts(model, search_texts)
            print(f"Generated {len(embeddings)} embeddings ({VECTOR_DIMENSIONS} dims each)")
        else:
            print("Warning: No embedding model available, building FTS-only index")

    # Build LanceDB table in temp dir, then package
    with tempfile.TemporaryDirectory() as tmpdir:
        lance_dir = Path(tmpdir) / "tools.lance"
        count = build_lance_table(tools, registry_hash, embeddings, lance_dir)

        # Package into tar.gz
        tar_path = args.output / "registry.lance.tar.gz"
        archive_size = package_lance(lance_dir, tar_path)

    # Summary
    print(f"\n{'='*60}")
    print(f"Registry LanceDB Build Summary")
    print(f"{'='*60}")
    print(f"  Tools:      {count}")
    print(f"  Hash:       {registry_hash[:16]}...")
    print(f"  Vectors:    {'yes' if embeddings else 'no (FTS only)'}")
    print(f"  Archive:    {tar_path} ({archive_size:,} bytes)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
