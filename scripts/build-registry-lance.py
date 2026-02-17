#!/usr/bin/env python3
"""
Build LanceDB registry artifacts from registry.yaml — method-level rows.

This script:
1. Reads the consolidated registry.yaml (output of build-registry.py)
2. Computes SHA-256 content hash → writes registry.sha256
3. For each (tool, method) pair, builds focused method-level search_text
4. Embeds search_text with BGE-M3 via FlagEmbedding (FP16)
   → 1024-dim dense vectors AND sparse vectors (learned lexical weights)
5. Creates LanceDB table 'tools' with one row per method
   (columns: tool_id, method_name, method_vector, sparse_json, etc.)
6. Creates FTS index on search_text column
7. Packages .lance directory → registry.lance.tar.gz

Schema version: 7.0 (method-level rows, sparse_json)

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

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
REGISTRY_PATH = PROJECT_ROOT / "registry.yaml"
OUTPUT_DIR = PROJECT_ROOT / "dist"

# BGE-M3 produces 1024-dim dense vectors
VECTOR_DIMENSIONS = 1024


def compute_sha256(content: bytes) -> str:
    """Compute SHA-256 hex digest of content."""
    return hashlib.sha256(content).hexdigest()


def build_method_search_text(tool: dict, method_name: str, method: dict) -> str:
    """
    Build focused per-method search text for FTS indexing.

    ~100-300 chars per method vs ~1200 chars per tool. BM25 naturally
    weights routing signals higher because there's less dilution.

    IMPORTANT: This logic is duplicated in the TypeScript client at
    packages/opencode/src/memory/tools.ts:buildMethodSearchText().
    Both must stay in sync for consistent FTS results between
    CI-built indexes and YAML-fallback client-built indexes.
    """
    parts: list[str] = []

    # Tool name for context
    parts.append(tool.get("name", ""))

    # Method identity
    parts.append(method_name)

    # Method-specific documentation
    parts.append(method.get("description", ""))
    if wtu := method.get("when_to_use"):
        parts.append(wtu)

    # Tool description (brief context)
    parts.append(tool.get("description", ""))

    # Routing use_for phrases (high-signal)
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


def embed_texts(
    model, texts: list[str]
) -> tuple[list[list[float]], list[dict[str, float]]]:
    """
    Embed texts using BGE-M3 model.

    Returns (dense_vectors, sparse_vectors) tuple.
    - Dense: list of 1024-dim float vectors
    - Sparse: list of {token_id: weight} dicts
    """
    if model is None:
        return ([[] for _ in texts], [{} for _ in texts])

    outputs = model.encode(
        texts,
        return_dense=True,
        return_sparse=True,
        return_colbert_vecs=False,
        max_length=8192,
    )

    dense_vecs = [emb.tolist() for emb in outputs["dense_vecs"]]

    # BGE-M3 sparse output: list of dicts with int keys (token IDs) and float weights
    sparse_vecs = []
    for sparse in outputs.get("lexical_weights", []):
        # Convert to string keys for JSON serialization
        sparse_dict = {str(k): float(v) for k, v in sparse.items()} if sparse else {}
        sparse_vecs.append(sparse_dict)

    return (dense_vecs, sparse_vecs)


def build_method_rows(tools: dict, registry_hash: str) -> list[dict]:
    """
    Build method-level rows from tool registry.

    Each (tool_id, method_name) pair produces one row with:
    - Tool-level metadata (shared across methods)
    - Method-specific fields (description, when_to_use, search_text)
    - Space for method_vector and sparse_json (added after embedding)
    """
    rows = []

    for tool_id, tool in tools.items():
        methods = tool.get("methods", {})
        tool_json = json.dumps(tool)
        phases_json = json.dumps(tool.get("phases", []))
        capabilities_json = json.dumps(tool.get("capabilities", []))
        routing_json = json.dumps(tool.get("routing", {}))
        methods_json = json.dumps(methods)
        requirements_json = json.dumps(tool.get("requirements", {}))
        resources_json = json.dumps(tool.get("resources", {}))
        see_also_json = json.dumps(tool.get("see_also", []))

        if not methods:
            # Tool with no methods — create a single "default" row
            search_text = build_method_search_text(
                tool, "default", {"description": tool.get("description", "")}
            )
            rows.append(
                {
                    "id": f"{tool_id}:default",
                    "tool_id": tool_id,
                    "method_name": "default",
                    "tool_name": tool.get("name", tool_id),
                    "tool_description": tool.get("description", ""),
                    "method_description": tool.get("description", ""),
                    "when_to_use": "",
                    "search_text": search_text,
                    "phases_json": phases_json,
                    "capabilities_json": capabilities_json,
                    "routing_json": routing_json,
                    "methods_json": methods_json,
                    "requirements_json": requirements_json,
                    "resources_json": resources_json,
                    "raw_json": tool_json,
                    "see_also_json": see_also_json,
                    "registry_hash": registry_hash,
                }
            )
        else:
            for method_name, method in methods.items():
                search_text = build_method_search_text(tool, method_name, method)
                rows.append(
                    {
                        "id": f"{tool_id}:{method_name}",
                        "tool_id": tool_id,
                        "method_name": method_name,
                        "tool_name": tool.get("name", tool_id),
                        "tool_description": tool.get("description", ""),
                        "method_description": method.get("description", ""),
                        "when_to_use": method.get("when_to_use", ""),
                        "search_text": search_text,
                        "phases_json": phases_json,
                        "capabilities_json": capabilities_json,
                        "routing_json": routing_json,
                        "methods_json": methods_json,
                        "requirements_json": requirements_json,
                        "resources_json": resources_json,
                        "raw_json": tool_json,
                        "see_also_json": see_also_json,
                        "registry_hash": registry_hash,
                    }
                )

    return rows


def build_lance_table(
    rows: list[dict],
    dense_embeddings: list[list[float]] | None,
    sparse_embeddings: list[dict[str, float]] | None,
    output_path: Path,
) -> int:
    """
    Build LanceDB table from method-level rows with optional embeddings.

    Returns the number of rows imported.
    """
    import lancedb

    # Add embeddings to rows
    for i, row in enumerate(rows):
        if dense_embeddings and i < len(dense_embeddings) and dense_embeddings[i]:
            row["method_vector"] = dense_embeddings[i]
        if sparse_embeddings and i < len(sparse_embeddings) and sparse_embeddings[i]:
            row["sparse_json"] = json.dumps(sparse_embeddings[i])
        else:
            row["sparse_json"] = ""

    # Create LanceDB database
    if output_path.exists():
        shutil.rmtree(output_path)

    db = lancedb.connect(str(output_path))

    # Create table from rows
    table = db.create_table("tools", rows)
    print(f"Created tools table with {table.count_rows()} method rows")

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
    parser = argparse.ArgumentParser(description="Build LanceDB registry artifacts (method-level)")
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

    # Build method-level rows
    rows = build_method_rows(tools, registry_hash)
    total_methods = len(rows)
    print(f"Built {total_methods} method rows from {len(tools)} tools")

    # Extract search texts for embedding
    search_texts = [row["search_text"] for row in rows]

    # Embed search texts (unless --skip-embeddings)
    dense_embeddings = None
    sparse_embeddings = None
    if not args.skip_embeddings:
        model = load_embedding_model()
        if model:
            print(f"Embedding {len(search_texts)} method search texts...")
            dense_embeddings, sparse_embeddings = embed_texts(model, search_texts)
            print(
                f"Generated {len(dense_embeddings)} dense + {len(sparse_embeddings)} sparse embeddings"
            )
        else:
            print("Warning: No embedding model available, building FTS-only index")

    # Build LanceDB table in temp dir, then package
    with tempfile.TemporaryDirectory() as tmpdir:
        lance_dir = Path(tmpdir) / "tools.lance"
        count = build_lance_table(rows, dense_embeddings, sparse_embeddings, lance_dir)

        # Package into tar.gz
        tar_path = args.output / "registry.lance.tar.gz"
        archive_size = package_lance(lance_dir, tar_path)

    # Summary
    print(f"\n{'='*60}")
    print(f"Registry LanceDB Build Summary (method-level v7.0)")
    print(f"{'='*60}")
    print(f"  Tools:      {len(tools)}")
    print(f"  Methods:    {count}")
    print(f"  Hash:       {registry_hash[:16]}...")
    print(f"  Vectors:    {'dense + sparse' if dense_embeddings else 'no (FTS only)'}")
    print(f"  Archive:    {tar_path} ({archive_size:,} bytes)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
