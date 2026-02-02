#!/usr/bin/env python3
"""
OpenSploit MCP Server: embedding

BGE-M3 embedding model for hybrid (dense + sparse) semantic search.
Provides embeddings for tool discovery, experience recording, and insight extraction.

Doc 22 §Part 5 (lines 1396-1473)
"""

import logging
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Global model instance (loaded once at startup)
_model = None


def get_model():
    """Get or initialize the BGE-M3 model."""
    global _model
    if _model is None:
        logger.info("Loading BGE-M3 model (FP16)...")
        from FlagEmbedding import BGEM3FlagModel
        _model = BGEM3FlagModel('BAAI/bge-m3', use_fp16=True)
        logger.info("BGE-M3 model loaded successfully")
    return _model


class EmbeddingServer(BaseMCPServer):
    """MCP server for BGE-M3 embeddings."""

    def __init__(self):
        super().__init__(
            name="embedding",
            description="BGE-M3 embedding model for hybrid semantic search (1024 dimensions)",
            version="1.0.0",
        )

        # Register methods
        self.register_method(
            name="embed",
            description="Generate embeddings for text(s). Returns dense (1024d) and optionally sparse embeddings.",
            params={
                "texts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "required": True,
                    "description": "List of texts to embed (queries, experiences, etc.)",
                },
                "return_sparse": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to return sparse lexical embeddings",
                },
            },
            handler=self.embed,
        )

        self.register_method(
            name="hybrid_score",
            description="Compute hybrid similarity scores combining dense and sparse embeddings",
            params={
                "query_dense": {
                    "type": "array",
                    "items": {"type": "number"},
                    "required": True,
                    "description": "Query dense embedding (1024 floats)",
                },
                "query_sparse": {
                    "type": "object",
                    "required": True,
                    "description": "Query sparse embedding (token -> weight dict)",
                },
                "corpus_dense": {
                    "type": "array",
                    "items": {"type": "array", "items": {"type": "number"}},
                    "required": True,
                    "description": "List of corpus dense embeddings",
                },
                "corpus_sparse": {
                    "type": "array",
                    "items": {"type": "object"},
                    "required": True,
                    "description": "List of corpus sparse embeddings",
                },
                "dense_weight": {
                    "type": "number",
                    "default": 0.4,
                    "description": "Weight for dense similarity (0-1)",
                },
                "sparse_weight": {
                    "type": "number",
                    "default": 0.6,
                    "description": "Weight for sparse similarity (0-1)",
                },
            },
            handler=self.hybrid_score,
        )

        self.register_method(
            name="health",
            description="Health check for embedding service",
            params={},
            handler=self.health,
        )

    async def embed(self, texts: List[str], return_sparse: bool = True) -> ToolResult:
        """
        Embed texts using BGE-M3.

        Returns both dense and sparse embeddings for hybrid search.
        Dense embeddings are 1024 dimensions.
        Sparse embeddings are token -> weight dictionaries.
        """
        try:
            if not texts:
                raise ToolError("No texts provided for embedding")

            model = get_model()

            # BGE-M3 produces dense, sparse, and colbert vectors in one call
            outputs = model.encode(
                texts,
                return_dense=True,
                return_sparse=return_sparse,
                return_colbert_vecs=False,  # Not needed for our use case
                max_length=8192
            )

            result = {
                "dense": outputs['dense_vecs'].tolist(),
                "dimensions": 1024,
                "count": len(texts),
            }

            if return_sparse and 'lexical_weights' in outputs:
                # Sparse embeddings as token -> weight dict
                # Convert numpy float32 to Python float for JSON serialization
                result["sparse"] = [
                    {k: float(v) for k, v in w.items()}
                    for w in outputs['lexical_weights']
                ]

            return ToolResult(
                success=True,
                data=result,
            )

        except Exception as e:
            logger.error(f"Embedding failed: {e}")
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def hybrid_score(
        self,
        query_dense: List[float],
        query_sparse: Dict[str, float],
        corpus_dense: List[List[float]],
        corpus_sparse: List[Dict[str, float]],
        dense_weight: float = 0.4,
        sparse_weight: float = 0.6,
    ) -> ToolResult:
        """
        Compute hybrid scores combining dense and sparse similarity.

        Default weights favor sparse (keyword fidelity) slightly.
        """
        try:
            import numpy as np

            # Dense similarity (cosine via dot product, assumes normalized)
            q_dense = np.array(query_dense)
            c_dense = np.array(corpus_dense)
            dense_scores = np.dot(c_dense, q_dense)

            # Sparse similarity (lexical overlap)
            sparse_scores = []
            for doc_sparse in corpus_sparse:
                score = sum(
                    query_sparse.get(token, 0) * doc_sparse.get(token, 0)
                    for token in set(query_sparse) | set(doc_sparse)
                )
                sparse_scores.append(score)
            sparse_scores = np.array(sparse_scores)

            # Normalize sparse scores to same scale as dense
            if sparse_scores.max() > 0:
                sparse_scores = sparse_scores / sparse_scores.max()

            # Combine with weights
            hybrid_scores = dense_weight * dense_scores + sparse_weight * sparse_scores

            return ToolResult(
                success=True,
                data={
                    "scores": hybrid_scores.tolist(),
                    "dense_weight": dense_weight,
                    "sparse_weight": sparse_weight,
                },
            )

        except Exception as e:
            logger.error(f"Hybrid scoring failed: {e}")
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def health(self) -> ToolResult:
        """Health check for fallback detection."""
        try:
            # Verify model is loadable
            get_model()
            return ToolResult(
                success=True,
                data={
                    "status": "ok",
                    "model": "bge-m3-fp16",
                    "dimensions": 1024,
                    "hybrid": True,
                },
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"status": "error"},
                error=str(e),
            )


if __name__ == "__main__":
    EmbeddingServer.main()
