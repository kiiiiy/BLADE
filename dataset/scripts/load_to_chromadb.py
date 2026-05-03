"""
BLADE - ChromaDB Knowledge Base Loader
bola_chunks.json → ChromaDB (nomic-embed-text embedding)

Usage:
    pip install chromadb ollama
    ollama pull nomic-embed-text
    python load_to_chromadb.py
"""

import json
import sys
import time
from pathlib import Path

import chromadb
import ollama

CHUNKS_FILE = Path(__file__).parent.parent / "chunks"    / "bola_chunks.json"
CHROMA_PATH = Path(__file__).parent.parent / "chroma_db"

COLLECTION_MAP = {
    "cwe":            "bola_standards",
    "capec":          "bola_standards",
    "owasp":          "bola_standards",
    "cve":            "bola_cve",
    "business_logic": "bola_patterns",
}


def embed(text: str) -> list[float]:
    return ollama.embeddings(model="nomic-embed-text", prompt=text)["embedding"]


def load_chunks() -> list[dict]:
    with open(CHUNKS_FILE, encoding="utf-8") as f:
        return json.load(f)


def get_collection_name(source_type: str) -> str:
    return COLLECTION_MAP.get(source_type, "bola_cve")


def run():
    print("=" * 50)
    print("BLADE ChromaDB Loader")
    print("=" * 50)

    if not CHUNKS_FILE.exists():
        print(f"[ERROR] {CHUNKS_FILE} not found")
        sys.exit(1)

    chunks = load_chunks()
    print(f"[INFO] Loaded {len(chunks)} chunks from {CHUNKS_FILE.name}\n")

    client = chromadb.PersistentClient(path=str(CHROMA_PATH))

    collections = {}
    for col_name in set(COLLECTION_MAP.values()):
        collections[col_name] = client.get_or_create_collection(
            name=col_name,
            metadata={"hnsw:space": "cosine"}
        )
        print(f"[INIT] Collection ready: {col_name}")

    print()

    success, skipped, failed = 0, 0, 0

    for chunk in chunks:
        chunk_id    = chunk["id"]
        document    = chunk["document"]
        metadata    = chunk["metadata"]
        source_type = metadata.get("source_type", "cve")
        col_name    = get_collection_name(source_type)
        collection  = collections[col_name]

        existing = collection.get(ids=[chunk_id])
        if existing["ids"]:
            print(f"  [SKIP] {chunk_id} already exists")
            skipped += 1
            continue

        try:
            embedding = embed(document)
            collection.add(
                ids=[chunk_id],
                embeddings=[embedding],
                documents=[document],
                metadatas=[metadata],
            )
            print(f"  [OK]   {chunk_id} → {col_name}")
            success += 1
            time.sleep(0.1)

        except Exception as e:
            print(f"  [FAIL] {chunk_id}: {e}")
            failed += 1

    print()
    print("=" * 50)
    print(f"Done — success: {success}  skipped: {skipped}  failed: {failed}")
    print(f"ChromaDB path: {CHROMA_PATH.resolve()}")

    print()
    print("[VERIFY] Collection counts:")
    for col_name, col in collections.items():
        print(f"  {col_name}: {col.count()} documents")


def search_test(query: str, top_k: int = 3):
    """Quick retrieval test after loading."""
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))

    all_collections = [
        client.get_or_create_collection(name)
        for name in set(COLLECTION_MAP.values())
    ]

    query_embedding = embed(query)
    results = []

    for col in all_collections:
        if col.count() == 0:
            continue
        res = col.query(query_embeddings=[query_embedding], n_results=min(top_k, col.count()))
        for doc, dist, meta in zip(
            res["documents"][0],
            res["distances"][0],
            res["metadatas"][0],
        ):
            results.append((dist, meta.get("source_id", "?"), doc[:120]))

    results.sort(key=lambda x: x[0])
    print(f'\n[SEARCH] Query: "{query}"')
    for dist, sid, snippet in results[:top_k]:
        print(f"  dist={dist:.4f}  id={sid}")
        print(f"  {snippet}...")
        print()


if __name__ == "__main__":
    run()

    print()
    print("[TEST] Running sample retrieval queries...")
    search_test("GET /api/orders/{orderId} user ownership path parameter jwt")
    search_test("UUID resource endpoint missing authorization check")
    search_test("admin role organization settings access control")
