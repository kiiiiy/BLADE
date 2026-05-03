"""
BLADE - Dataset Merger
Merges nvd_chunks.json / sheets_chunks.json into bola_chunks.json.
Deduplicates by both chunk ID AND source_id (CVE ID) so the same CVE
collected from different sources is not stored twice.

Usage:
    python merge_datasets.py                   # merge nvd_chunks.json
    python merge_datasets.py --also-sheets     # also merge sheets_chunks.json
    python merge_datasets.py --dry-run         # preview only
"""

import argparse
import json
from pathlib import Path

DATASET_DIR   = Path(__file__).parent.parent
MAIN_CHUNKS   = DATASET_DIR / "chunks" / "bola_chunks.json"
NVD_CHUNKS    = DATASET_DIR / "chunks" / "nvd_chunks.json"
SHEETS_CHUNKS = DATASET_DIR / "chunks" / "sheets_chunks.json"


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def merge_into(existing: list[dict], incoming: list[dict], label: str) -> tuple[list[dict], int, int]:
    existing_chunk_ids  = {c["id"] for c in existing}
    existing_source_ids = {c["metadata"].get("source_id", "") for c in existing}

    new_chunks = []
    dup_id = dup_source = 0

    for c in incoming:
        if c["id"] in existing_chunk_ids:
            dup_id += 1
            continue
        sid = c["metadata"].get("source_id", "")
        if sid and sid in existing_source_ids:
            dup_source += 1
            continue
        new_chunks.append(c)
        existing_chunk_ids.add(c["id"])
        if sid:
            existing_source_ids.add(sid)

    total_dup = dup_id + dup_source
    print(f"[{label}]")
    print(f"  Input chunks              : {len(incoming):>5}")
    print(f"  Duplicate chunk IDs       : {dup_id:>5}")
    print(f"  Duplicate CVE IDs         : {dup_source:>5}  ← same CVE from another source")
    print(f"  New to add                : {len(new_chunks):>5}")
    return existing + new_chunks, len(new_chunks), total_dup


def run(dry_run: bool, also_sheets: bool):
    existing = load(MAIN_CHUNKS)
    print(f"Existing bola_chunks.json : {len(existing):>5} chunks\n")

    nvd = load(NVD_CHUNKS)
    if nvd:
        existing, added, duped = merge_into(existing, nvd, "nvd_chunks.json")
    else:
        print(f"[SKIP] {NVD_CHUNKS.name} not found")

    if also_sheets:
        sheets = load(SHEETS_CHUNKS)
        if sheets:
            existing, added2, duped2 = merge_into(existing, sheets, "sheets_chunks.json")
        else:
            print(f"[SKIP] {SHEETS_CHUNKS.name} not found — run sheets_importer.py first")

    print(f"\nMerged total              : {len(existing):>5} chunks")

    if dry_run:
        print("\n[DRY-RUN] No files written.")
        return

    with open(MAIN_CHUNKS, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)
    print(f"[OK] bola_chunks.json updated → {len(existing)} total chunks")

    col_map = {"cwe": "bola_standards", "capec": "bola_standards",
               "owasp": "bola_standards", "cve": "bola_cve",
               "business_logic": "bola_patterns"}
    counts: dict[str, int] = {}
    for c in existing:
        st  = c["metadata"].get("source_type", "cve")
        col = col_map.get(st, "bola_cve")
        counts[col] = counts.get(col, 0) + 1
    print("\n[STATS] Collection breakdown:")
    for col, cnt in sorted(counts.items()):
        print(f"  {col:<25} {cnt}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--also-sheets", action="store_true",
                        help="Also merge sheets_chunks.json")
    args = parser.parse_args()
    run(dry_run=args.dry_run, also_sheets=args.also_sheets)
