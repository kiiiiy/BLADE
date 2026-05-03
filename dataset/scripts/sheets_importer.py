"""
BLADE - Google Sheets CVE Importer
Downloads user's Google Spreadsheet (500+ CVEs) and converts to bola_chunks.json entries.

The spreadsheet has these columns (Korean headers):
  CVE ID, 취약 엔드포인트 패턴, ID 유형, 소유권 검증 누락 위치, 공격 방식,
  OWASP 매핑, 탐지 가능 여부, LLM 추론 필요 여부, 설명, CWE

Most cells except CVE ID, 설명(description) and CWE are 'N/A'.

Output: sheets_chunks.json — then run merge_datasets.py to fold into bola_chunks.json

Usage:
    pip install requests
    python sheets_importer.py
    python sheets_importer.py --sheet-id YOUR_SHEET_ID
"""

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Default sheet — user's spreadsheet
# ---------------------------------------------------------------------------
DEFAULT_SHEET_ID = "1R2aoTQrz_ByQ5CABeZLJrWvQZg5kSu-30tVbVWxmSQU"

DATASET_DIR    = Path(__file__).parent.parent
CHUNKS_OUT     = DATASET_DIR / "chunks" / "sheets_chunks.json"

# ---------------------------------------------------------------------------
# Column name normalisation
# (Korean headers → canonical field names)
# ---------------------------------------------------------------------------
HEADER_MAP = {
    # Korean headers
    "CVE ID":          "cve_id",
    "cve id":          "cve_id",
    "취약 엔드포인트 패턴":   "endpoint_pattern",
    "ID 유형":          "id_type",
    "소유권 검증 누락 위치":  "ownership_missing",
    "공격 방식":          "attack_method",
    "OWASP 매핑":        "owasp_mapping",
    "탐지 가능 여부":       "detectable_rule_based",
    "LLM 추론 필요 여부":   "llm_inference_needed",
    "설명":             "description",
    "CWE":             "cwe_mapping",
    # English fall-backs
    "cve_id":           "cve_id",
    "endpoint_pattern": "endpoint_pattern",
    "description":      "description",
    "cwe":              "cwe_mapping",
    "cwe_mapping":      "cwe_mapping",
    "owasp":            "owasp_mapping",
}


def download_csv(sheet_id: str) -> str:
    url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid=0"
    print(f"[DOWNLOAD] {url}")
    r = requests.get(url, timeout=30, allow_redirects=True)
    if r.status_code != 200:
        print(f"[ERROR] HTTP {r.status_code}")
        sys.exit(1)
    if "text/csv" not in r.headers.get("Content-Type", "") and len(r.text) < 500:
        print("[WARN] Response may not be CSV — check sheet is publicly viewable (Anyone with link → Viewer)")
        print(f"[DEBUG] Response start: {r.text[:300]}")
    print(f"[OK] Downloaded {len(r.text)} chars")
    return r.text


def normalise_header(h: str) -> str:
    stripped = h.strip()
    return HEADER_MAP.get(stripped, stripped.lower().replace(" ", "_"))


def parse_csv(raw: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(raw))
    rows = []
    for row in reader:
        normalised = {normalise_header(k): v.strip() for k, v in row.items()}
        rows.append(normalised)
    return rows


def is_na(val: str) -> bool:
    return not val or val.strip().upper() in ("N/A", "NA", "-", "")


def _domain_guess(description: str) -> str:
    desc_l = description.lower()
    hints = {
        "e-commerce":  ["cart", "order", "payment", "invoice", "product", "shop"],
        "healthcare":  ["patient", "medical", "health", "doctor", "clinical"],
        "banking":     ["bank", "account", "transfer", "transaction", "finance"],
        "hr":          ["employee", "salary", "payroll", "staff", "hr"],
        "saas":        ["tenant", "organization", "subscription", "workspace"],
        "social":      ["post", "comment", "friend", "profile", "message"],
    }
    for domain, keywords in hints.items():
        if any(k in desc_l for k in keywords):
            return domain
    return "generic"


def row_to_chunk(row: dict, index: int) -> dict | None:
    cve_id = row.get("cve_id", "").strip()
    if not cve_id or not re.match(r"CVE-\d{4}-\d+", cve_id, re.IGNORECASE):
        return None  # skip header repeats or non-CVE rows

    desc     = row.get("description", "").strip()
    cwe      = row.get("cwe_mapping", row.get("cwe", "N/A")).strip()
    owasp    = row.get("owasp_mapping", "API1:2023").strip()
    endpoint = row.get("endpoint_pattern", "N/A").strip()
    attack   = row.get("attack_method", "N/A").strip()
    id_type  = row.get("id_type", "N/A").strip()

    if is_na(owasp):
        owasp = "API1:2023"

    domain = _domain_guess(desc)

    document = (
        f"CVE ID: {cve_id}\n"
        f"CWE: {cwe}\n"
        f"OWASP: {owasp}\n"
        f"Endpoint: {endpoint}\n"
        f"Attack method: {attack}\n"
        f"ID type: {id_type}\n"
        f"Domain: {domain}\n"
        f"Description: {desc}"
    )

    chunk_id = f"cve_{cve_id.replace('-', '_').lower()}_sh{index:04d}"

    metadata = {
        "source_type": "cve",
        "source_id":   cve_id,
        "rule_type":   "jwt_ownership",
        "severity":    0.0,
        "cwe":         cwe,
        "owasp":       owasp,
        "domain":      domain,
        "business_logic_complexity": 3,
        "from_sheets": True,
    }

    return {"id": chunk_id, "document": document, "metadata": metadata}


def run(sheet_id: str, local_csv: str | None = None):
    print("=" * 55)
    print("BLADE  Google Sheets Importer")
    print("=" * 55)

    if local_csv:
        print(f"[LOCAL] Reading {local_csv}")
        raw = Path(local_csv).read_text(encoding="utf-8-sig")
    else:
        raw = download_csv(sheet_id)
    rows = parse_csv(raw)
    print(f"[PARSE] {len(rows)} rows found\n")

    chunks = []
    skipped = 0
    for i, row in enumerate(rows):
        chunk = row_to_chunk(row, i)
        if chunk:
            chunks.append(chunk)
        else:
            skipped += 1

    print(f"[CONVERT] {len(chunks)} valid CVE chunks  |  {skipped} skipped (headers/invalid)")

    with open(CHUNKS_OUT, "w", encoding="utf-8") as f:
        json.dump(chunks, f, ensure_ascii=False, indent=2)
    print(f"[OK] {CHUNKS_OUT.name}  →  {len(chunks)} chunks")
    print()
    print("Next step: python merge_datasets.py  (merges into bola_chunks.json)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sheet-id", default=DEFAULT_SHEET_ID)
    parser.add_argument("--local-csv", default=None, help="Path to locally downloaded CSV file")
    args = parser.parse_args()
    run(sheet_id=args.sheet_id, local_csv=args.local_csv)
