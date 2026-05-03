"""
BLADE - NVD Bulk CVE Collector
Queries NVD API v2.0 by CWE ID to collect BOLA-related CVEs.

Target CWEs:
  CWE-639  Insecure Direct Object Reference (IDOR)
  CWE-862  Missing Authorization
  CWE-284  Improper Access Control
  CWE-285  Improper Authorization
  CWE-863  Incorrect Authorization

Output:
  nvd_raw.csv       — flat enriched CVE rows (bola_dataset.csv compatible)
  nvd_chunks.json   — ChromaDB-ready chunks

Usage:
    pip install requests
    python nvd_bulk_collector.py
    python nvd_bulk_collector.py --api-key YOUR_KEY   (10x rate limit)
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TARGET_CWES = ["CWE-639", "CWE-862", "CWE-284", "CWE-285", "CWE-863"]

# NVD rate limits: 5 req/30 s unauthenticated, 50 req/30 s with API key
SLEEP_UNAUTHENTICATED = 6.5   # seconds between pages (safe margin)
SLEEP_AUTHENTICATED   = 0.7

RESULTS_PER_PAGE = 100        # NVD max is 2000, 100 keeps responses manageable

DATASET_DIR  = Path(__file__).parent.parent
RAW_CSV      = DATASET_DIR / "raw"  / "nvd_raw.csv"
CHUNKS_JSON  = DATASET_DIR / "chunks" / "nvd_chunks.json"

CSV_FIELDNAMES = [
    "source_id", "source_type", "endpoint_pattern", "http_method",
    "id_type", "id_format", "ownership_type", "ownership_missing",
    "attack_method", "owasp_mapping", "cwe_mapping",
    "detectable_rule_based", "llm_inference_needed", "rule_type",
    "severity_score", "business_logic_complexity", "domain", "description",
]

# CWEs that directly map to BOLA/IDOR → API1:2023
BOLA_CWES = {"CWE-639", "CWE-862", "CWE-284", "CWE-285", "CWE-863"}

# ---------------------------------------------------------------------------
# NVD fetch helpers
# ---------------------------------------------------------------------------

def _headers(api_key: str | None) -> dict:
    if api_key:
        return {"apiKey": api_key}
    return {}


def fetch_page(cwe_id: str, start: int, api_key: str | None) -> dict:
    params = {
        "cweId":          cwe_id,
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex":     start,
    }
    for attempt in range(5):
        try:
            r = requests.get(NVD_BASE, params=params, headers=_headers(api_key), timeout=30)
            if r.status_code == 429:
                wait = 35 + attempt * 15
                print(f"    [429] Rate limited — sleeping {wait}s …")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            wait = 10 * (attempt + 1)
            print(f"    [WARN] Request error ({e}) — retry in {wait}s")
            time.sleep(wait)
    return {}


def collect_cwe(cwe_id: str, api_key: str | None) -> list[dict]:
    """Return all CVE items for a given CWE ID."""
    sleep_t = SLEEP_AUTHENTICATED if api_key else SLEEP_UNAUTHENTICATED
    items: list[dict] = []
    start = 0

    while True:
        print(f"  Page startIndex={start} …", end=" ", flush=True)
        data = fetch_page(cwe_id, start, api_key)
        if not data:
            print("empty/error, stopping")
            break

        total       = data.get("totalResults", 0)
        page_items  = data.get("vulnerabilities", [])
        items.extend(page_items)
        print(f"{len(page_items)} items  (total={total})")

        if start + RESULTS_PER_PAGE >= total:
            break
        start += RESULTS_PER_PAGE
        time.sleep(sleep_t)

    return items


# ---------------------------------------------------------------------------
# CVE → row / chunk conversion
# ---------------------------------------------------------------------------

def _severity(cve_item: dict) -> float:
    """Best-available CVSS base score (0.0 if absent)."""
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, IndexError):
                pass
    return 0.0


def _description(cve_item: dict) -> str:
    for d in cve_item.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "").strip()
    return ""


def _cwe_list(cve_item: dict) -> list[str]:
    cwes = []
    for weakness in cve_item.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return list(dict.fromkeys(cwes))   # deduplicate, preserve order


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


def cve_to_row(cve_item: dict) -> dict:
    cve      = cve_item.get("cve", {})
    cve_id   = cve.get("id", "UNKNOWN")
    desc     = _description(cve)
    score    = _severity(cve)
    cwes     = _cwe_list(cve)
    cwe_str  = "|".join(cwes) if cwes else "N/A"

    # severity → business_logic_complexity heuristic
    if score >= 9.0:
        blc = 2
    elif score >= 7.0:
        blc = 2
    elif score >= 5.0:
        blc = 3
    else:
        blc = 3

    owasp = "API1:2023" if any(c in BOLA_CWES for c in cwes) else "API5:2023"

    return {
        "source_id":                cve_id,
        "source_type":              "cve",
        "endpoint_pattern":         "N/A",
        "http_method":              "N/A",
        "id_type":                  "N/A",
        "id_format":                "N/A",
        "ownership_type":           "N/A",
        "ownership_missing":        "N/A",
        "attack_method":            "N/A",
        "owasp_mapping":            owasp,
        "cwe_mapping":              cwe_str,
        "detectable_rule_based":    "N/A",
        "llm_inference_needed":     "N/A",
        "rule_type":                "jwt_ownership",
        "severity_score":           score,
        "business_logic_complexity": blc,
        "domain":                   _domain_guess(desc),
        "description":              desc,
    }


def row_to_chunk(row: dict, chunk_index: int) -> dict:
    cve_id  = row["source_id"]
    desc    = row["description"]
    score   = row["severity_score"]
    cwes    = row["cwe_mapping"]
    domain  = row["domain"]
    owasp   = row["owasp_mapping"]

    document = (
        f"CVE ID: {cve_id}\n"
        f"Severity: {score}\n"
        f"CWE: {cwes}\n"
        f"OWASP: {owasp}\n"
        f"Domain: {domain}\n"
        f"Description: {desc}"
    )

    metadata = {
        "source_type":              "cve",
        "source_id":                cve_id,
        "rule_type":                "jwt_ownership",
        "severity":                 score,
        "cwe":                      cwes,
        "owasp":                    owasp,
        "domain":                   domain,
        "business_logic_complexity": row["business_logic_complexity"],
    }

    return {
        "id":       f"cve_{cve_id.replace('-', '_').lower()}_{chunk_index:04d}",
        "document": document,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(api_key: str | None):
    print("=" * 55)
    print("BLADE  NVD Bulk Collector")
    print("=" * 55)
    if api_key:
        print("[AUTH] Using NVD API key")
    else:
        print("[AUTH] No API key — unauthenticated (slow, 5 req/30 s)")
    print()

    all_items: dict[str, dict] = {}   # cve_id → raw item (dedup)

    for cwe_id in TARGET_CWES:
        print(f"[CWE] {cwe_id}")
        items = collect_cwe(cwe_id, api_key)
        before = len(all_items)
        for item in items:
            cve_id_val = item.get("cve", {}).get("id", "")
            if cve_id_val and cve_id_val not in all_items:
                all_items[cve_id_val] = item
        added = len(all_items) - before
        print(f"  → {len(items)} fetched  |  {added} new unique  |  total so far: {len(all_items)}\n")

    print(f"[TOTAL] {len(all_items)} unique CVEs collected\n")

    rows   = [cve_to_row(item) for item in all_items.values()]
    chunks = [row_to_chunk(row, i) for i, row in enumerate(rows)]

    # --- Write CSV ---
    with open(RAW_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[CSV]   {RAW_CSV.name}  →  {len(rows)} rows")

    # --- Write JSON chunks ---
    with open(CHUNKS_JSON, "w", encoding="utf-8") as f:
        json.dump(chunks, f, ensure_ascii=False, indent=2)
    print(f"[JSON]  {CHUNKS_JSON.name}  →  {len(chunks)} chunks")

    # --- Stats ---
    print()
    print("[STATS] Domain distribution:")
    domain_counts: dict[str, int] = {}
    for r in rows:
        domain_counts[r["domain"]] = domain_counts.get(r["domain"], 0) + 1
    for domain, cnt in sorted(domain_counts.items(), key=lambda x: -x[1]):
        print(f"  {domain:<20} {cnt}")

    print()
    print("[STATS] Severity distribution:")
    bands = {"critical(9+)": 0, "high(7-9)": 0, "medium(4-7)": 0, "low(<4)": 0}
    for r in rows:
        s = float(r["severity_score"])
        if s >= 9:
            bands["critical(9+)"] += 1
        elif s >= 7:
            bands["high(7-9)"] += 1
        elif s >= 4:
            bands["medium(4-7)"] += 1
        else:
            bands["low(<4)"] += 1
    for band, cnt in bands.items():
        print(f"  {band:<20} {cnt}")

    print()
    print("Done.")
    print(f"Next step: run merge_datasets.py to combine with existing bola_chunks.json")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BLADE NVD bulk CVE collector")
    parser.add_argument("--api-key", default=None, help="NVD API key (optional but recommended)")
    args = parser.parse_args()
    run(api_key=args.api_key)
