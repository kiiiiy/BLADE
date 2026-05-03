"""
BLADE - NVD CVE Enricher
Rule-based enrichment of nvd_raw.csv N/A fields using description analysis.

Fills in:
  endpoint_pattern, http_method, id_type, id_format,
  ownership_type, ownership_missing, attack_method,
  detectable_rule_based, llm_inference_needed,
  rule_type (refine), business_logic_complexity (refine)

Output: nvd_raw.csv (overwrite) + nvd_chunks.json (regenerate)

Usage:
    python enrich_nvd.py
    python enrich_nvd.py --dry-run   (show sample without writing)
"""

import argparse
import csv
import json
import re
from pathlib import Path

DATASET_DIR = Path(__file__).parent.parent
RAW_CSV     = DATASET_DIR / "raw"    / "nvd_raw.csv"
CHUNKS_OUT  = DATASET_DIR / "chunks" / "nvd_chunks.json"

# ---------------------------------------------------------------------------
# Rule engine helpers
# ---------------------------------------------------------------------------

def _lower(text: str) -> str:
    return text.lower()


# --- endpoint_pattern ---

_EXPLICIT_URL = re.compile(
    r'(?:GET|POST|PUT|DELETE|PATCH)\s+(\/[^\s,\.\'"<>]{3,})', re.IGNORECASE
)
_URL_PATTERN = re.compile(
    r'(?:endpoint|path|url|uri|route)[:\s]+([/][a-zA-Z0-9_\-/{}.]+)', re.IGNORECASE
)
_PARAM_WORD = re.compile(
    r'(?:the\s+)?(\w+)\s*(?:parameter|param|id|ID|identifier)\b', re.IGNORECASE
)

_RESOURCE_KEYWORDS = {
    "order":        "/api/orders/{orderId}",
    "invoice":      "/api/invoices/{invoiceId}",
    "cart":         "/api/cart",
    "product":      "/api/products/{productId}",
    "user":         "/api/users/{userId}",
    "account":      "/api/accounts/{accountId}",
    "profile":      "/api/profiles/{userId}",
    "message":      "/api/messages/{messageId}",
    "post":         "/api/posts/{postId}",
    "comment":      "/api/comments/{commentId}",
    "file":         "/api/files/{fileId}",
    "document":     "/api/documents/{documentId}",
    "report":       "/api/reports/{reportId}",
    "ticket":       "/api/tickets/{ticketId}",
    "issue":        "/api/issues/{issueId}",
    "project":      "/api/projects/{projectId}",
    "task":         "/api/tasks/{taskId}",
    "patient":      "/api/patients/{patientId}",
    "record":       "/api/records/{recordId}",
    "employee":     "/api/employees/{employeeId}",
    "subscription": "/api/subscriptions/{subId}",
    "payment":      "/api/payments/{paymentId}",
    "transaction":  "/api/transactions/{transactionId}",
    "poll":         "/api/polls/{pollId}",
    "paper":        "/api/papers/{paperId}",
    "event":        "/api/events/{eventId}",
    "booking":      "/api/bookings/{bookingId}",
    "course":       "/api/courses/{courseId}",
    "pinboard":     "/api/pinboards/{pinboardId}",
    "household":    "/api/households/{householdId}",
    "repository":   "/api/repos/{repoId}",
    "merge request": "/api/mergerequests/{mrId}",
    "group":        "/api/groups/{groupId}",
    "organization": "/api/organizations/{orgId}",
    "tenant":       "/api/tenants/{tenantId}",
    "swimlane":     "/api/swimlanes/{swimlaneId}",
    "column":       "/api/columns/{columnId}",
    "category":     "/api/categories/{categoryId}",
    "job":          "/api/jobs/{jobId}",
    "schedule":     "/api/schedules/{scheduleId}",
    "log":          "/api/logs/{logId}",
    "backup":       "/api/backups/{backupId}",
    "key":          "/api/keys/{keyId}",
    "token":        "/api/tokens/{tokenId}",
    "voucher":      "/api/vouchers/{voucherId}",
    "coupon":       "/api/coupons/{couponId}",
    "address":      "/api/addresses/{addressId}",
    "wishlist":     "/api/wishlists/{wishlistId}",
    "review":       "/api/reviews/{reviewId}",
    "rating":       "/api/ratings/{ratingId}",
    "notification": "/api/notifications/{notificationId}",
    "webhook":      "/api/webhooks/{webhookId}",
    "session":      "/api/sessions/{sessionId}",
    "device":       "/api/devices/{deviceId}",
    "secret":       "/api/secrets/{secretId}",
    "credential":   "/api/credentials/{credentialId}",
}

def infer_endpoint(desc: str, cwe: str) -> str:
    d = _lower(desc)
    # explicit URL in description
    m = _EXPLICIT_URL.search(desc)
    if m:
        path = m.group(1).rstrip(".,;)")
        # normalise any concrete IDs to placeholders
        path = re.sub(r'/\d+', '/{id}', path)
        return path
    # resource keyword match
    for keyword, pattern in _RESOURCE_KEYWORDS.items():
        if keyword in d:
            return pattern
    # fallback: try to extract param name
    m2 = _PARAM_WORD.search(desc)
    if m2:
        param = m2.group(1).lower()
        return f"/api/{{resource}}/{{{param}Id}}"
    return "/api/{resource}/{id}"


# --- http_method ---

def infer_http_method(desc: str) -> str:
    d = _lower(desc)
    methods = []
    if any(w in d for w in ["view", "read", "access", "disclose", "retrieve", "get", "list", "expose", "leak"]):
        methods.append("GET")
    if any(w in d for w in ["modif", "edit", "update", "change", "alter", "set "]):
        methods.append("PUT")
    if any(w in d for w in ["delete", "remov", "delet"]):
        methods.append("DELETE")
    if any(w in d for w in ["creat", "submit", "add ", "upload", "post "]):
        methods.append("POST")
    if not methods:
        methods = ["GET"]
    return "/".join(dict.fromkeys(methods))


# --- id_type ---

def infer_id_type(desc: str) -> str:
    d = _lower(desc)
    if any(w in d for w in ["path param", "url param", "uri param", "via /{", "in the path", "path variable"]):
        return "path_param"
    if any(w in d for w in ["query param", "query string", "get param", "?id=", "?pid=", "?user_id="]):
        return "query_param"
    if any(w in d for w in ["post body", "request body", "form data", "json body", "body param"]):
        return "body_param"
    # default BOLA assumption
    return "path_param"


# --- id_format ---

def infer_id_format(desc: str) -> str:
    d = _lower(desc)
    if any(w in d for w in ["uuid", "guid", "universally unique"]):
        return "uuid"
    if any(w in d for w in ["sequential", "integer id", "numeric id", "incremental", "auto-increment", "integer value", "guessable"]):
        return "integer_sequential"
    if any(w in d for w in ["username", "email", "slug", "name-based"]):
        return "string_slug"
    return "N/A"


# --- ownership_type ---

def infer_ownership_type(desc: str, cwe: str) -> str:
    d = _lower(desc)
    if any(w in d for w in ["admin", "role", "privilege", "permission level", "rbac"]):
        return "role_based"
    if any(w in d for w in ["organization", "tenant", "company", "department", "group member", "org member"]):
        return "hierarchical"
    if any(w in d for w in ["sender", "recipient", "both", "either party", "shared with", "delegat"]):
        return "delegated"
    if any(w in d for w in ["context", "workflow", "state", "phase", "draft", "published"]):
        return "contextual"
    return "direct"


# --- ownership_missing ---

_OWNERSHIP_TEMPLATES = {
    "role_based":   "role-based access check missing — JWT role not verified before resource access",
    "hierarchical": "organization/tenant membership not verified — cross-tenant access possible",
    "delegated":    "delegation chain not checked — recipient/owner relationship not validated",
    "contextual":   "context-dependent authorization missing — workflow state not enforced",
    "direct":       "object owner not compared against JWT subject — any authenticated user can access",
}

def infer_ownership_missing(desc: str, ownership_type: str) -> str:
    d = _lower(desc)
    # try to extract specific resource name for a more precise message
    for keyword in _RESOURCE_KEYWORDS:
        if keyword in d:
            resource = keyword
            base = _OWNERSHIP_TEMPLATES[ownership_type]
            return f"{resource} {base}"
    return _OWNERSHIP_TEMPLATES[ownership_type]


# --- attack_method ---

def infer_attack_method(desc: str) -> str:
    d = _lower(desc)
    if any(w in d for w in ["enumerat", "brute force", "sequential", "iterate", "increment", "series of"]):
        return "id_enumeration"
    if any(w in d for w in ["tamper", "forge", "craft", "manipulat", "alter", "modif"]):
        return "parameter_tampering"
    # substitution is the most common BOLA pattern
    return "id_substitution"


# --- rule_type ---

def infer_rule_type(cwe: str, ownership_type: str) -> str:
    cwes = set(cwe.upper().split("|"))
    if "CWE-284" in cwes or "CWE-863" in cwes:
        return "block_path"
    if ownership_type == "role_based":
        return "block_path"
    return "jwt_ownership"


# --- detectable / llm_inference_needed ---

def infer_detectable(rule_type: str, id_type: str, ownership_type: str) -> str:
    if rule_type == "jwt_ownership" and id_type == "path_param" and ownership_type == "direct":
        return "True"
    if rule_type == "rate_limit":
        return "True"
    return "False"


def infer_llm_needed(detectable: str, ownership_type: str) -> str:
    if detectable == "False":
        return "True"
    if ownership_type in ("hierarchical", "delegated", "contextual"):
        return "True"
    return "False"


# --- business_logic_complexity ---

_COMPLEXITY_MAP = {
    "direct":      2,
    "delegated":   3,
    "contextual":  3,
    "role_based":  4,
    "hierarchical": 4,
}

def infer_complexity(ownership_type: str, severity: float) -> int:
    base = _COMPLEXITY_MAP.get(ownership_type, 3)
    # bump up for very high severity (likely multi-vector)
    if severity >= 9.0:
        base = min(base + 1, 5)
    return base


# ---------------------------------------------------------------------------
# Enrich a single row
# ---------------------------------------------------------------------------

def enrich_row(row: dict) -> dict:
    desc  = row.get("description", "")
    cwe   = row.get("cwe_mapping", "N/A")
    score = float(row.get("severity_score", 0) or 0)

    ownership_type = infer_ownership_type(desc, cwe)
    endpoint       = infer_endpoint(desc, cwe)
    http_method    = infer_http_method(desc)
    id_type        = infer_id_type(desc)
    id_format      = infer_id_format(desc)
    attack_method  = infer_attack_method(desc)
    ownership_miss = infer_ownership_missing(desc, ownership_type)
    rule_type      = infer_rule_type(cwe, ownership_type)
    detectable     = infer_detectable(rule_type, id_type, ownership_type)
    llm_needed     = infer_llm_needed(detectable, ownership_type)
    complexity     = infer_complexity(ownership_type, score)

    return {
        **row,
        "endpoint_pattern":         endpoint,
        "http_method":              http_method,
        "id_type":                  id_type,
        "id_format":                id_format,
        "ownership_type":           ownership_type,
        "ownership_missing":        ownership_miss,
        "attack_method":            attack_method,
        "detectable_rule_based":    detectable,
        "llm_inference_needed":     llm_needed,
        "rule_type":                rule_type,
        "business_logic_complexity": complexity,
    }


# ---------------------------------------------------------------------------
# Row → chunk
# ---------------------------------------------------------------------------

def row_to_chunk(row: dict, index: int) -> dict:
    cve_id   = row["source_id"]
    desc     = row["description"]
    score    = row["severity_score"]
    cwe      = row["cwe_mapping"]
    domain   = row["domain"]
    owasp    = row["owasp_mapping"]
    endpoint = row["endpoint_pattern"]
    method   = row["http_method"]
    id_type  = row["id_type"]
    ot       = row["ownership_type"]
    attack   = row["attack_method"]
    rt       = row["rule_type"]
    blc      = row["business_logic_complexity"]

    document = (
        f"CVE ID: {cve_id}\n"
        f"Severity: {score}\n"
        f"CWE: {cwe}\n"
        f"OWASP: {owasp}\n"
        f"Endpoint: {endpoint}\n"
        f"HTTP method: {method}\n"
        f"ID type: {id_type}\n"
        f"Ownership type: {ot}\n"
        f"Attack method: {attack}\n"
        f"Rule type: {rt}\n"
        f"Domain: {domain}\n"
        f"Description: {desc}"
    )

    metadata = {
        "source_type":               "cve",
        "source_id":                 cve_id,
        "rule_type":                 rt,
        "severity":                  float(score),
        "cwe":                       cwe,
        "owasp":                     owasp,
        "domain":                    domain,
        "ownership_type":            ot,
        "attack_method":             attack,
        "business_logic_complexity": int(blc),
    }

    return {
        "id":       f"cve_{cve_id.replace('-', '_').lower()}_{index:04d}",
        "document": document,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

FIELDNAMES = [
    "source_id", "source_type", "endpoint_pattern", "http_method",
    "id_type", "id_format", "ownership_type", "ownership_missing",
    "attack_method", "owasp_mapping", "cwe_mapping",
    "detectable_rule_based", "llm_inference_needed", "rule_type",
    "severity_score", "business_logic_complexity", "domain", "description",
]


def run(dry_run: bool):
    print("=" * 55)
    print("BLADE  NVD Enricher")
    print("=" * 55)

    with open(RAW_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"[READ] {len(rows)} rows from {RAW_CSV.name}")

    enriched = [enrich_row(r) for r in rows]

    # --- sample preview ---
    print("\n[SAMPLE] First 3 enriched rows:")
    for r in enriched[:3]:
        print(f"  {r['source_id']}")
        print(f"    endpoint      : {r['endpoint_pattern']}")
        print(f"    http_method   : {r['http_method']}")
        print(f"    id_type       : {r['id_type']}")
        print(f"    id_format     : {r['id_format']}")
        print(f"    ownership     : {r['ownership_type']}")
        print(f"    attack_method : {r['attack_method']}")
        print(f"    rule_type     : {r['rule_type']}")
        print(f"    detectable    : {r['detectable_rule_based']}")
        print(f"    llm_needed    : {r['llm_inference_needed']}")
        print()

    # --- stats ---
    def dist(key):
        counts: dict = {}
        for r in enriched:
            v = str(r[key])
            counts[v] = counts.get(v, 0) + 1
        return sorted(counts.items(), key=lambda x: -x[1])

    print("[STATS] ownership_type:")
    for v, c in dist("ownership_type"):
        print(f"  {v:<20} {c}")

    print("[STATS] attack_method:")
    for v, c in dist("attack_method"):
        print(f"  {v:<25} {c}")

    print("[STATS] rule_type:")
    for v, c in dist("rule_type"):
        print(f"  {v:<20} {c}")

    print("[STATS] detectable_rule_based:")
    for v, c in dist("detectable_rule_based"):
        print(f"  {v:<10} {c}")

    if dry_run:
        print("\n[DRY-RUN] No files written.")
        return

    # --- write CSV ---
    with open(RAW_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(enriched)
    print(f"\n[CSV]  {RAW_CSV.name} overwritten with enriched data")

    # --- write chunks ---
    chunks = [row_to_chunk(r, i) for i, r in enumerate(enriched)]
    with open(CHUNKS_OUT, "w", encoding="utf-8") as f:
        json.dump(chunks, f, ensure_ascii=False, indent=2)
    print(f"[JSON] {CHUNKS_OUT.name} regenerated → {len(chunks)} chunks")
    print()
    print("Next: python merge_datasets.py  (re-merge enriched chunks into bola_chunks.json)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    run(dry_run=args.dry_run)
