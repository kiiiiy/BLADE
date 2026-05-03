# nvd_raw.csv 데이터 수집 가이드

## 개요

NVD(National Vulnerability Database) API v2.0을 활용해 BOLA 관련 CVE를 대량 수집한 데이터셋.

- **수집 일자**: 2026-05-03
- **총 행 수**: 6,635개
- **수집 스크립트**: `nvd_bulk_collector.py`
- **보강 스크립트**: `enrich_nvd.py`

---

## 수집 기준

### 검색 방식
NVD API의 `cweId` 파라미터 기반 검색 (키워드 검색이 아닌 CWE ID 직접 조회)

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={CWE_ID}&resultsPerPage=100&startIndex={offset}
```

### 대상 CWE

| CWE ID | 이름 | 수집 건수 |
|---|---|---|
| CWE-639 | Authorization Bypass Through User-Controlled Key (IDOR) | 746 |
| CWE-862 | Missing Authorization | 1,593 |
| CWE-284 | Improper Access Control | 2,136 |
| CWE-285 | Improper Authorization | 494 |
| CWE-863 | Incorrect Authorization | 907 |

> 중복 CVE ID 제거 후 최종 **6,635개** 유지

---

## 스키마

| 컬럼 | 설명 | 수집 방식 |
|---|---|---|
| `source_id` | CVE ID (예: CVE-2024-1234) | NVD API |
| `source_type` | 고정값 `cve` | - |
| `endpoint_pattern` | 취약 API 엔드포인트 패턴 | `enrich_nvd.py` 규칙 기반 추론 |
| `http_method` | HTTP 메서드 (GET/PUT/DELETE 등) | `enrich_nvd.py` 규칙 기반 추론 |
| `id_type` | ID 위치 (path_param / query_param / body_param) | `enrich_nvd.py` 규칙 기반 추론 |
| `id_format` | ID 형식 (integer_sequential / uuid / string_slug) | `enrich_nvd.py` 규칙 기반 추론 |
| `ownership_type` | 소유권 유형 (direct / hierarchical / delegated / role_based / contextual) | `enrich_nvd.py` 규칙 기반 추론 |
| `ownership_missing` | 누락된 검증 설명 | `enrich_nvd.py` 규칙 기반 추론 |
| `attack_method` | 공격 방식 (id_substitution / id_enumeration / parameter_tampering) | `enrich_nvd.py` 규칙 기반 추론 |
| `owasp_mapping` | OWASP API Top 10 매핑 | NVD CWE → API1:2023 자동 매핑 |
| `cwe_mapping` | CWE ID (복수 시 `|` 구분) | NVD API |
| `detectable_rule_based` | 규칙 기반 탐지 가능 여부 | `enrich_nvd.py` 추론 |
| `llm_inference_needed` | LLM 추론 필요 여부 | `enrich_nvd.py` 추론 |
| `rule_type` | 적용 규칙 타입 (jwt_ownership / block_path / rate_limit) | CWE 기반 매핑 |
| `severity_score` | CVSS Base Score (0.0~10.0) | NVD API (CVSSv3 우선, 없으면 v2) |
| `business_logic_complexity` | 비즈니스 로직 복잡도 (1~5) | ownership_type + severity 기반 |
| `domain` | 서비스 도메인 추정 | description 키워드 분석 |
| `description` | CVE 영문 설명 원문 | NVD API |

---

## 규칙 기반 필드 추론 로직 (`enrich_nvd.py`)

### ownership_type
| 판단 기준 (description 키워드) | 값 |
|---|---|
| admin, role, privilege, rbac | `role_based` |
| organization, tenant, company, group member | `hierarchical` |
| sender, recipient, shared with, delegat | `delegated` |
| context, workflow, draft, published | `contextual` |
| 해당 없음 | `direct` (기본값) |

### attack_method
| 판단 기준 | 값 |
|---|---|
| enumerat, sequential, iterate, brute force | `id_enumeration` |
| tamper, forge, craft, manipulat | `parameter_tampering` |
| 해당 없음 | `id_substitution` (기본값) |

### rule_type
| 조건 | 값 |
|---|---|
| CWE-284 또는 CWE-863 포함, 또는 ownership_type=role_based | `block_path` |
| 그 외 | `jwt_ownership` |

### detectable_rule_based
- `True`: rule_type=jwt_ownership AND id_type=path_param AND ownership_type=direct
- `False`: 그 외 (복잡한 소유권 구조 또는 block_path 규칙)

---

## severity 분포

| 구간 | 건수 |
|---|---|
| Critical (9.0+) | 588 |
| High (7.0~8.9) | 2,104 |
| Medium (4.0~6.9) | 3,647 |
| Low (~3.9) | 296 |

## domain 분포

| 도메인 | 건수 |
|---|---|
| generic | 4,078 |
| e-commerce | 774 |
| hr | 769 |
| social | 527 |
| banking | 330 |
| saas | 97 |
| healthcare | 60 |

---

## 재생성 방법

```powershell
# 1. NVD API로 재수집 (API 키 있으면 10배 빠름)
python nvd_bulk_collector.py
python nvd_bulk_collector.py --api-key YOUR_KEY

# 2. N/A 필드 규칙 기반 보강
python enrich_nvd.py

# 3. bola_chunks.json에 병합
python merge_datasets.py

# 4. ChromaDB 재적재
python load_to_chromadb.py
```

## 한계

- `endpoint_pattern`은 description에서 URL이 명시된 경우 직접 추출, 없으면 resource 키워드 매핑으로 추정 — 정확도 약 60~70%
- `ownership_type`, `attack_method`는 키워드 기반이므로 복잡한 케이스에서 오분류 가능
- CVSS 점수 없는 CVE는 `severity_score=0.0` 으로 기록됨
- NVD description이 짧거나 기술적 세부사항이 없는 경우 대부분 기본값(direct, id_substitution)으로 채워짐

## Google Sheets Link
- https://docs.google.com/spreadsheets/d/136lvK_Af8d79hbkq9ZduzfvOtgstiQyMRyV_MmzOAKA/edit?usp=sharing