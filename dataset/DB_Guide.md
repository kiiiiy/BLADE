# BLADE - RAG 지식 베이스 구축 가이드

> LLM 기반 BOLA 자동 탐지 프록시 오픈소스 — 데이터베이스 설계 및 구축 문서  

---

## 목차

1. [시스템 내 데이터베이스의 역할](#1-시스템-내-데이터베이스의-역할)
2. [데이터 소스 분류](#2-데이터-소스-분류)
3. [스프레드시트 스키마 (수치화 기준)](#3-스프레드시트-스키마-수치화-기준)
4. [ChromaDB 청크 설계](#4-chromadb-청크-설계)
5. [비즈니스 로직 패턴 라이브러리](#5-비즈니스-로직-패턴-라이브러리)
6. [단계별 구축 계획](#6-단계별-구축-계획)
7. [수집 자동화 코드 가이드](#7-수집-자동화-코드-가이드)
8. [품질 검증 기준](#8-품질-검증-기준)
9. [주의사항 및 흔한 실수](#9-주의사항-및-흔한-실수)

---

## 1. 시스템 내 데이터베이스의 역할

### 전체 흐름에서의 위치

```
[오프라인 - 1회성]
NVD / OWASP / HackerOne / 비즈니스로직패턴
            ↓ embed (nomic-embed-text)
        ChromaDB (지식 베이스)
            ↓ RAG 검색
OAS 파일 입력 → LLM (qwen2.5:7b) → policy.json 생성

[런타임 - 매 요청]
API 요청 → JWT 파싱 → policy.json 매핑 → 차단/허용
                                          (LLM 없음)
```

**핵심 역할:**  
ChromaDB는 LLM이 OAS 엔드포인트를 보고 "이 파라미터는 소유권 검증이 필요하다"고 추론할 때 근거를 제공하는 보조 지식입니다.  
LLM을 직접 훈련시키는 게 아니라, **추론 시점에 관련 사례를 주입**하는 RAG 방식입니다.

---

## 2. 데이터 소스 분류

### 2-1. 자동 수집 가능 (우선순위 높음)

| 소스 | 내용 | 수집 방법 | 분량 목표 |
|------|------|-----------|-----------|
| **NVD CVE** | BOLA/IDOR 관련 CVE | NVD REST API v2.0 | 50~100개 |
| **CWE XML** | CWE-639, 284, 285, 862, 863 | mitre.org XML 파싱 | 5~10개 |
| **CAPEC XML** | CAPEC-122, 1, 560 | mitre.org XML 파싱 | 5~10개 |
| **OWASP WSTG** | BUSL-01~09 비즈니스 로직 테스트 | PDF/HTML 파싱 | 9개 섹션 |

**NVD 수집 키워드 (현재 3개 → 확장 필요):**
```python
keywords = [
    "broken object level authorization",
    "insecure direct object reference IDOR",
    "object level authorization API",
    # 추가 권장
    "unauthorized access to resource",
    "missing authorization check",
    "BOLA API vulnerability",
    "object ownership bypass",
    "horizontal privilege escalation",
]
```

### 2-2. 수동 수집 필요 (우선순위 높음)

| 소스 | 내용 | 수집 방법 | 분량 목표 |
|------|------|-----------|-----------|
| **HackerOne 공개 리포트** | 실제 IDOR 취약점 사례 | 사이트 수동 수집 후 정형화 | 20~30개 |
| **PortSwigger BL Labs** | 비즈니스 로직 취약점 예시 | 페이지 텍스트 파싱 | 10개 |
| **버그바운티 블로그** | Medium IDOR writeup | 수동 수집 | 10~15개 |

**HackerOne 수집 경로:**
```
https://hackerone.com/hacktivity
→ 필터: "IDOR" 또는 "Broken Object Level Authorization"
→ Disclosed 상태인 것만
→ 아래 스키마로 정형화
```

### 2-3. 직접 작성 필요 (우선순위 높음, 대체 불가)

- **비즈니스 로직 패턴 라이브러리** (섹션 5 참고)
- **파라미터 이름 → 소유권 의미 매핑**
- **Few-shot 예시 쌍** (OAS 엔드포인트 → 올바른 policy.json)

---

## 3. 스프레드시트 스키마 (수치화 기준)

모든 수집 데이터는 아래 공통 스키마로 정형화한 뒤 ChromaDB에 적재합니다.

### 컬럼 정의

| 컬럼명 | 타입 | 설명 | 값 예시 |
|--------|------|------|---------|
| `source_id` | string | 고유 식별자 | CVE-2024-55072, H1-123456, BL-001 |
| `source_type` | enum | 데이터 출처 | cve / cwe / capec / hackerone / owasp / business_logic |
| `endpoint_pattern` | string | 취약 엔드포인트 패턴 | /api/users/{userId}/orders |
| `http_method` | enum | HTTP 메서드 | GET / POST / PUT / PATCH / DELETE |
| `id_type` | enum | ID 노출 방식 | path_param / query_param / body_field |
| `id_format` | enum | ID 형식 | integer_sequential / uuid / slug / hash |
| `ownership_type` | enum | 소유권 관계 유형 | direct / hierarchical / delegated / role_based / contextual |
| `ownership_missing` | string | 검증 누락 위치 | DB 조회 전 소유권 미확인 |
| `attack_method` | string | 공격 방식 | id_enumeration / id_substitution / parameter_tampering |
| `owasp_mapping` | string | OWASP 매핑 | API1:2023 |
| `cwe_mapping` | string | CWE 매핑 | CWE-639 |
| `detectable_rule_based` | boolean | 룰 기반 탐지 가능 여부 | true / false |
| `llm_inference_needed` | boolean | LLM 추론 필요 여부 | true / false |
| `rule_type` | enum | 생성될 정책 룰 타입 | jwt_ownership / block_path / rate_limit / strip_body_field |
| `severity_score` | float | CVSS 점수 (없으면 추정) | 0.0 ~ 10.0 |
| `business_logic_complexity` | int | 소유권 규칙 복잡도 | 1(단순) ~ 5(다단계) |
| `domain` | string | 비즈니스 도메인 | ecommerce / finance / sns / enterprise / file |
| `description` | string | 취약점 설명 (한/영) | 전문 설명 |

### 수치화 기준 상세

**`id_type` 위험도 점수:**
```
path_param  → 3점 (URL에 노출, 열거 용이)
query_param → 2점 (URL에 노출, 변경 용이)
body_field  → 1점 (body 수정 필요, 상대적으로 어려움)
```

**`business_logic_complexity` 기준:**
```
1 → JWT.sub == path_param (단순 1:1 비교)
2 → DB 1회 조회 후 비교
3 → DB 2회 조회 (중간 테이블 경유)
4 → 계층적 소유권 (org > team > user)
5 → 다단계 소유권 + 역할 조합
```

**`rule_type` 매핑 기준:**
```
소유권 검증 필요           → jwt_ownership
관리자만 접근 가능 경로    → block_path
열거 공격 방지 필요        → rate_limit
민감 필드 노출 방지        → strip_body_field
```

---

## 4. ChromaDB 청크 설계

### 4-1. 청크 단위 원칙

```
1 청크 = 1 의미 단위
- CVE 1개 → 1 청크
- 비즈니스 로직 패턴 1개 → 1 청크
- 버그바운티 리포트 1개 → 1 청크 (요약 압축)

토큰 범위: 200 ~ 400 토큰
언어: 영어 권장 (임베딩 모델 성능)
```

### 4-2. CVE 청크 형식

```python
document = """
취약점_유형: BOLA
CVE_ID: CVE-2024-55072
엔드포인트_패턴: /api/users/{userId}
HTTP_메서드: GET
ID_유형: path_parameter
ID_형식: integer_sequential
소유권_관계: users.id == JWT.sub (직접 비교)
누락된_검증: DB 조회 전 소유권 미확인
공격_방식: userId를 타인의 값으로 변경하여 계정 정보 열람
탐지_룰_타입: jwt_ownership
심각도: MEDIUM (CVSS 5.4)
CWE: CWE-862
설명: BOLA vulnerability in /api/users/{user-id} component. 
      Attacker can access other users' data by manipulating userId parameter.
"""

metadata = {
    "source_type": "cve",
    "cve_id": "CVE-2024-55072",
    "rule_type": "jwt_ownership",
    "severity": "MEDIUM",
    "domain": "general"
}
```

### 4-3. 비즈니스 로직 패턴 청크 형식

```python
document = """
패턴_ID: BL-003
도메인: ecommerce
리소스_유형: order
엔드포인트_패턴: /api/orders/{orderId}
HTTP_메서드: GET, PUT, DELETE
소유권_유형: direct
소유권_관계: orders.user_id == JWT.sub
DB_검증_쿼리: SELECT user_id FROM orders WHERE id = {orderId}
비교_대상: JWT.sub (user identifier)
복잡도: 2 (DB 1회 조회)
위험도: HIGH
설명: 주문 리소스는 생성한 사용자만 조회/수정/삭제 가능.
      orderId만으로 주문에 접근하면 타인 주문 열람 가능.
탐지_룰_타입: jwt_ownership
관련_CVE: CVE-2024-55072, CVE-2024-55073
"""
```

### 4-4. HackerOne 리포트 청크 형식

```python
document = """
리포트_ID: H1-XXXXX
소스: hackerone
도메인: [회사명 도메인 유형]
취약_엔드포인트: /api/profile/{accountId}
HTTP_메서드: GET
ID_유형: path_parameter
ID_형식: integer_sequential
공격_방식: accountId 값을 순차적으로 변경하여 타 사용자 프로필 조회
노출_데이터: 이름, 이메일, 전화번호 등 PII
소유권_누락: accountId가 JWT의 사용자와 일치하는지 미검증
심각도: medium
탐지_룰_타입: jwt_ownership
"""
```

### 4-5. ChromaDB 컬렉션 구조

```python
# 컬렉션 분리 전략
collections = {
    "bola_cve":      "NVD CVE 데이터 (자동 수집)",
    "bola_patterns": "비즈니스 로직 패턴 (직접 작성)",
    "bola_reports":  "버그바운티 리포트 (수동 정형화)",
    "bola_standards":"CWE / CAPEC / OWASP 표준 (파싱)"
}

# 검색 시 모든 컬렉션에서 병렬 검색 후 합산
```

---

## 5. 비즈니스 로직 패턴 라이브러리

### 5-1. 소유권 관계 5가지 유형

BOLA는 아래 5가지 소유권 구조로 완전히 커버됩니다.

```
유형 1: Direct Ownership (직접 소유)
  조건: resource.owner_id == JWT.sub
  예시: GET /orders/{orderId}
  탐지: jwt_ownership

유형 2: Hierarchical Ownership (계층 소유)
  조건: resource.org_id == user.org_id AND user.role >= required_role
  예시: GET /company/{companyId}/invoices
  탐지: jwt_ownership + role check

유형 3: Delegated Access (위임 접근)
  조건: resource.shared_with[] contains JWT.sub
  예시: GET /documents/{docId}
  탐지: jwt_ownership (shared table 조회)

유형 4: Role-Based (역할 기반)
  조건: JWT.role in [admin, moderator]
  예시: GET /admin/users/{userId}
  탐지: block_path (role 미충족 시)

유형 5: Contextual / Derived (문맥 파생)
  조건: resource.created_by == JWT.sub OR JWT.role == admin
  예시: GET /posts/{postId}/edit
  탐지: jwt_ownership + role fallback
```

### 5-2. 도메인별 리소스 패턴 (직접 작성 필요)

```markdown
## 전자상거래 (ecommerce)
- orders/{orderId}       → Direct, user_id 비교
- cart                   → Direct, session user
- reviews/{reviewId}     → Direct, 작성자만 수정/삭제
- addresses/{addressId}  → Direct, user_id 비교
- wishlists/{wishlistId} → Direct, user_id 비교

## 파일/문서 (file)
- files/{fileId}         → Direct, uploader_id 비교
- shared/{fileId}        → Delegated, shared_with 테이블
- public/{fileId}        → 인증된 사용자 전체 허용
- folders/{folderId}     → Hierarchical, 부모 폴더 소유권 체인

## 결제/금융 (finance)
- payment-methods/{id}   → Direct, 강화 검증 필요
- transactions/{txId}    → Direct, sender 또는 receiver
- bank-accounts/{id}     → Direct, 추가 인증 권장

## SNS/커뮤니티 (sns)
- posts/{postId}         → Contextual, 조회 공개/수정은 작성자만
- messages/{msgId}       → Delegated, sender + receiver
- profiles/{userId}      → Direct, 수정만 제한 (조회 공개)
- follows/{followId}     → Direct, follower_id 비교

## 기업/조직 (enterprise)
- employees/{empId}      → Hierarchical, 같은 org의 manager 이상
- org/{orgId}/settings   → Role-Based, admin만
- teams/{teamId}/members → Hierarchical, 팀 내부
- reports/{reportId}     → Hierarchical, org 내 권한자
```

### 5-3. 파라미터 이름 → 소유권 의미 매핑

LLM이 OAS 파라미터 이름만 보고도 소유권 추론을 할 수 있도록 제공하는 사전입니다.

```python
PARAM_OWNERSHIP_SIGNALS = {
    # 직접 소유권 신호 (HIGH RISK)
    "high_risk": [
        "userId", "user_id", "uid", "accountId", "account_id",
        "memberId", "member_id", "customerId", "customer_id",
        "profileId", "profile_id", "ownerId", "owner_id"
    ],
    # 리소스 식별자 (DB 조회 후 소유권 확인 필요)
    "medium_risk": [
        "orderId", "order_id", "invoiceId", "invoice_id",
        "fileId", "file_id", "documentId", "document_id",
        "postId", "post_id", "messageId", "message_id",
        "paymentId", "payment_id", "transactionId"
    ],
    # 역할/권한 신호
    "role_signal": [
        "admin", "role", "permission", "scope", "privilege"
    ],
    # 조직 계층 신호
    "hierarchy_signal": [
        "orgId", "org_id", "companyId", "company_id",
        "teamId", "team_id", "departmentId", "department_id"
    ]
}
```

---

## 6. 단계별 구축 계획

### Phase 1: 기반 구축 (1주차)

```
목표: ChromaDB에 최소 30개 이상의 고품질 청크 적재

[ ] qwen2.5:7b + nomic-embed-text Ollama 설치 및 테스트
[ ] ChromaDB 컬렉션 4개 생성 (cve / patterns / reports / standards)
[ ] CWE-639, 284, 285, 862, 863 XML 파싱 → 청크 변환 → 적재
[ ] CAPEC-122, 1, 560 XML 파싱 → 청크 변환 → 적재
[ ] NVD 수집 키워드 8개로 확장 → 재수집 (목표: 50개)
[ ] 스프레드시트 스키마 확정 및 기존 13개 CVE 재정형화
```

### Phase 2: 핵심 데이터 구축 (2주차)

```
목표: 비즈니스 로직 패턴 + 버그바운티 리포트 적재

[ ] 비즈니스 로직 패턴 라이브러리 작성 (도메인 5개 × 각 5개 = 25개)
[ ] 파라미터 이름 소유권 매핑 사전 완성
[ ] HackerOne IDOR 공개 리포트 20개 수집 → 스키마 정형화 → 적재
[ ] OWASP WSTG-BUSL-01~09 파싱 → 청크 변환 → 적재
[ ] PortSwigger Business Logic 섹션 텍스트 수집 → 적재
```

### Phase 3: RAG 품질 검증 (3주차)

```
목표: "올바른 쿼리에 올바른 청크가 검색되는지" 검증

[ ] 테스트 쿼리 20개 작성
    예) "GET /orders/{orderId} user ownership path parameter"
[ ] 각 쿼리의 검색 결과 top-5 수동 검토
[ ] 유사도 임계값 조정 (현재 0.8 → 최적값 탐색)
[ ] 관련 없는 청크가 반환되면 해당 청크 수정 또는 분리
```

### Phase 4: 정책 생성 품질 검증 (4주차)

```
목표: LLM + RAG → policy.json 품질 측정

[ ] 테스트용 OAS 파일 5종 준비
    (ecommerce, sns, finance, enterprise, file)
[ ] 각 엔드포인트별 정책 생성 → 사람이 직접 검토
[ ] 신뢰도 70% 미만 항목 분석 → 관련 청크 보강
[ ] 오탐/미탐 케이스 정리 → 추가 데이터 적재
```

---

## 7. 수집 자동화 코드 가이드

### 7-1. CWE/CAPEC XML 파싱

```python
import xml.etree.ElementTree as ET
import chromadb
import ollama

def parse_cwe(xml_path: str) -> list[dict]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"cwe": "http://cwe.mitre.org/cwe-6"}

    chunks = []
    target_cwe_ids = ["639", "284", "285", "862", "863"]

    for weakness in root.findall(".//cwe:Weakness", ns):
        cwe_id = weakness.get("ID")
        if cwe_id not in target_cwe_ids:
            continue

        name = weakness.get("Name", "")
        desc = weakness.find("cwe:Description", ns)
        desc_text = desc.text if desc is not None else ""

        document = f"""
취약점_유형: CWE
CWE_ID: CWE-{cwe_id}
이름: {name}
설명: {desc_text}
BOLA_관련성: 객체 수준 인가 누락으로 인한 무단 접근
"""
        chunks.append({
            "document": document,
            "metadata": {
                "source_type": "cwe",
                "cwe_id": f"CWE-{cwe_id}",
                "name": name
            }
        })
    return chunks
```

### 7-2. ChromaDB 적재 공통 함수

```python
def embed_and_store(collection, chunks: list[dict]):
    for i, chunk in enumerate(chunks):
        embedding = ollama.embeddings(
            model="nomic-embed-text",
            prompt=chunk["document"]
        )["embedding"]

        collection.add(
            ids=[f"{chunk['metadata']['source_type']}-{i}"],
            embeddings=[embedding],
            documents=[chunk["document"]],
            metadatas=[chunk["metadata"]]
        )
    print(f"적재 완료: {len(chunks)}개")
```

### 7-3. RAG 검색 함수

```python
def retrieve_context(
    endpoint_info: dict,
    collections: list,
    top_k: int = 5,
    distance_threshold: float = 0.8
) -> list[str]:

    query = f"""
    {endpoint_info['method']} {endpoint_info['path']}
    {endpoint_info.get('summary', '')}
    {' '.join(endpoint_info.get('path_params', []))}
    authorization ownership object level BOLA IDOR
    """

    embedding = ollama.embeddings(
        model="nomic-embed-text",
        prompt=query
    )["embedding"]

    all_results = []
    for col in collections:
        results = col.query(
            query_embeddings=[embedding],
            n_results=top_k
        )
        for doc, dist in zip(
            results["documents"][0],
            results["distances"][0]
        ):
            if dist < distance_threshold:
                all_results.append((doc, dist))

    # 거리 기준 정렬 후 상위 3개만 반환 (컨텍스트 오염 방지)
    all_results.sort(key=lambda x: x[1])
    return [doc for doc, _ in all_results[:3]]
```

---

## 8. 품질 검증 기준

### 8-1. ChromaDB 검색 품질

| 지표 | 목표값 | 측정 방법 |
|------|--------|-----------|
| Precision@3 | > 80% | 상위 3개 중 관련 청크 비율 |
| 유사도 거리 | < 0.7 | 정답 청크의 평균 거리 |
| 검색 실패율 | < 10% | 관련 청크 0개 반환 비율 |

### 8-2. 정책 생성 품질

| 지표 | 목표값 | 측정 방법 |
|------|--------|-----------|
| rule_type 정확도 | > 85% | 사람 검토 기준 |
| 신뢰도 평균 | > 75% | LLM 자체 신뢰도 |
| JSON 파싱 성공률 | 100% | 형식 오류 없어야 함 |
| PENDING 비율 | < 20% | 신뢰도 70% 미만 항목 |

### 8-3. BOLA 탐지 성능 (최종 목표)

| 지표 | 목표값 |
|------|--------|
| 탐지율 (True Positive) | > 90% |
| 오탐율 (False Positive) | < 5% |
| 미탐율 (False Negative) | < 10% |

---

## 9. 주의사항 및 흔한 실수

### 데이터 수집 시

```
❌ CVE 전체 텍스트를 하나의 청크로 저장
   → 검색 정확도 저하, 관련없는 정보 포함

✅ 엔드포인트 패턴 + 소유권 관계 + 룰 타입을 하나의 청크로 압축


❌ 청크를 한국어와 영어로 혼재
   → nomic-embed-text는 영어에 최적화

✅ 청크 본문은 영어, metadata에 한국어 설명 보조로 추가


❌ top_k를 10 이상으로 설정
   → 관련없는 CVE가 LLM 컨텍스트 오염

✅ top_k=5 검색 후 거리 임계값으로 필터링, 최대 3개만 프롬프트에 주입
```

### LLM 추론 시

```
❌ temperature 높게 설정 (> 0.3)
   → 같은 OAS 입력에 매번 다른 policy 생성

✅ temperature=0.1 고정 (일관성 우선)


❌ JSON 검증 없이 policy.json 저장
   → 런타임에서 파싱 에러로 시스템 다운

✅ json.loads() + 스키마 검증 후 저장, 실패 시 재시도 1회


❌ 비즈니스 로직 패턴 없이 CVE만으로 정책 생성
   → LLM이 도메인 맥락 없이 추론 → 낮은 신뢰도

✅ 비즈니스 로직 패턴 라이브러리를 먼저 완성하고 RAG 시작
```

### 데이터셋 규모에 대한 현실적 기대

```
적은 양의 고품질 데이터 >> 많은 양의 저품질 데이터

목표:
- CVE/CWE/CAPEC:         50~70개 (정형화된 것)
- 비즈니스 로직 패턴:    25~30개 (직접 작성)
- HackerOne 리포트:      20~30개 (수동 정형화)
- OWASP/표준 문서:       15~20개 (섹션 단위)

총합 110~150개 청크로도 충분히 동작 가능
```

---

## 참고 자료 링크

| 자료 | URL |
|------|-----|
| NVD REST API v2.0 | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| CWE XML 다운로드 | https://cwe.mitre.org/data/xml/cwec_latest.xml.zip |
| CAPEC XML 다운로드 | https://capec.mitre.org/data/xml/capec_latest.xml |
| OWASP WSTG (Business Logic) | https://owasp.org/www-project-web-security-testing-guide/ |
| HackerOne Hacktivity | https://hackerone.com/hacktivity |
| PortSwigger BL Vuln | https://portswigger.net/web-security/logic-flaws |
| 팀 스프레드시트 | https://docs.google.com/spreadsheets/d/1R2aoTQrz_ByQ5CABeZLJrWvQZg5kSu-30tVbVWxmSQU |


