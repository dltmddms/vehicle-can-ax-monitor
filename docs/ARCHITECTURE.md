# Architecture

```text
HCRL / Uploaded CAN Log
        │
        ▼
Windowing
100 / 200 / 300 / 500 messages
        │
        ▼
17 Statistical Features
        │
        ├─ message rate / inter-arrival
        ├─ CAN ID entropy & diversity
        ├─ dominant ID ratio
        └─ payload statistics
        │
        ▼
Random Forest
Normal / DoS / Fuzzy / Gear / RPM
        │
        ├─ Window timeline
        ├─ abnormal interval
        └─ frequent CAN IDs
        │
        ▼
Incident Report
deterministic template / optional local Ollama
        │
        ▼
Human Review & Approval
```

## 역할 분리

- **ML**: 수치적 공격 패턴 판정
- **Rule-based analysis**: Window별 통계와 비정상 구간 구조화
- **Optional GenAI**: 계산된 결과를 엔지니어용 자연어 리포트로 정리
- **Human-in-the-loop**: 실제 ECU/Gateway 조치 전 사람의 검토와 승인

## 중요한 제한

DBC 또는 OEM 사양이 없으므로 CAN ID의 실제 물리 신호 의미를 단정하지 않습니다.
