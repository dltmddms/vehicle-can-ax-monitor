from __future__ import annotations

import json
import os

import requests


def build_report_context(summary: dict, model_mode: str) -> dict:
    attack = summary.get("predicted_attack", "normal")

    checks = {
        "normal": [],
        "dos": [
            "메시지 발생 주기와 전송률을 정상 구간과 비교",
            "반복 빈도가 높은 CAN ID의 전송 패턴 확인",
            "Gateway 또는 ECU 단에서 비정상 반복 전송 여부 확인",
        ],
        "fuzzy": [
            "CAN ID 다양성과 payload 분포를 정상 구간과 비교",
            "비정상 ID와 payload 패턴을 시간 순서로 확인",
            "Gateway filtering 및 입력 검증 정책 확인",
        ],
        "gear": [
            "비정상 구간의 주요 CAN ID와 payload 변화 확인",
            "반복 주입과 메시지 주기 변화 여부 확인",
            "DBC 또는 차량 사양과 대조해 실제 신호 의미 확인",
        ],
        "rpm": [
            "비정상 구간의 주요 CAN ID와 payload 변화 확인",
            "반복 주입과 메시지 주기 변화 여부 확인",
            "DBC 또는 차량 사양과 대조해 실제 신호 의미 확인",
        ],
    }

    if model_mode == "synthetic_demo":
        descriptions = {
            "normal": "합성 정상 로그에서 모의 탐지 규칙에 해당하는 이상 패턴이 확인되지 않았다.",
            "dos": "합성 로그에서 동일 CAN ID가 높은 비율로 반복되는 DoS 유사 패턴이 확인됐다.",
            "fuzzy": "합성 로그에서 CAN ID 분포가 넓게 퍼지는 Fuzzy 유사 패턴이 확인됐다.",
        }
    else:
        descriptions = {
            "normal": "현재 분석 구간에서는 학습된 공격 패턴이 확인되지 않았다.",
            "dos": "특정 CAN ID의 반복 빈도와 메시지 분포가 정상 구간과 다르게 나타났다.",
            "fuzzy": "CAN ID 및 payload 분포가 정상 구간보다 넓게 퍼지는 패턴이 나타났다.",
            "gear": "Gear spoofing 학습 패턴과 유사한 구간이 확인됐다.",
            "rpm": "RPM spoofing 학습 패턴과 유사한 구간이 확인됐다.",
        }

    return {
        **summary,
        "model_mode": model_mode,
        "pattern_description": descriptions.get(
            attack, "학습된 패턴과 유사한 구간이 확인됐다."
        ),
        "recommended_checks": checks.get(attack, []),
    }


def template_report(summary: dict, model_mode: str) -> str:
    ctx = build_report_context(summary, model_mode)

    ids = ", ".join(
        f"0x{x['can_id']} ({x['count']})"
        for x in ctx.get("suspicious_ids", [])
    ) or "없음"


    base = f"""### Summary

| Item | Result |
|---|---|
| Status | **{ctx['status']}** |
| Detected pattern | **{ctx['predicted_attack'].upper()}** |
| Abnormal windows | {ctx['abnormal_windows']} / {ctx['total_windows']} |
| Frequent CAN IDs | {ids} |

### Interpretation

{ctx['pattern_description']}
"""

    if not ctx["recommended_checks"]:
        return base

    checks = "\n".join(
        f"{i + 1}. {item}"
        for i, item in enumerate(ctx["recommended_checks"])
    )
    return base + f"""
### Recommended checks

{checks}
"""


def ollama_report(summary: dict, model_mode: str) -> str | None:
    url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    ctx = build_report_context(summary, model_mode)

    prompt = f"""다음 CAN 로그 분석 결과를 간결한 기술 리포트로 정리한다.

규칙:
- 입력에 없는 사실을 추가하지 않는다.
- CAN ID의 실제 물리 신호 의미를 추측하지 않는다.
- 과장된 표현을 사용하지 않는다.
- 정상 결과라면 불필요한 점검 항목을 만들지 않는다.
- 섹션은 Summary, Interpretation, 필요한 경우 Recommended checks만 사용한다.

DATA:
{json.dumps(ctx, ensure_ascii=False, indent=2)}
"""

    try:
        response = requests.post(
            url,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=30,
        )
        response.raise_for_status()
        return response.json().get("response")
    except Exception:
        return None
