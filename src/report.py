from __future__ import annotations

import json
import os
from datetime import datetime
import requests


def build_engineering_context(summary: dict, model_mode: str) -> dict:
    attack = summary.get("predicted_attack", "normal")
    guidance = {
        "dos": [
            "메시지 발생 주기와 bus load 급증 여부를 정상 구간과 비교",
            "지배적으로 반복되는 CAN ID가 있는지 확인",
            "Gateway/ECU에서 비정상 flooding의 발신 경로를 점검",
        ],
        "fuzzy": [
            "짧은 시간 내 CAN ID 다양성과 payload entropy가 급증했는지 확인",
            "정상 구간과 비교해 비정상 ID 및 payload 패턴을 목록화",
            "Gateway filtering 및 입력 검증 정책을 점검",
        ],
        "gear": [
            "비정상 구간의 주요 CAN ID 및 payload 변화 패턴을 정상 구간과 비교",
            "반복 주입 및 주기 변화 여부를 확인",
            "실제 신호 의미는 DBC/OEM 사양으로 교차검증",
        ],
        "rpm": [
            "비정상 구간의 주요 CAN ID 및 payload 변화 패턴을 정상 구간과 비교",
            "반복 주입 및 주기 변화 여부를 확인",
            "실제 신호 의미는 DBC/OEM 사양으로 교차검증",
        ],
        "normal": [
            "현재 분석 구간에서 공격 패턴이 탐지되지 않았습니다.",
            "필요 시 다른 Window size와 더 긴 로그 구간으로 재검증",
        ],
    }
    return {
        **summary,
        "model_mode": model_mode,
        "recommended_checks": guidance.get(attack, guidance["normal"]),
    }


def template_report(summary: dict, model_mode: str) -> str:
    ctx = build_engineering_context(summary, model_mode)
    ids = ", ".join(
        f"0x{x['can_id']} ({x['count']})" for x in ctx["suspicious_ids"]
    ) or "없음"
    checks = "\n".join(
        f"{i+1}. {x}" for i, x in enumerate(ctx["recommended_checks"])
    )

    if ctx["status"] == "NORMAL":
        interval = "비정상 구간 없음"
    else:
        interval = f"{ctx['start_time']} ~ {ctx['end_time']}"

    note = (
        "\n> ⚠️ 현재 모델은 합성 DEMO 모델입니다. 실제 HCRL 데이터로 재학습이 필요합니다.\n"
        if model_mode == "demo" else ""
    )

    return f"""# CAN Incident Report

## 1. Summary
- 생성 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- 상태: **{ctx['status']}**
- 추정 패턴: **{ctx['predicted_attack'].upper()}**
- 공격 Window 평균 신뢰도: **{ctx['confidence']*100:.1f}%**
- 이상 Window: **{ctx['abnormal_windows']} / {ctx['total_windows']}**
- 비정상 구간 내 고빈도 CAN ID: {ids}
- 분석 구간: {interval}
{note}
## 2. Interpretation
본 시스템은 고정 길이 CAN message window에서 전송률, inter-arrival time,
CAN ID 다양성/entropy, 지배 ID 비율, payload 통계 등을 추출한 뒤
Random Forest로 Normal / DoS / Fuzzy / Gear / RPM 패턴을 분류합니다.

고빈도 CAN ID는 추가 점검 후보일 뿐 공격 원인이나 실제 물리 신호 의미를 뜻하지 않습니다.
DBC 또는 OEM 사양이 없는 상태에서는 CAN ID의 실제 의미를 확정하지 않습니다.

## 3. Recommended Checks
{checks}

## 4. Human-in-the-loop
이 보고서는 자동 분석 초안입니다.
실제 차량·시험 환경에서 조치를 수행하기 전에 담당 엔지니어가 원본 로그와 차량 사양을 검토하고 승인해야 합니다.
"""


def ollama_report(summary: dict, model_mode: str) -> str | None:
    url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    ctx = build_engineering_context(summary, model_mode)

    prompt = f"""당신은 자동차 CAN 테스트 로그 분석 보조 AI입니다.
아래 구조화된 분석 결과만 근거로 한국어 Incident Report를 작성하세요.
CAN ID의 실제 물리적 의미를 추측하지 마세요.
수치적 공격 판정은 이미 ML 모델이 완료했으며, 당신의 역할은 결과를 정리하는 것입니다.
실제 차량 조치 전 엔지니어 검토가 필요하다고 명시하세요.

필수 구조:
1. Executive Summary
2. Observed Evidence
3. Possible Causes (추정이라고 명시)
4. Recommended Checks
5. Human Approval

DATA:
{json.dumps(ctx, ensure_ascii=False, indent=2)}
"""
    try:
        r = requests.post(
            url,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("response")
    except Exception:
        return None
