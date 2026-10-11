from pathlib import Path
import json
import pandas as pd
import streamlit as st

from src.data_loader import read_hcrl_csv
from src.modeling import load_bundle
from src.inference import analyze_frames, incident_summary
from src.report import template_report, ollama_report

ROOT = Path(__file__).parent
MODEL = ROOT / "models/can_ax_model.joblib"
METRICS = ROOT / "models/metrics.json"
DEMO = ROOT / "data/demo/demo_incident.csv"
REAL_SAMPLES = ROOT / "data/test_samples"

st.set_page_config(
    page_title="CAN AX Monitor",
    page_icon="🚗",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- minimal portfolio styling ----------
st.markdown("""
<style>
.block-container {padding-top: 1.8rem; padding-bottom: 3rem;}
[data-testid="stMetric"] {
    background: rgba(127,127,127,0.08);
    border: 1px solid rgba(127,127,127,0.18);
    padding: 12px 14px;
    border-radius: 12px;
}
.small-note {opacity:0.72; font-size:0.92rem;}
.hero-sub {opacity:0.78; margin-top:-0.35rem; margin-bottom:0.8rem;}
</style>
""", unsafe_allow_html=True)

ATTACK_INFO = {
    "normal": {
        "label": "Normal",
        "desc": "해당 분석 구간에서 모델이 공격 패턴을 탐지하지 않았습니다.",
    },
    "dos": {
        "label": "DoS",
        "desc": "특정 CAN ID가 매우 짧은 주기로 반복되어 버스 점유율과 지배 ID 비율이 증가하는 패턴입니다.",
    },
    "fuzzy": {
        "label": "Fuzzy",
        "desc": "다양한 CAN ID와 payload 값이 비정상적으로 주입되어 ID 다양성·entropy·payload 통계가 변하는 패턴입니다.",
    },
    "gear": {
        "label": "Gear Spoofing",
        "desc": "기어 관련 메시지 패턴을 모사한 spoofing 공격 샘플입니다. 실제 신호 의미는 DBC/OEM 사양 없이 단정하지 않습니다.",
    },
    "rpm": {
        "label": "RPM Spoofing",
        "desc": "RPM 관련 메시지 패턴을 모사한 spoofing 공격 샘플입니다. 실제 신호 의미는 DBC/OEM 사양 없이 단정하지 않습니다.",
    },
}

VALIDATION_ROWS = [
    {"Sample": "Normal", "Messages": 30000, "Windows": 150, "Abnormal": 0, "Injected T": "0.00%", "Prediction": "NORMAL"},
    {"Sample": "DoS", "Messages": 26476, "Windows": 132, "Abnormal": 70, "Injected T": "27.21%", "Prediction": "DOS"},
    {"Sample": "Fuzzy", "Messages": 26567, "Windows": 132, "Abnormal": 42, "Injected T": "11.65%", "Prediction": "FUZZY"},
    {"Sample": "Gear spoofing", "Messages": 27140, "Windows": 135, "Abnormal": 71, "Injected T": "16.38%", "Prediction": "GEAR"},
    {"Sample": "RPM spoofing", "Messages": 26708, "Windows": 133, "Abnormal": 75, "Injected T": "17.52%", "Prediction": "RPM"},
]

st.title("🚗 Vehicle CAN Log Analysis & Incident Report Automation")
st.markdown(
    '<div class="hero-sub">실제 차량 CAN 로그를 Window 단위로 분석해 '
    'Normal / DoS / Fuzzy / Gear / RPM 패턴을 분류하고, '
    '엔지니어용 Incident Report까지 자동 생성하는 AX 포트폴리오 프로젝트</div>',
    unsafe_allow_html=True,
)

if not MODEL.exists():
    st.error("모델이 없습니다. TRAIN_REAL_DATA.bat을 먼저 실행하세요.")
    st.stop()

bundle = load_bundle(MODEL)
mode = bundle.get("dataset_mode", "unknown")

sample_map = {
    "Normal": REAL_SAMPLES / "normal_real_sample.csv",
    "DoS": REAL_SAMPLES / "dos_real_sample.csv",
    "Fuzzy": REAL_SAMPLES / "fuzzy_real_sample.csv",
    "Gear spoofing": REAL_SAMPLES / "gear_real_sample.csv",
    "RPM spoofing": REAL_SAMPLES / "rpm_real_sample.csv",
}

with st.sidebar:
    st.header("Analysis Controls")
    source = st.radio(
        "Input source",
        ["Real HCRL sample", "Upload CSV", "Bundled synthetic demo"],
        index=0,
    )

    selected_name = None
    if source == "Real HCRL sample":
        selected_name = st.selectbox("Sample", list(sample_map.keys()))

    window_size = st.select_slider(
        "Window size (messages)",
        options=[100, 200, 300, 500],
        value=200,
    )

    use_ollama = st.checkbox(
        "Use local Ollama for GenAI report",
        value=False,
    )
    st.caption(
        "미연결 시 검증 가능한 템플릿 리포트를 생성합니다. "
        "수치적 공격 판정은 LLM이 아니라 ML 모델이 담당합니다."
    )

analysis_tab, validation_tab, project_tab = st.tabs(
    ["🔎 Analysis", "📊 Validation", "🧩 Project Overview"]
)

# ---------- Analysis ----------
with analysis_tab:
    if mode == "real_hcrl":
        st.success("Model status · Trained with the real HCRL Car-Hacking Dataset")
    else:
        st.warning("Model status · Synthetic demo model. 실제 데이터 재학습이 필요합니다.")

    try:
        if source == "Real HCRL sample":
            selected = sample_map[selected_name]
            if not selected.exists():
                st.warning(
                    "실제 테스트 샘플이 없습니다. "
                    "`MAKE_REAL_TEST_FILES.bat`을 먼저 실행하세요."
                )
                st.stop()
            raw = read_hcrl_csv(selected)
            filename = selected.name

        elif source == "Bundled synthetic demo":
            raw = read_hcrl_csv(DEMO)
            filename = DEMO.name
            if mode == "real_hcrl":
                st.warning(
                    "이 입력은 UI 확인용 합성 데이터입니다. "
                    "실제 모델 성능 평가에는 사용하지 마세요."
                )
        else:
            uploaded = st.file_uploader(
                "Upload an HCRL-format CSV",
                type=["csv", "txt"],
            )
            if uploaded is None:
                st.info("CSV를 업로드하면 분석을 시작합니다.")
                st.stop()
            raw = read_hcrl_csv(uploaded)
            filename = uploaded.name

        windows = analyze_frames(
            raw,
            bundle,
            window_size=window_size,
            stride=window_size,
        )
        summary = incident_summary(raw, windows)

        injected = int((raw["flag"] == "T").sum()) if "flag" in raw.columns else 0
        injected_pct = injected / len(raw) * 100.0 if len(raw) else 0.0
        abnormal_ratio = (
            summary["abnormal_windows"] / summary["total_windows"] * 100.0
            if summary["total_windows"] else 0.0
        )
        mean_conf = (
            float(windows["confidence"].mean())
            if len(windows) and "confidence" in windows.columns
            else 0.0
        )

        st.caption(f"Analyzed file · `{filename}`")

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("CAN Messages", f"{len(raw):,}")
        c2.metric("Windows", f"{len(windows):,}")
        c3.metric("Abnormal Windows", f"{summary['abnormal_windows']:,}", f"{abnormal_ratio:.1f}%")
        c4.metric("Risk", summary["status"])
        c5.metric("Injected T", f"{injected_pct:.2f}%")

        attack_key = summary["predicted_attack"].lower()
        info = ATTACK_INFO.get(attack_key, {
            "label": summary["predicted_attack"].upper(),
            "desc": "분석 결과를 확인하세요.",
        })

        left, right = st.columns([0.95, 1.05])

        with left:
            st.subheader("Detection Result")
            st.metric("Predicted pattern", info["label"])
            st.metric("Mean window confidence", f"{mean_conf*100:.1f}%")
            st.info(info["desc"])

            st.markdown("**Frequent CAN IDs in abnormal windows**")
            st.caption(
                "비정상 구간에서 자주 등장한 ID입니다. "
                "빈도만으로 공격 원인이나 실제 신호 의미를 단정하지 않습니다."
            )
            suspicious = pd.DataFrame(summary["suspicious_ids"])
            if suspicious.empty:
                st.success("비정상 구간이 없어 표시할 CAN ID가 없습니다.")
            else:
                st.dataframe(
                    suspicious.rename(columns={"can_id": "CAN ID", "count": "Count"}),
                    hide_index=True,
                    use_container_width=True,
                )

        with right:
            st.subheader("Window Timeline")
            timeline = pd.DataFrame({
                "Window": range(1, len(windows) + 1),
                "Abnormal": windows["is_abnormal"].astype(int).values,
            }).set_index("Window")
            st.line_chart(timeline, height=245)

            st.markdown("**Prediction distribution**")
            pred_dist = (
                windows["prediction"]
                .value_counts()
                .rename_axis("Prediction")
                .to_frame("Windows")
            )
            st.bar_chart(pred_dist, height=245)

        st.subheader("Window-level Analysis")
        display = windows.copy()
        display.insert(0, "window_no", range(1, len(display) + 1))
        show_cols = [
            c for c in [
                "window_no", "prediction", "confidence", "msg_rate",
                "unique_id_count", "dominant_id_ratio", "payload_entropy",
                "start_time", "end_time"
            ] if c in display.columns
        ]
        st.dataframe(
            display[show_cols],
            hide_index=True,
            use_container_width=True,
            height=315,
        )

        st.subheader("Incident Report")
        report = None
        report_mode = "Template / deterministic"
        if use_ollama:
            report = ollama_report(summary, mode)
            if report is not None:
                report_mode = "Local GenAI · Ollama"
            else:
                st.info("Ollama 호출 실패 → 템플릿 리포트로 자동 전환했습니다.")
        if report is None:
            report = template_report(summary, mode)

        st.caption(f"Report mode · {report_mode}")
        st.markdown(report)

        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "Download incident_report.md",
                report,
                file_name="incident_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with d2:
            st.download_button(
                "Download window_predictions.csv",
                windows.to_csv(index=False).encode("utf-8-sig"),
                file_name="window_predictions.csv",
                mime="text/csv",
                use_container_width=True,
            )

    except Exception as e:
        st.exception(e)

# ---------- Validation ----------
with validation_tab:
    st.subheader("Real-sample validation")
    st.write(
        "실제 HCRL에서 추출한 연속 구간을 앱에 입력해 "
        "Normal 및 4개 공격 유형이 기대한 패턴으로 분류되는지 확인했습니다."
    )
    st.dataframe(
        pd.DataFrame(VALIDATION_ROWS),
        hide_index=True,
        use_container_width=True,
    )

    st.caption(
        "위 표는 샘플 단위 동작 검증입니다. "
        "새로운 차량·ECU·공격에 대한 일반화 성능을 의미하지 않습니다."
    )

    st.subheader("Model evaluation")
    if METRICS.exists():
        metrics = json.loads(METRICS.read_text(encoding="utf-8"))
        rf = metrics.get("random_forest", {})
        lr = metrics.get("logistic_regression", {})

        model_table = pd.DataFrame([
            {
                "Model": "Logistic Regression",
                "Macro F1": lr.get("macro_f1"),
                "Attack Recall": lr.get("attack_recall"),
                "Balanced Accuracy": lr.get("balanced_accuracy"),
            },
            {
                "Model": "Random Forest",
                "Macro F1": rf.get("macro_f1"),
                "Attack Recall": rf.get("attack_recall"),
                "Balanced Accuracy": rf.get("balanced_accuracy"),
            },
        ])
        st.dataframe(model_table, hide_index=True, use_container_width=True)

        fi = metrics.get("feature_importance", [])
        if fi:
            st.markdown("**Top feature importance**")
            st.dataframe(
                pd.DataFrame(fi[:10]),
                hide_index=True,
                use_container_width=True,
            )

    st.warning(
        "현재 학습 성능은 HCRL 데이터셋 내부 temporal hold-out 평가입니다. "
        "같은 차량/데이터셋에 특화된 공격 패턴은 높은 점수가 나오기 쉬우므로 "
        "외부 차량·새 공격에 대한 성능으로 과장하지 않습니다."
    )

# ---------- Project Overview ----------
with project_tab:
    st.subheader("Problem")
    st.write(
        "차량 CAN 로그는 메시지 수가 많아 사람이 직접 이상 구간을 찾고 "
        "초기 분석 보고서를 작성하는 데 시간이 듭니다. "
        "이 프로젝트는 이 반복 업무를 `로그 → 탐지 → 요약 → 리포트` 흐름으로 자동화합니다."
    )

    st.subheader("System Architecture")
    st.code(
"""HCRL / Uploaded CAN Log
        │
        ▼
Windowing (100 / 200 / 300 / 500 messages)
        │
        ▼
17 Statistical Features
- message rate
- inter-arrival statistics
- CAN ID entropy / diversity
- dominant ID ratio
- payload statistics
        │
        ▼
Random Forest
Normal / DoS / Fuzzy / Gear / RPM
        │
        ├── Window timeline / suspicious interval
        └── Frequent CAN IDs
                │
                ▼
Incident Report
(template by default / optional local Ollama)
                │
                ▼
Human review & approval""",
        language="text",
    )

    st.subheader("AI / AX role separation")
    st.markdown("""
- **ML**: 정량적인 공격 패턴 분류를 담당합니다.
- **Rule-based analysis**: Window 통계와 관련 CAN ID를 구조화합니다.
- **Optional GenAI**: 이미 계산된 분석 결과를 엔지니어가 읽기 쉬운 보고서로 변환합니다.
- **Human-in-the-loop**: 실제 차량 조치 전에는 담당자의 검토와 승인을 전제로 합니다.
""")

    st.subheader("Portfolio scope")
    st.write(
        "2~3일 내 구현 가능한 학부생 수준의 MVP로 범위를 제한했습니다. "
        "새로운 IDS 알고리즘을 제안하는 연구가 아니라, "
        "공개 실차 데이터를 이용해 자동차 로그 분석 업무를 AX workflow로 구현하고 "
        "그 한계를 검증하는 데 목적이 있습니다."
    )

    st.subheader("Limitations")
    st.markdown("""
1. HCRL 한 데이터셋의 패턴에 의존합니다.
2. DBC/OEM 사양이 없어 CAN ID의 실제 물리 신호 의미를 확정하지 않습니다.
3. 실제 차량 실시간 통신 환경과 배포 성능은 검증하지 않았습니다.
4. 모델 점수가 매우 높더라도 새로운 차량/공격에 동일하게 일반화된다고 주장하지 않습니다.
""")

st.divider()
st.caption(
    "CAN AX Portfolio MVP · HCRL real CAN data · "
    "Window-based ML detection · Incident reporting · Human-in-the-loop"
)
