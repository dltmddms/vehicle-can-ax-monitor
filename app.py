from pathlib import Path
import json
import html
import pandas as pd
import streamlit as st

from src.data_loader import read_hcrl_csv
from src.modeling import load_bundle
from src.inference import analyze_frames, incident_summary
from src.report import template_report, ollama_report
from src.demo import DEMO_SAMPLES, demo_bundle, make_demo_log

ROOT = Path(__file__).parent
MODEL = ROOT / "models/can_ax_model.joblib"
METRICS = ROOT / "models/metrics.json"
REAL_SAMPLES = ROOT / "data/test_samples"
EXPERIMENT = ROOT / "experiments/window_size_results.csv"

st.set_page_config(
    page_title="Vehicle CAN AX Monitor",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {
        max-width: 1440px;
        padding-top: 2.4rem;
        padding-bottom: 3rem;
    }
    [data-testid="stMetric"] {
        border: 1px solid rgba(130,145,160,.18);
        border-radius: 10px;
        padding: .9rem 1rem;
        background: rgba(110,125,140,.035);
    }
    [data-testid="stMetricLabel"] {font-size:.78rem; opacity:.68;}
    [data-testid="stMetricValue"] {font-size:1.62rem; letter-spacing:-.025em;}
    [data-testid="stSidebar"] {border-right:1px solid rgba(130,145,160,.12);}
    .project-title {
        font-size:2.15rem;
        font-weight:700;
        letter-spacing:-.04em;
        line-height:1.15;
        margin-bottom:.3rem;
    }
    .project-subtitle {
        font-size:.98rem;
        opacity:.62;
        margin-bottom:1.5rem;
    }
    .meta-row {
        display:flex;
        gap:.5rem;
        flex-wrap:wrap;
        margin:.15rem 0 1.15rem;
    }
    .meta-chip {
        border:1px solid rgba(130,145,160,.20);
        border-radius:999px;
        padding:.28rem .62rem;
        font-size:.73rem;
        opacity:.72;
    }
    .interpretation {
        border-left:2px solid rgba(130,145,160,.34);
        padding:.05rem 0 .05rem .8rem;
        margin:.9rem 0 1rem;
        font-size:.88rem;
        opacity:.72;
        line-height:1.6;
    }
    .timeline-wrap {margin:.4rem 0 1.1rem;}
    .timeline-track {
        height:34px;
        display:flex;
        overflow:hidden;
        border-radius:7px;
        border:1px solid rgba(130,145,160,.17);
        background:rgba(110,125,140,.035);
    }
    .timeline-normal {background:rgba(150,165,180,.18);}
    .timeline-abnormal {background:rgba(235,88,88,.78);}
    .timeline-labels {
        display:flex;
        justify-content:space-between;
        margin-top:.35rem;
        font-size:.72rem;
        opacity:.48;
    }
    .dist-row {
        display:grid;
        grid-template-columns:120px 1fr 44px;
        gap:.7rem;
        align-items:center;
        margin:.58rem 0;
        font-size:.84rem;
    }
    .dist-track {
        height:10px;
        border-radius:999px;
        overflow:hidden;
        background:rgba(130,145,160,.12);
    }
    .dist-fill {
        height:100%;
        border-radius:999px;
        background:rgba(130,175,220,.78);
    }
    .clean-status {
        border:1px solid rgba(130,145,160,.17);
        border-radius:10px;
        padding:1rem 1.1rem;
        margin:.6rem 0 1rem;
        background:rgba(110,125,140,.025);
    }
    .clean-status b {font-size:.96rem;}
    .clean-status span {display:block; opacity:.60; font-size:.83rem; margin-top:.2rem;}
    .section-note {
        font-size:.81rem;
        opacity:.54;
        line-height:1.55;
        margin:.7rem 0 .2rem;
    }
    div[data-testid="stDownloadButton"] button {
        border-radius:8px;
        min-height:2.6rem;
    }
    #MainMenu {visibility:hidden;}
    footer {visibility:hidden;}
    [data-testid="stToolbar"] {visibility:hidden; height:0;}
    h1 > a, h2 > a, h3 > a, h4 > a, h5 > a, h6 > a {
        display: none !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

SAMPLE_MAP = {
    "Normal": REAL_SAMPLES / "normal_real_sample.csv",
    "DoS": REAL_SAMPLES / "dos_real_sample.csv",
    "Fuzzy": REAL_SAMPLES / "fuzzy_real_sample.csv",
    "Gear spoofing": REAL_SAMPLES / "gear_real_sample.csv",
    "RPM spoofing": REAL_SAMPLES / "rpm_real_sample.csv",
}

PATTERN_NOTE = {
    "normal": "현재 구간에서는 학습된 공격 패턴이 확인되지 않았다.",
    "dos": "특정 CAN ID의 반복 빈도와 메시지 분포가 정상 구간과 다르게 나타났다.",
    "fuzzy": "CAN ID와 payload 분포가 정상 구간보다 넓게 퍼지는 패턴이 나타났다.",
    "gear": "Gear spoofing 학습 패턴과 유사한 구간이 확인됐다. 실제 신호 의미는 차량 사양과 함께 확인해야 한다.",
    "rpm": "RPM spoofing 학습 패턴과 유사한 구간이 확인됐다. 실제 신호 의미는 차량 사양과 함께 확인해야 한다.",
}

VALIDATION_ROWS = [
    {"Sample": "Normal", "Messages": 30000, "Windows": 150, "Abnormal": 0, "Injected": "0.00%", "Prediction": "NORMAL"},
    {"Sample": "DoS", "Messages": 26476, "Windows": 132, "Abnormal": 70, "Injected": "27.21%", "Prediction": "DOS"},
    {"Sample": "Fuzzy", "Messages": 26567, "Windows": 132, "Abnormal": 42, "Injected": "11.65%", "Prediction": "FUZZY"},
    {"Sample": "Gear spoofing", "Messages": 27140, "Windows": 135, "Abnormal": 71, "Injected": "16.38%", "Prediction": "GEAR"},
    {"Sample": "RPM spoofing", "Messages": 26708, "Windows": 133, "Abnormal": 75, "Injected": "17.52%", "Prediction": "RPM"},
]


def render_timeline(windows: pd.DataFrame) -> None:
    if windows.empty:
        return
    total = len(windows)
    segments = []
    for abnormal in windows["is_abnormal"].astype(bool).tolist():
        css = "timeline-abnormal" if abnormal else "timeline-normal"
        segments.append(
            f'<span class="{css}" style="flex:1 1 {100/total:.4f}%"></span>'
        )
    st.markdown(
        '<div class="timeline-wrap">'
        '<div class="timeline-track">' + "".join(segments) + '</div>'
        f'<div class="timeline-labels"><span>Window 1</span><span>Window {total}</span></div>'
        '</div>',
        unsafe_allow_html=True,
    )


def render_distribution(windows: pd.DataFrame) -> None:
    counts = windows["prediction"].value_counts()
    if counts.empty:
        return
    maximum = int(counts.max())
    rows = []
    for label, count in counts.items():
        width = 100 * int(count) / maximum if maximum else 0
        rows.append(
            '<div class="dist-row">'
            f'<span>{html.escape(str(label).upper())}</span>'
            '<div class="dist-track">'
            f'<div class="dist-fill" style="width:{width:.1f}%"></div>'
            '</div>'
            f'<b>{int(count)}</b>'
            '</div>'
        )
    st.markdown("".join(rows), unsafe_allow_html=True)


st.markdown('<div class="project-title">Vehicle CAN AX Monitor</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="project-subtitle">CAN Log Analysis & Incident Reporting</div>',
    unsafe_allow_html=True,
)

real_bundle = None
model_load_error = None
if MODEL.exists():
    try:
        real_bundle = load_bundle(MODEL)
    except Exception as exc:
        model_load_error = str(exc)

with st.sidebar:
    st.markdown("### Analysis")
    analysis_mode = st.radio(
        "Mode",
        ["Synthetic demo", "HCRL model"],
        index=0,
        help="Synthetic demo는 외부 데이터나 학습 모델 없이 화면 흐름을 체험하는 모드다.",
    )

    selected_demo = None
    source = None
    selected_name = None

    if analysis_mode == "Synthetic demo":
        selected_demo = st.selectbox("Demo sample", list(DEMO_SAMPLES.keys()))
        st.caption("합성 CAN 로그 · 규칙 기반 모의 분석")
    else:
        if real_bundle is None:
            st.warning("학습 모델이 없어 HCRL model 모드는 현재 사용할 수 없다.")
        source = st.radio(
            "Input",
            ["Real HCRL sample", "Upload CSV"],
            index=0,
        )
        if source == "Real HCRL sample":
            selected_name = st.selectbox("Sample", list(SAMPLE_MAP.keys()))

    window_size = st.select_slider(
        "Window size",
        options=[100, 200, 300, 500],
        value=200,
        help="한 번에 분석할 CAN message 수",
    )

    with st.expander("Report settings"):
        use_ollama = st.checkbox(
            "Use local language model",
            value=False,
            disabled=analysis_mode == "Synthetic demo",
            help="HCRL model 모드에서만 선택적으로 사용한다.",
        )

    st.caption("Default · 200 messages")

monitor_tab, validation_tab, method_tab = st.tabs(["Monitor", "Validation", "Method"])

with monitor_tab:
    try:
        is_demo = analysis_mode == "Synthetic demo"

        if is_demo:
            sample_key = DEMO_SAMPLES[selected_demo]
            raw = make_demo_log(sample_key, window_size=window_size)
            bundle = demo_bundle()
            mode = "synthetic_demo"
            filename = f"synthetic_{sample_key}.csv"
            st.info(
                "Synthetic Demo · 합성 CAN 로그와 규칙 기반 모의 탐지 결과. "
                "HCRL 학습 모델의 예측 또는 성능 평가 결과가 아니다."
            )
        else:
            if real_bundle is None:
                st.warning(
                    "HCRL 학습 모델을 찾을 수 없다. 실제 분석 모드는 TRAIN_REAL_DATA.bat 실행 후 사용할 수 있다."
                )
                if model_load_error:
                    st.caption(f"Model load error: {model_load_error}")
                st.stop()

            bundle = real_bundle
            mode = bundle.get("dataset_mode", "unknown")

            if source == "Real HCRL sample":
                selected = SAMPLE_MAP[selected_name]
                if not selected.exists():
                    st.info("실제 샘플이 없다. MAKE_REAL_TEST_FILES.bat을 먼저 실행해 주세요.")
                    st.stop()
                raw = read_hcrl_csv(selected)
                filename = selected.name
            else:
                uploaded = st.file_uploader(
                    "CAN log file",
                    type=["csv", "txt"],
                    label_visibility="collapsed",
                )
                if uploaded is None:
                    st.info("CSV 또는 TXT 형식의 CAN 로그를 업로드하면 분석을 시작한다.")
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

        mean_conf = float(windows["confidence"].mean()) if len(windows) else 0.0
        abnormal_count = int(summary["abnormal_windows"])
        total_windows = int(summary["total_windows"])
        injected_pct = (
            float((raw["flag"] == "T").mean() * 100)
            if "flag" in raw.columns else None
        )

        chips = [
            html.escape(filename),
            f"Window {window_size}",
            "Synthetic demo · mock detector" if is_demo else "HCRL-trained model",
        ]

        st.markdown(
            '<div class="meta-row">' +
            "".join(f'<span class="meta-chip">{x}</span>' for x in chips) +
            '</div>',
            unsafe_allow_html=True,
        )

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Messages", f"{len(raw):,}")
        c2.metric("Windows", f"{total_windows:,}")
        c3.metric("Detected pattern", summary["predicted_attack"].upper())
        c4.metric(
            "Mock confidence" if is_demo else "Mean confidence",
            f"{mean_conf * 100:.1f}%",
        )
        c5.metric("Abnormal windows", f"{abnormal_count:,} / {total_windows:,}")

        st.subheader("CAN message sample")
        message_cols = [
            c for c in ["timestamp", "can_id", "dlc", "d0", "d1", "d2", "d3", "flag"]
            if c in raw.columns
        ]
        st.dataframe(
            raw[message_cols].head(16),
            hide_index=True,
            use_container_width=True,
            height=220,
        )
        if is_demo:
            st.caption("flag는 합성 데이터 생성 시 넣은 구간 표시이며 모의 탐지기의 입력으로 사용하지 않는다.")

        st.divider()

        left, right = st.columns([1.12, .88], gap="large")

        with left:
            st.subheader("Detection timeline")
            render_timeline(windows)
            st.markdown(
                f'<div class="interpretation">'
                f'{PATTERN_NOTE.get(summary["predicted_attack"].lower(), "분석 결과를 확인한다.")}'
                f'</div>',
                unsafe_allow_html=True,
            )

        with right:
            st.subheader("Prediction distribution")
            render_distribution(windows)

        if abnormal_count > 0:
            st.subheader("CAN IDs in abnormal windows")
            st.caption(
                "비정상 구간에서 자주 등장한 ID를 빈도순으로 정리했다. "
                "빈도만으로 공격 원인을 단정하지 않는다."
            )
            suspicious = pd.DataFrame(summary["suspicious_ids"])
            if not suspicious.empty:
                st.dataframe(
                    suspicious.rename(columns={"can_id": "CAN ID", "count": "Count"}),
                    hide_index=True,
                    use_container_width=True,
                )
        else:
            st.markdown(
                '<div class="clean-status">'
                '<b>No abnormal windows detected</b>'
                '<span>현재 샘플의 모든 Window가 Normal로 분류됐다.</span>'
                '</div>',
                unsafe_allow_html=True,
            )

        with st.expander("Window-level details"):
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
                height=330,
            )

        st.divider()

        if is_demo:
            report_title = "Demo report"
        else:
            report_title = "Analysis report" if abnormal_count == 0 else "Incident report"
        st.subheader(report_title)

        report = ollama_report(summary, mode) if (use_ollama and not is_demo) else None
        if report is None:
            report = template_report(summary, mode)

        st.markdown(report)

        report_note = (
            '합성 데이터와 규칙 기반 모의 분석 결과이며 실제 HCRL 모델 성능과 무관하다.'
            if is_demo
            else '초기 로그 분석을 위한 참고 결과이며, 실제 조치 전 원본 로그와 차량 사양을 함께 확인한다.'
        )
        st.markdown(
            f'<div class="section-note">{report_note}</div>',
            unsafe_allow_html=True,
        )

        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "Download report",
                report,
                file_name="can_analysis_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with d2:
            st.download_button(
                "Download window results",
                windows.to_csv(index=False).encode("utf-8-sig"),
                file_name="window_predictions.csv",
                mime="text/csv",
                use_container_width=True,
            )

    except Exception as exc:
        st.exception(exc)

with validation_tab:
    st.info(
        "이 탭의 수치는 HCRL 학습 모델 검증 결과다. Synthetic Demo의 모의 탐지 결과와 별도로 본다."
    )
    st.subheader("Real-sample validation")
    st.caption(
        "HCRL 원본에서 추출한 연속 구간으로 다섯 가지 샘플을 확인했다. "
        "Injected 값은 데이터셋의 정답 라벨 비율이며 Monitor의 실시간 입력 정보로 사용하지 않는다."
    )
    st.dataframe(
        pd.DataFrame(VALIDATION_ROWS),
        hide_index=True,
        use_container_width=True,
    )

    st.divider()
    st.subheader("Window-size comparison")

    if EXPERIMENT.exists():
        exp = pd.read_csv(EXPERIMENT)
    else:
        exp = pd.DataFrame([
            {"window_size": 100, "macro_f1": 0.9809, "attack_recall": 0.9980, "sample_type_accuracy": 0.80},
            {"window_size": 200, "macro_f1": 0.9974, "attack_recall": 0.9961, "sample_type_accuracy": 1.00},
            {"window_size": 500, "macro_f1": 1.0000, "attack_recall": 1.0000, "sample_type_accuracy": 1.00},
        ])
    st.dataframe(exp, hide_index=True, use_container_width=True)

    st.markdown(
        '<div class="interpretation">'
        '기본값은 200 messages다. 100은 시간 해상도는 높지만 샘플 유형 판별이 불안정했고, '
        '500은 높은 성능을 보였지만 한 구간이 커져 이상 위치를 세밀하게 보기 어렵다.'
        '</div>',
        unsafe_allow_html=True,
    )

    if METRICS.exists():
        st.divider()
        st.subheader("Model evaluation")
        metrics = json.loads(METRICS.read_text(encoding="utf-8"))
        rf = metrics.get("random_forest", {})
        lr = metrics.get("logistic_regression", {})
        st.dataframe(
            pd.DataFrame([
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
            ]),
            hide_index=True,
            use_container_width=True,
        )

    st.caption(
        "평가 결과는 동일 HCRL 데이터셋 범위의 결과다. 새로운 차량이나 새로운 공격에 대한 일반화 성능으로 해석하지 않는다."
    )

with method_tab:
    st.subheader("System flow")
    st.code(
"""CAN Log
   ↓
Windowing
   ↓
Statistical Features
   ↓
Random Forest
   ↓
Window-level Detection
   ↓
Analysis Summary
   ↓
Report""",
        language="text",
    )

    st.markdown("#### Analysis modes")
    st.write(
        "**Synthetic demo**: 합성 로그와 규칙 기반 모의 탐지기로 UI와 분석 흐름을 체험한다. "
        "**HCRL model**: 학습된 Random Forest 모델과 실제/업로드 로그를 사용한다."
    )

    m1, m2 = st.columns(2, gap="large")
    with m1:
        st.markdown("#### Detection")
        st.write(
            "메시지 발생률, inter-arrival time, CAN ID 분포, dominant ID ratio, "
            "payload 통계 등 Window 단위 특징을 계산해 패턴을 분류한다."
        )
        st.markdown("#### Model")
        st.write(
            "Random Forest를 주 모델로 사용하고 Logistic Regression을 baseline으로 비교했다."
        )
    with m2:
        st.markdown("#### Reporting")
        st.write(
            "분류 결과와 이상 구간 정보를 구조화해 보고서로 정리한다. "
            "선택적으로 로컬 언어 모델을 연결할 수 있지만 탐지 판단에는 사용하지 않는다."
        )
        st.markdown("#### Scope")
        st.write(
            "HCRL 공개 데이터 기반의 소프트웨어 MVP다. "
            "DBC/OEM 사양 없이 CAN ID의 실제 물리 신호 의미를 단정하지 않는다."
        )

st.caption("HCRL Car-Hacking Dataset · Window-based CAN log analysis")
