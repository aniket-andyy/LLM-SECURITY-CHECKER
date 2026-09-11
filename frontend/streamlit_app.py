"""Streamlit frontend for the AI security evaluator."""

from __future__ import annotations

import asyncio
import pathlib
import sys

import streamlit as st

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from app.main import run_scan
from app.models.model_router import ModelRouter
from app.privacy.secret_manager import EphemeralSecretManager
from app.target.base import TargetConfig

st.set_page_config(
    page_title="AI Security Evaluator",
    layout="wide",
)

st.title("AI Security Evaluator")
st.caption(
    "Authorized security evaluation only. "
    "No persistent customer data is stored. Secrets remain in memory only."
)

if "secret_manager" not in st.session_state:
    st.session_state.secret_manager = EphemeralSecretManager()

with st.sidebar:
    st.header("Target Configuration")

    provider = st.selectbox(
        "Provider",
        ["mock", "openai", "gemini", "ollama", "custom"],
        index=0,
    )

    model = st.text_input("Model", value="mock-model")
    endpoint = st.text_input("Endpoint", value="")

    api_key = st.text_input(
        "Target API Key",
        type="password",
        autocomplete="off",
        help="Stored only in memory for this session. Never written to disk.",
    )

    st.header("Scan Configuration")

    profile = st.selectbox("Profile", ["quick", "standard", "deep", "custom"], index=0)
    max_attacks = st.slider("Maximum attacks", 1, 50, 5)
    categories = st.multiselect(
        "Attack categories",
        ["prompt_injection", "disclosure", "agency", "adaptive"],
        default=["prompt_injection", "disclosure"],
    )
    adaptive = st.checkbox("Adaptive mode", value=True)
    defense_comparison = st.checkbox("Defense comparison", value=False)

    start = st.button("Start Evaluation", type="primary")

if start:
    secret_manager: EphemeralSecretManager = st.session_state.secret_manager

    handle = secret_manager.register(api_key) if api_key else None

    target_config = TargetConfig(
        provider=provider,
        model=model,
        endpoint=endpoint,
        api_key_handle=handle.handle_id if handle else None,
    )

    scan_config = {
        "profile": profile,
        "max_attacks": max_attacks,
        "categories": categories,
        "adaptive": adaptive,
        "defense_comparison": defense_comparison,
        "stop_on_critical": True,
    }

    with st.status("Running evaluation...", expanded=True) as status:
        try:
            report = asyncio.run(
                run_scan(
                    target_config=target_config,
                    scan_config=scan_config,
                    secret_manager=secret_manager,
                    model_router=ModelRouter(config_path="configs/models.yaml"),
                )
            )
            st.session_state.report = report
            status.update(label="Scan complete", state="complete")
        except Exception as exc:
            st.error(f"Scan failed: {type(exc).__name__}")
            status.update(label="Scan failed", state="error")
        finally:
            secret_manager.clear()

if "report" in st.session_state:
    report = st.session_state.report

    st.subheader("Security Score")
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Score", report.get("security_score"))
    with col2:
        st.metric("Overall Risk", report.get("overall_risk"))
    with col3:
        st.metric("Findings", len(report.get("findings", [])))

    st.subheader("Executive Summary")
    st.write(report.get("executive_summary", ""))

    st.subheader("Attack Statistics")
    st.json(report.get("attack_statistics", {}))

    st.subheader("Findings")
    st.json(report.get("findings", []))

    st.subheader("Full Report")
    st.json(report)
