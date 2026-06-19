"""Streamlit compliance dashboard.

Runs against the FastAPI backend at BACKEND_URL (default: http://localhost:8000).
Start backend first:  uvicorn compliance_scan.api.app:app --reload
Then run UI:          streamlit run ui/app.py
"""
from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

st.set_page_config(
    page_title="Compliance Pre-Scan",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS — explicit dark text on all cards so both light and dark mode work ────
st.markdown("""
<style>
/* Risk badges */
.risk-clean  { background:#1e7e34; color:#ffffff !important; border-radius:6px;
               padding:3px 12px; font-weight:700; display:inline-block; }
.risk-warn   { background:#d39e00; color:#ffffff !important; border-radius:6px;
               padding:3px 12px; font-weight:700; display:inline-block; }
.risk-high   { background:#b21f2d; color:#ffffff !important; border-radius:6px;
               padding:3px 12px; font-weight:700; display:inline-block; }

/* Hit cards — always dark text regardless of Streamlit theme */
.hit-card     { border-left:4px solid #dc3545; background:#2a1215;
                border-radius:4px; padding:9px 14px; margin-bottom:7px;
                font-size:0.88rem; color:#f8d7da !important; }
.hit-card-med { border-left:4px solid #fd7e14; background:#2a1a08;
                border-radius:4px; padding:9px 14px; margin-bottom:7px;
                font-size:0.88rem; color:#ffe8cc !important; }
.hit-card-low { border-left:4px solid #0dcaf0; background:#07282e;
                border-radius:4px; padding:9px 14px; margin-bottom:7px;
                font-size:0.88rem; color:#cff4fc !important; }
.hit-card     b, .hit-card-med b, .hit-card-low b  { font-weight:700; }
.hit-card     code, .hit-card-med code, .hit-card-low code {
    background:rgba(255,255,255,0.12); color:inherit !important;
    padding:1px 5px; border-radius:3px; font-size:0.85em;
}
</style>
""", unsafe_allow_html=True)

# ── Sidebar nav ───────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ Compliance Pre-Scan")
page = st.sidebar.radio(
    "Navigation",
    ["📤 Upload & Scan", "📋 Audit Trail", "📥 Betriebsrat Export"],
    label_visibility="collapsed",
)
st.sidebar.markdown("---")
st.sidebar.caption(f"Backend: `{BACKEND_URL}`")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _risk_badge(risk: str) -> str:
    cls = {
        "CLEAN": "risk-clean",
        "SENSITIVE_PII": "risk-warn",
        "SECRET_FOUND": "risk-high",
        "STRUCTURAL_ANOMALY": "risk-high",
    }.get(risk, "risk-warn")
    return f'<span class="{cls}">{risk}</span>'


def _decision_icon(decision: str) -> str:
    return {"ALLOW": "✅", "ALLOW_WITH_WARNING": "⚠️", "BLOCK": "🚫"}.get(decision, "❓")


def _severity_class(sev: str) -> str:
    return {"HIGH": "hit-card", "MEDIUM": "hit-card-med"}.get(sev, "hit-card-low")


def _render_hits(title: str, hits: list[dict], color: str) -> None:
    if not hits:
        return
    with st.expander(f"{title} ({len(hits)} hit{'s' if len(hits) != 1 else ''})", expanded=True):
        for h in hits:
            css = _severity_class(h.get("severity", "LOW"))
            snippet = h.get("match_snippet", "")
            rule    = h.get("rule_id", "")
            entity  = h.get("entity_type") or rule
            offset  = h.get("offset_char", "")
            st.markdown(
                f'<div class="{css}">'
                f'<b>{entity}</b>'
                f' &nbsp;·&nbsp; severity: {h.get("severity", "?")}'
                f'{" &nbsp;·&nbsp; offset: " + str(offset) if offset != "" else ""}'
                f'{" &nbsp;·&nbsp; <code>" + snippet + "</code>" if snippet else ""}'
                f'</div>',
                unsafe_allow_html=True,
            )


# ─────────────────────────────────────────────────────────────────────────────
# Page 1 — Upload & Scan
# ─────────────────────────────────────────────────────────────────────────────
if page == "📤 Upload & Scan":
    st.title("🛡️ Pre-Upload Compliance Scan")
    st.caption(
        "Files are scanned locally before reaching the LLM. "
        "No content leaves your system during this step."
    )

    col1, col2 = st.columns([2, 1])
    with col1:
        uploaded = st.file_uploader(
            "Select a file to scan",
            type=["pdf", "docx", "doc", "txt", "xlsx", "xlsm", "rtf"],
            help="Supported: PDF, DOCX, TXT, XLSX, RTF",
        )
    with col2:
        user_id    = st.text_input("User ID",    value="demo-user",    help="Passed to audit trail")
        session_id = st.text_input("Session ID", value="demo-session")

    if uploaded and st.button("🔍 Scan file", type="primary"):
        with st.spinner("Scanning…"):
            try:
                resp = requests.post(
                    f"{BACKEND_URL}/scan",
                    data={"user_id": user_id, "session_id": session_id},
                    files={"file": (uploaded.name, uploaded.getvalue(), uploaded.type)},
                    timeout=60,
                )
                resp.raise_for_status()
                result = resp.json()
            except requests.RequestException as exc:
                st.error(f"Backend unreachable: {exc}")
                st.stop()

        decision = result.get("decision", "ALLOW")
        risk     = result.get("risk_level", "CLEAN")
        duration = result.get("scan_duration_ms", 0)

        if decision == "ALLOW":
            st.success(f"✅ **ALLOW** — no sensitive content detected. ({duration} ms)")
        elif decision == "ALLOW_WITH_WARNING":
            st.warning(
                f"⚠️ **WARNING** — sensitive or anomalous content detected. "
                f"Review hits below before proceeding. ({duration} ms)"
            )
        else:
            st.error(f"🚫 **BLOCKED** — upload prevented by compliance policy. ({duration} ms)")

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Risk level",    risk)
        c2.metric("PII hits",      len(result.get("pii_matches", [])))
        c3.metric("Secret hits",   len(result.get("secret_matches", [])))
        c4.metric("Keyword hits",  len(result.get("keyword_matches", [])))
        c5.metric("Anomaly flags", len(result.get("anomaly_matches", [])))

        st.markdown("---")

        with st.expander("🗂 File identity", expanded=False):
            st.json({
                "filename":          result.get("filename"),
                "detected_type":     result.get("file_type_detected"),
                "declared_type":     result.get("file_type_declared"),
                "extension_mismatch": result.get("extension_mismatch"),
            })

        _render_hits("🔑 Secrets",   result.get("secret_matches",  []), "#dc3545")
        _render_hits("👤 PII",        result.get("pii_matches",     []), "#fd7e14")
        _render_hits("🔤 Keywords",   result.get("keyword_matches", []), "#6f42c1")
        _render_hits("⚠️ Anomalies",  result.get("anomaly_matches", []), "#0dcaf0")

        st.session_state["last_result"] = result

    elif "last_result" in st.session_state:
        st.info("Last scan result is still in session. Upload a new file to re-scan.")


# ─────────────────────────────────────────────────────────────────────────────
# Page 2 — Audit Trail
# ─────────────────────────────────────────────────────────────────────────────
elif page == "📋 Audit Trail":
    st.title("📋 Compliance Audit Trail")

    with st.form("filter_form"):
        fc1, fc2, fc3, fc4 = st.columns(4)
        f_user  = fc1.text_input("User ID (optional)")
        f_from  = fc2.date_input("From date", value=None)
        f_to    = fc3.date_input("To date",   value=None)
        f_limit = fc4.number_input("Max rows", min_value=10, max_value=500, value=100)
        submitted = st.form_submit_button("🔎 Load events")

    if submitted or "audit_df" in st.session_state:
        params: dict = {"limit": int(f_limit)}
        if f_user: params["user_id"]   = f_user
        if f_from: params["from_date"] = str(f_from)
        if f_to:   params["to_date"]   = str(f_to)

        if submitted:
            with st.spinner("Loading…"):
                try:
                    r = requests.get(f"{BACKEND_URL}/events", params=params, timeout=15)
                    r.raise_for_status()
                    st.session_state["audit_df"] = r.json()
                except requests.RequestException as exc:
                    st.error(f"Backend unreachable: {exc}")
                    st.stop()

        events = st.session_state.get("audit_df", [])

        if not events:
            st.info("No events found for the selected filters.")
        else:
            df = pd.DataFrame(events)
            display_cols = [
                "timestamp", "user_id", "filename",
                "risk_level", "decision",
                "pii_count", "secret_count", "keyword_count",
                "anomaly_flags", "scan_duration_ms",
            ]
            df = df[[c for c in display_cols if c in df.columns]]

            def _style_risk(val: str) -> str:
                return {
                    "CLEAN":            "background-color:#1e7e34;color:#ffffff",
                    "SENSITIVE_PII":    "background-color:#856404;color:#ffffff",
                    "SECRET_FOUND":     "background-color:#721c24;color:#ffffff",
                    "STRUCTURAL_ANOMALY": "background-color:#721c24;color:#ffffff",
                }.get(val, "")

            subset = ["risk_level"] if "risk_level" in df.columns else []
            styled = df.style.applymap(_style_risk, subset=subset)
            st.markdown(f"**{len(df)} events**")
            st.dataframe(styled, use_container_width=True, height=500)


# ─────────────────────────────────────────────────────────────────────────────
# Page 3 — Betriebsrat Export
# ─────────────────────────────────────────────────────────────────────────────
elif page == "📥 Betriebsrat Export":
    st.title("📥 Betriebsrat / Audit Export")
    st.info(
        "Generates a CSV of compliance events for the works council (Betriebsrat) or "
        "internal audit. No raw file content is included — only metadata and masked snippets."
    )

    with st.form("export_form"):
        ec1, ec2, ec3 = st.columns(3)
        e_user = ec1.text_input("User ID (leave blank for all)")
        e_from = ec2.date_input("From date", value=None)
        e_to   = ec3.date_input("To date",   value=None)
        export_btn = st.form_submit_button("⬇️ Generate CSV", type="primary")

    if export_btn:
        params: dict = {}
        if e_user: params["user_id"]   = e_user
        if e_from: params["from_date"] = str(e_from)
        if e_to:   params["to_date"]   = str(e_to)

        with st.spinner("Generating export…"):
            try:
                r = requests.get(
                    f"{BACKEND_URL}/events/export",
                    params=params,
                    timeout=30,
                )
                r.raise_for_status()
                csv_bytes = r.content
            except requests.RequestException as exc:
                st.error(f"Backend unreachable: {exc}")
                st.stop()

        st.success("Export ready.")
        st.download_button(
            label="💾 Download compliance_export.csv",
            data=csv_bytes,
            file_name="compliance_export.csv",
            mime="text/csv",
        )

        import io
        try:
            preview_df = pd.read_csv(io.BytesIO(csv_bytes), encoding="utf-8-sig", nrows=20)
            st.markdown("**Preview (first 20 rows):**")
            st.dataframe(preview_df, use_container_width=True)
        except Exception:
            pass
