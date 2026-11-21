"""
Final Assessment (A.5): Streamlit Chat Frontend for CTI RAG Chatbot & Autonomous Scanner
"""

import os
import requests
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

st.set_page_config(page_title="MongoDB CTI LLM Chatbot", page_icon="🛡️", layout="wide")
st.title("🛡️ MongoDB Threat Intelligence & Autonomous Remediation Chatbot")
st.caption("Synthesizing Exercises 1–18 • Hosted Google Gemini LLM API • MongoDB Vector Search & Session Memory")

with st.sidebar:
    st.header("Target Scope & Filters")
    platform = st.selectbox("Platform", ["All", "Linux", "Windows", "macOS", "Android", "iOS"])
    lifecycle = st.selectbox("Threat Lifecycle", ["All", "Anticipated", "Active", "Evolving", "Resolved"])
    session_id = st.text_input("Session ID", value="cti-analyst-session-01")

    st.divider()
    st.subheader("Background Scanner Service")
    scan_plat = st.selectbox("Scan Platform", ["Linux", "Windows", "macOS", "Android", "iOS"], key="scan_p")
    scan_scope = st.selectbox("Scan Scope", ["system-wide", "project-directory"])
    if st.button("Run Vulnerability Scan", use_container_width=True):
        try:
            r = requests.post(
                f"{BACKEND_URL}/scan",
                json={"platform": scan_plat, "scope": scan_scope},
                timeout=15,
            )
            data = r.json()
            st.success(f"Scan {data['scan_id']} complete ({len(data['findings'])} findings).")
        except Exception as exc:
            st.error(f"Scan failed: {exc}")

if "messages" not in st.session_state:
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": (
                "Welcome to the **MongoDB Threat Intelligence & Remediation Assistant** (Powered by Hosted Gemini API, "
                "NOT Ollama). Select a platform (`Linux`, `Windows`, `macOS`, `Android`, `iOS`) and ask about "
                "**Anticipated**, **Active**, **Evolving**, or **Resolved** threats, or reply `CONFIRM FIX <VULN-ID>` "
                "to remediate findings detected by the background scanner."
            ),
        }
    ]

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("Ask about platform threats, CVEs, IoCs, or type 'CONFIRM FIX VULN-LNX-101'..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        try:
            resp = requests.post(
                f"{BACKEND_URL}/chat",
                json={
                    "message": prompt,
                    "session_id": session_id,
                    "platform": platform,
                    "lifecycle": lifecycle,
                },
                timeout=45,
            )
            answer = resp.json().get("answer", "No response returned.")
        except Exception as exc:
            answer = f"Backend unreachable ({exc}). Ensure FastAPI is running on `{BACKEND_URL}`."
        st.markdown(answer)
        st.session_state.messages.append({"role": "assistant", "content": answer})
