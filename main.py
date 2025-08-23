import streamlit as st
from pipeline.threat_pipeline import ThreatPipeline
from reporting.dashboard import update_dashboard

pipeline = ThreatPipeline("data/network_traffic_logs.csv")

st.title("🛡️ Cybersecurity Watchdog (Multi-Agent AI)")

if "results" not in st.session_state:
    st.session_state.results = []

if st.button("➡️ Next Row"):
    row, report = pipeline.next_row()
    if row:
        st.write("### Current Log Entry:", row)
        st.write("### AI Analysis:", report)
        st.session_state.results.append({"row": row, "report": report})
        update_dashboard(st.session_state.results)
    else:
        st.success(report)
