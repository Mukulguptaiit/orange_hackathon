import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

def update_dashboard(results):
    df = pd.DataFrame(results)
    if not df.empty:
        st.subheader("📊 Threat Statistics")
        threat_counts = df['report'].value_counts()
        st.bar_chart(threat_counts)
        
        st.subheader("📝 Reports")
        for r in results[-5:]:
            st.markdown(f"**Log:** {r['row']}")
            st.markdown(f"**Report:** {r['report']}")
