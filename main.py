import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from pipeline.threat_pipeline import ThreatPipeline
from reporting.dashboard import update_dashboard, create_summary_report

# Page configuration
st.set_page_config(
    page_title="🛡️ CyberWatchdog",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if "pipeline" not in st.session_state:
    st.session_state.pipeline = ThreatPipeline("data/network_traffic_logs.csv")
    st.session_state.results = []
    st.session_state.current_row = 0

# Sidebar
with st.sidebar:
    st.title("🛡️ CyberWatchdog")
    st.markdown("**AI-Powered Threat Detection**")
    
    st.divider()
    
    # Controls
    st.subheader("Controls")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("➡️ Next Row", type="primary"):
            row, result = st.session_state.pipeline.next_row()
            if row:
                st.session_state.results.append(result)
                st.session_state.current_row += 1
                st.rerun()
            else:
                st.success(result)
    
    with col2:
        if st.button("🔄 Reset"):
            st.session_state.pipeline = ThreatPipeline("data/network_traffic_logs.csv")
            st.session_state.results = []
            st.session_state.current_row = 0
            st.rerun()
    
    # Statistics
    st.divider()
    st.subheader("Statistics")
    
    total_rows = len(st.session_state.pipeline.df)
    processed = st.session_state.current_row
    
    st.metric("Total Rows", total_rows)
    st.metric("Processed", processed)
    st.metric("Remaining", total_rows - processed)
    
    if total_rows > 0:
        progress = processed / total_rows
        st.progress(progress, text=f"{progress:.1%} Complete")
    
    # Cost-effective mode
    st.divider()
    st.subheader("Cost Control")
    
    cost_mode = st.selectbox(
        "AI Mode",
        ["🟢 Efficient (Low Cost)", "🟡 Balanced", "🔴 Detailed (High Cost)"],
        index=0
    )
    
    # Batch processing
    st.divider()
    st.subheader("Batch Processing")
    
    batch_size = st.slider("Batch Size", 1, 10, 5)
    if st.button(f"🚀 Process {batch_size} Rows"):
        for _ in range(batch_size):
            row, result = st.session_state.pipeline.next_row()
            if row:
                st.session_state.results.append(result)
                st.session_state.current_row += 1
            else:
                st.success("All data processed!")
                break
        st.rerun()

# Main content
st.title("🛡️ Cybersecurity Watchdog")
st.markdown("**Multi-Agent AI-Enabled Threat Detection & Response System**")

# Status bar with visual indicators
if st.session_state.results:
    latest_result = st.session_state.results[-1]
    latest_validation = latest_result.get("validation", {})
    threat_type = latest_validation.get("threat_type", "Unknown")
    severity = latest_validation.get("severity", "Unknown")
    confidence = latest_validation.get("confidence", 0)
    
    # Color coding for severity
    severity_colors = {
        "Low": "🟢",
        "Medium": "🟡", 
        "High": "🟠",
        "Critical": "🔴",
        "Unknown": "⚪"
    }
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Latest Threat", f"{threat_type}")
    with col2:
        st.metric("Severity", f"{severity_colors.get(severity, '⚪')} {severity}")
    with col3:
        # Confidence gauge
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = confidence,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Confidence"},
            delta = {'reference': 0.8},
            gauge = {
                'axis': {'range': [None, 1]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 0.5], 'color': "lightgray"},
                    {'range': [0.5, 0.8], 'color': "yellow"},
                    {'range': [0.8, 1], 'color': "green"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 0.9
                }
            }
        ))
        fig.update_layout(height=200)
        st.plotly_chart(fig, use_container_width=True)
    with col4:
        st.metric("Total Analyzed", len(st.session_state.results))

# Visual Analysis Section
if st.session_state.results:
    latest_result = st.session_state.results[-1]
    
    # Create tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Analysis", "📊 Dashboard", "🛡️ Response", "📋 Report"])
    
    with tab1:
        st.subheader("🔍 Latest Analysis")
        
        # Visual representation of the log entry
        row = latest_result.get("row", {})
        
        # Network flow diagram
        fig = go.Figure()
        
        # Source node
        fig.add_trace(go.Scatter(
            x=[0], y=[0.5],
            mode='markers+text',
            marker=dict(size=30, color='red'),
            text=[row.get("Source IP", "Unknown")],
            textposition="bottom center",
            name="Source"
        ))
        
        # Destination node
        fig.add_trace(go.Scatter(
            x=[1], y=[0.5],
            mode='markers+text',
            marker=dict(size=30, color='blue'),
            text=[row.get("Destination IP", "Unknown")],
            textposition="bottom center",
            name="Destination"
        ))
        
        # Connection line
        fig.add_trace(go.Scatter(
            x=[0.1, 0.9], y=[0.5, 0.5],
            mode='lines',
            line=dict(color='gray', width=3),
            showlegend=False
        ))
        
        # Protocol label
        fig.add_annotation(
            x=0.5, y=0.6,
            text=f"Protocol: {row.get('Protocol', 'Unknown')}",
            showarrow=False,
            font=dict(size=14)
        )
        
        fig.update_layout(
            title="Network Flow",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=300,
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Key metrics in columns
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Packet Size", f"{row.get('Packet Size (bytes)', 0):.0f} bytes")
        with col2:
            st.metric("Duration", f"{row.get('Flow Duration (s)', 0):.2f}s")
        with col3:
            st.metric("Threat", "🔴 Yes" if row.get("Threat") == "Yes" else "🟢 No")
        
        # AI Classification Results
        st.subheader("🤖 AI Analysis Results")
        
        classification = latest_result.get("classification", {})
        if classification:
            # Visual classification display
            col1, col2 = st.columns(2)
            
            with col1:
                # Threat type indicator
                threat_type = classification.get("threat_type", "Unknown")
                threat_icons = {
                    "Malware": "🦠",
                    "Phishing": "🎣",
                    "DDoS": "🌐",
                    "Data Breach": "📂",
                    "Port Scan": "🔍",
                    "Brute Force": "💪",
                    "Privilege Escalation": "⬆️",
                    "Benign": "✅"
                }
                
                st.markdown(f"""
                <div style='text-align: center; padding: 20px; border: 2px solid #ddd; border-radius: 10px;'>
                    <h2>{threat_icons.get(threat_type, '❓')}</h2>
                    <h3>{threat_type}</h3>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                # Severity indicator
                severity = classification.get("severity", "Unknown")
                severity_colors = {
                    "Low": "#28a745",
                    "Medium": "#ffc107",
                    "High": "#fd7e14",
                    "Critical": "#dc3545"
                }
                
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(severity, 0),
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Severity Level"},
                    gauge = {
                        'axis': {'range': [None, 4]},
                        'bar': {'color': severity_colors.get(severity, "gray")},
                        'steps': [
                            {'range': [0, 1], 'color': "#28a745"},
                            {'range': [1, 2], 'color': "#ffc107"},
                            {'range': [2, 3], 'color': "#fd7e14"},
                            {'range': [3, 4], 'color': "#dc3545"}
                        ]
                    }
                ))
                fig.update_layout(height=200)
                st.plotly_chart(fig, use_container_width=True)
            
            # IOCs display
            iocs = classification.get("iocs", [])
            if iocs:
                st.subheader("🔍 Indicators of Compromise (IOCs)")
                for ioc in iocs:
                    st.markdown(f"- `{ioc}`")
        else:
            st.warning("⚠️ No AI classification available")
    
    with tab2:
        update_dashboard(st.session_state.results, st.session_state.pipeline)
    
    with tab3:
        st.subheader("🛡️ Response Plan")
        response = latest_result.get("response", "No response generated.")
        if response and response != "No response generated.":
            st.markdown(response)
        else:
            st.warning("No response plan generated")
    
    with tab4:
        st.subheader("📋 Final Report")
        report = latest_result.get("report", "No report generated.")
        if report and report != "No report generated.":
            st.markdown(report)
        else:
            st.warning("No final report generated")

else:
    st.info("👆 Click 'Next Row' in the sidebar to start analyzing network traffic logs.")

# Footer
st.divider()
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🛡️ CyberWatchdog - AI-Powered Cybersecurity Analysis</p>
    <p>Visual • Efficient • Intelligent</p>
</div>
""", unsafe_allow_html=True)
