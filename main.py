import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
from datetime import datetime, timedelta
from pipeline.network_pipeline import NetworkPipeline
from pipeline.system_pipeline import SystemPipeline
from pipeline.automated_logger import AutomatedLogger

# Page configuration
st.set_page_config(
    page_title="🛡️ CyberWatchdog",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if "network_pipeline" not in st.session_state:
    st.session_state.network_pipeline = NetworkPipeline("data/network_traffic_logs.csv")
    st.session_state.network_results = []

if "system_pipeline" not in st.session_state:
    st.session_state.system_pipeline = SystemPipeline("data/system_event_logs.csv")
    st.session_state.system_results = []

if "automated_logger" not in st.session_state:
    st.session_state.automated_logger = AutomatedLogger()
    # Set up callback to update session state when new threats are found
    def update_automated_results(new_results):
        if "automated_results" not in st.session_state:
            st.session_state.automated_results = []
        st.session_state.automated_results.extend(new_results)
        st.session_state.last_automated_run = datetime.now()
    
    st.session_state.automated_logger.set_update_callback(update_automated_results)

if "automated_results" not in st.session_state:
    st.session_state.automated_results = []

if "last_automated_run" not in st.session_state:
    st.session_state.last_automated_run = None

if "view_mode" not in st.session_state:
    st.session_state.view_mode = "automated"  # "automated", "manual", "dashboard"

# Sidebar
with st.sidebar:
    st.title("🛡️ CyberWatchdog")
    st.markdown("**Dual-System AI Security**")
    
    st.divider()
    
    # View Mode Selection
    st.subheader("View Mode")
    view_mode = st.selectbox(
        "Select Mode",
        ["🤖 Automated (5-min intervals)", "🎮 Manual Control", "📊 Dashboard Only"],
        index=0
    )
    
    if view_mode == "🤖 Automated (5-min intervals)":
        st.session_state.view_mode = "automated"
    elif view_mode == "🎮 Manual Control":
        st.session_state.view_mode = "manual"
    else:
        st.session_state.view_mode = "dashboard"
    
    st.divider()
    
    # Controls based on view mode
    if st.session_state.view_mode == "automated":
        st.subheader("🤖 Automated Mode")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🚀 Start Auto", type="primary"):
                st.session_state.automated_logger.start_automation()
                st.success("Automated logging started!")
        
        with col2:
            if st.button("⏹️ Stop Auto"):
                st.session_state.automated_logger.stop_automation()
                st.success("Automated logging stopped!")
        
        if st.button("🔍 Manual Scan Now"):
            threats_found = st.session_state.automated_logger.manual_scan()
            st.success(f"Manual scan complete! Found {threats_found} threats.")
        
        # Automation Status
        status = st.session_state.automated_logger.get_status()
        st.metric("Auto Status", "🟢 Running" if status["is_running"] else "🔴 Stopped")
        st.metric("Total Threats", status["total_threats_found"])
        
        if status["last_network_check"]:
            st.metric("Last Check", status["last_network_check"].strftime("%H:%M:%S"))
    
    elif st.session_state.view_mode == "manual":
        st.subheader("🎮 Manual Control")
        
        # Network Pipeline Controls
        st.write("**Network Pipeline**")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🌐 Process Network"):
                results = st.session_state.network_pipeline.process_batch(batch_size=5)
                st.session_state.network_results.extend(results)
                st.success(f"Processed {len(results)} network logs")
        
        with col2:
            if st.button("🔄 Reset Network"):
                st.session_state.network_pipeline = NetworkPipeline("data/network_traffic_logs.csv")
                st.session_state.network_results = []
                st.success("Network pipeline reset!")
        
        # System Pipeline Controls
        st.write("**System Pipeline**")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("💻 Process System"):
                results = st.session_state.system_pipeline.process_batch(batch_size=5)
                st.session_state.system_results.extend(results)
                st.success(f"Processed {len(results)} system logs")
        
        with col2:
            if st.button("🔄 Reset System"):
                st.session_state.system_pipeline = SystemPipeline("data/system_event_logs.csv")
                st.session_state.system_results = []
                st.success("System pipeline reset!")
    
    # Statistics
    st.divider()
    st.subheader("Statistics")
    
    if st.session_state.view_mode == "automated":
        status = st.session_state.automated_logger.get_status()
        st.metric("Network Processed", status["network_stats"]["processed"])
        st.metric("System Processed", status["system_stats"]["processed"])
        st.metric("Threats Found", status["total_threats_found"])
    else:
        network_stats = st.session_state.network_pipeline.get_stats()
        system_stats = st.session_state.system_pipeline.get_stats()
        st.metric("Network Threats", len(st.session_state.network_results))
        st.metric("System Threats", len(st.session_state.system_results))
        st.metric("Total Threats", len(st.session_state.network_results) + len(st.session_state.system_results))
    
    # Reset All
    st.divider()
    if st.button("🔄 Reset All Pipelines"):
        st.session_state.network_pipeline = NetworkPipeline("data/network_traffic_logs.csv")
        st.session_state.system_pipeline = SystemPipeline("data/system_event_logs.csv")
        st.session_state.network_results = []
        st.session_state.system_results = []
        st.session_state.automated_logger.reset_pipelines()
        st.success("All pipelines reset!")

# Main content
st.title("🛡️ Cybersecurity Watchdog")
st.markdown("**Dual-System AI-Enabled Threat Detection & Response System**")

# Status Overview
if st.session_state.view_mode == "automated":
    # Automated Mode Status
    status = st.session_state.automated_logger.get_status()
    recent_threats = st.session_state.automated_results  # Use session state directly
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🤖 Auto Status", "🟢 Running" if status["is_running"] else "🔴 Stopped")
    with col2:
        st.metric("🔍 Total Threats", status["total_threats_found"])
    with col3:
        st.metric("📊 Last 24h", len(recent_threats))
    with col4:
        if status["last_network_check"]:
            st.metric("⏰ Last Check", status["last_network_check"].strftime("%H:%M"))
        else:
            st.metric("⏰ Last Check", "Never")
    
    # Recent Threats Display
    if recent_threats:
        st.subheader("🚨 Recent Threats (Last 24 Hours)")
        
        # Group threats by type
        threat_summary = {}
        for threat in recent_threats:
            threat_type = threat.get("validation", {}).get("threat_type", "Unknown")
            log_type = threat.get("type", "Unknown")
            key = f"{log_type.upper()}: {threat_type}"
            if key not in threat_summary:
                threat_summary[key] = 0
            threat_summary[key] += 1
        
        # Display threat summary
        for threat_desc, count in threat_summary.items():
            st.write(f"• **{threat_desc}**: {count} occurrences")
        
        # Show detailed results
        with st.expander("📋 View Detailed Threat Reports"):
            for i, threat in enumerate(recent_threats[-5:]):  # Show last 5
                with st.container():
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**{threat.get('validation', {}).get('threat_type', 'Unknown')}** - {threat.get('type', 'Unknown').title()}")
                        st.write(f"Severity: {threat.get('validation', {}).get('severity', 'Unknown')}")
                        st.write(f"Confidence: {threat.get('validation', {}).get('confidence', 0):.1%}")
                    with col2:
                        if st.button(f"View Report {i+1}", key=f"report_{i}"):
                            st.session_state.selected_threat = threat
                            st.rerun()
    
    else:
        st.info("✅ No threats detected in the last 24 hours. System is secure!")
    
    # Start automation if not running
    if not status["is_running"]:
        st.warning("⚠️ Automated logging is not running. Click 'Start Auto' in the sidebar to begin monitoring.")
    
else:
    # Manual Mode Status
    network_stats = st.session_state.network_pipeline.get_stats()
    system_stats = st.session_state.system_pipeline.get_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🌐 Network Threats", len(st.session_state.network_results))
    with col2:
        st.metric("💻 System Threats", len(st.session_state.system_results))
    with col3:
        st.metric("📊 Total Processed", network_stats["processed"] + system_stats["processed"])
    with col4:
        st.metric("⏳ Remaining", network_stats["remaining"] + system_stats["remaining"])
    
    # Manual Results Display
    if st.session_state.network_results or st.session_state.system_results:
        st.subheader("🔍 Manual Analysis Results")
        
        # Network Results
        if st.session_state.network_results:
            st.write("**🌐 Network Threats**")
            for i, result in enumerate(st.session_state.network_results[-3:]):  # Show last 3
                with st.container():
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**{result.get('validation', {}).get('threat_type', 'Unknown')}**")
                        st.write(f"Source: {result.get('row', {}).get('Source IP', 'Unknown')} → {result.get('row', {}).get('Destination IP', 'Unknown')}")
                        st.write(f"Protocol: {result.get('row', {}).get('Protocol', 'Unknown')}")
                    with col2:
                        if st.button(f"View Network {i+1}", key=f"network_{i}"):
                            st.session_state.selected_threat = result
                            st.rerun()
        
        # System Results
        if st.session_state.system_results:
            st.write("**💻 System Threats**")
            for i, result in enumerate(st.session_state.system_results[-3:]):  # Show last 3
                with st.container():
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.write(f"**{result.get('validation', {}).get('threat_type', 'Unknown')}**")
                        st.write(f"User: {result.get('row', {}).get('User', 'Unknown')}")
                        st.write(f"Event: {result.get('row', {}).get('Event Type', 'Unknown')}")
                    with col2:
                        if st.button(f"View System {i+1}", key=f"system_{i}"):
                            st.session_state.selected_threat = result
                            st.rerun()
    else:
        st.info("👆 Use the manual controls in the sidebar to process logs and analyze threats.")

# Display Selected Threat Report
if "selected_threat" in st.session_state:
    st.divider()
    st.subheader("📋 Detailed Threat Report")
    
    threat = st.session_state.selected_threat
    threat_type = threat.get("validation", {}).get("threat_type", "Unknown")
    severity = threat.get("validation", {}).get("severity", "Unknown")
    confidence = threat.get("validation", {}).get("confidence", 0)
    log_type = threat.get("type", "Unknown")
    
    # Header with threat info
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Threat Type", threat_type)
    with col2:
        st.metric("Severity", severity)
    with col3:
        st.metric("Confidence", f"{confidence:.1%}")
    with col4:
        st.metric("Log Type", log_type.title())
    
    # Create tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Analysis", "🛡️ Response", "📋 Report", "📊 Raw Data"])
    
    with tab1:
        st.subheader("🔍 Threat Analysis")
        
        # Visual representation
        if log_type == "network":
            row = threat.get("row", {})
            
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
            
            # Key metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Packet Size", f"{row.get('Packet Size (bytes)', 0):.0f} bytes")
            with col2:
                st.metric("Duration", f"{row.get('Flow Duration (s)', 0):.2f}s")
            with col3:
                st.metric("Threat", "🔴 Yes" if row.get("Threat") == "Yes" else "🟢 No")
        
        else:  # System log
            row = threat.get("row", {})
            
            # System event visualization
            fig = go.Figure()
            
            # Event type indicator
            event_type = row.get("Event Type", "Unknown")
            event_icons = {
                "Privilege Escalation": "⬆️",
                "Malware Detected": "🦠",
                "Data Breach": "📂",
                "Failed Login": "❌",
                "File Access": "📁",
                "Login": "🔑"
            }
            
            fig.add_trace(go.Scatter(
                x=[0.5], y=[0.5],
                mode='markers+text',
                marker=dict(size=50, color='red' if row.get("Threat") == "Yes" else 'green'),
                text=[f"{event_icons.get(event_type, '❓')}\n{event_type}"],
                textposition="middle center",
                textfont=dict(size=16)
            ))
            
            fig.update_layout(
                title="System Event",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[0, 1]),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[0, 1]),
                height=300,
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Key metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("User", row.get("User", "Unknown"))
            with col2:
                st.metric("Success", row.get("Success", "Unknown"))
            with col3:
                st.metric("Threat", "🔴 Yes" if row.get("Threat") == "Yes" else "🟢 No")
        
        # AI Classification Results
        st.subheader("🤖 AI Analysis Results")
        
        classification = threat.get("classification", {})
        if classification:
            col1, col2 = st.columns(2)
            
            with col1:
                # Threat type indicator
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
    
    with tab2:
        st.subheader("🛡️ Response Plan")
        response = threat.get("response", "No response generated.")
        if response and response != "No response generated.":
            st.markdown(response)
        else:
            st.warning("No response plan generated")
    
    with tab3:
        st.subheader("📋 Final Report")
        report = threat.get("report", "No report generated.")
        if report and report != "No report generated.":
            st.markdown(report)
        else:
            st.warning("No final report generated")
    
    with tab4:
        st.subheader("📊 Raw Data")
        st.json(threat.get("row", {}))
    
    # Close button
    if st.button("❌ Close Report"):
        del st.session_state.selected_threat
        st.rerun()

# Footer
st.divider()
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>🛡️ CyberWatchdog - Dual-System AI Cybersecurity Analysis</p>
    <p>Network + System Logs • Automated + Manual Control • Cost-Effective AI</p>
</div>
""", unsafe_allow_html=True)
