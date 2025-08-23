import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import seaborn as sns
from datetime import datetime
import json

def update_dashboard(results, pipeline=None):
    """Update the dashboard with comprehensive visualizations"""
    
    if not results:
        st.info("No data processed yet. Click 'Next Row' to start analysis.")
        return
    
    # Create tabs for different views
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🎯 Threat Analysis", "📈 Trends", "📋 Details"])
    
    with tab1:
        show_overview(results)
    
    with tab2:
        show_threat_analysis(results)
    
    with tab3:
        show_trends(results)
    
    with tab4:
        show_details(results, pipeline)

def show_overview(results):
    """Show overview statistics and charts"""
    st.subheader("📊 Security Overview")
    
    # Basic statistics
    col1, col2, col3, col4 = st.columns(4)
    
    total_events = len(results)
    threat_events = sum(1 for r in results if r.get("validation", {}).get("threat_type", "").lower() != "benign")
    high_severity = sum(1 for r in results if r.get("validation", {}).get("severity", "").lower() in ["high", "critical"])
    avg_confidence = sum(r.get("validation", {}).get("confidence", 0) for r in results) / len(results) if results else 0
    
    with col1:
        st.metric("Total Events", total_events)
    with col2:
        st.metric("Threat Events", threat_events)
    with col3:
        st.metric("High Severity", high_severity)
    with col4:
        st.metric("Avg Confidence", f"{avg_confidence:.2f}")
    
    # Threat distribution pie chart
    if results:
        threat_counts = {}
        for r in results:
            threat_type = r.get("validation", {}).get("threat_type", "Unknown")
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        fig = px.pie(
            values=list(threat_counts.values()),
            names=list(threat_counts.keys()),
            title="Threat Type Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)

def show_threat_analysis(results):
    """Show detailed threat analysis"""
    st.subheader("🎯 Threat Analysis")
    
    if not results:
        return
    
    # Severity distribution
    severity_counts = {}
    for r in results:
        severity = r.get("validation", {}).get("severity", "Unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.bar(
            x=list(severity_counts.keys()),
            y=list(severity_counts.values()),
            title="Severity Distribution",
            labels={"x": "Severity", "y": "Count"}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Confidence distribution
    with col2:
        confidences = [r.get("validation", {}).get("confidence", 0) for r in results]
        fig = px.histogram(
            x=confidences,
            title="Confidence Distribution",
            labels={"x": "Confidence", "y": "Count"},
            nbins=10
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Top IOCs
    st.subheader("🔍 Top Indicators of Compromise (IOCs)")
    all_iocs = []
    for r in results:
        iocs = r.get("validation", {}).get("iocs", [])
        if isinstance(iocs, list):
            all_iocs.extend(iocs)
    
    if all_iocs:
        ioc_counts = pd.Series(all_iocs).value_counts().head(10)
        fig = px.bar(
            x=ioc_counts.values,
            y=ioc_counts.index,
            orientation='h',
            title="Top 10 IOCs",
            labels={"x": "Count", "y": "IOC"}
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No IOCs detected yet.")

def show_trends(results):
    """Show temporal trends"""
    st.subheader("📈 Temporal Trends")
    
    if not results:
        return
    
    # Create timeline data
    timeline_data = []
    for i, r in enumerate(results):
        row = r.get("row", {})
        timestamp = row.get("Timestamp", f"Event {i+1}")
        threat_type = r.get("validation", {}).get("threat_type", "Unknown")
        severity = r.get("validation", {}).get("severity", "Unknown")
        
        timeline_data.append({
            "timestamp": timestamp,
            "threat_type": threat_type,
            "severity": severity,
            "confidence": r.get("validation", {}).get("confidence", 0)
        })
    
    df_timeline = pd.DataFrame(timeline_data)
    
    # Threat type over time
    fig = px.scatter(
        df_timeline,
        x="timestamp",
        y="threat_type",
        color="severity",
        size="confidence",
        title="Threat Types Over Time",
        labels={"timestamp": "Time", "threat_type": "Threat Type"}
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Severity trend
    severity_trend = df_timeline.groupby("severity").size().reset_index(name="count")
    fig = px.line(
        severity_trend,
        x="severity",
        y="count",
        title="Severity Trend",
        labels={"severity": "Severity", "count": "Count"}
    )
    st.plotly_chart(fig, use_container_width=True)

def show_details(results, pipeline=None):
    """Show detailed results"""
    st.subheader("📋 Detailed Results")
    
    if not results:
        return
    
    # Show pipeline statistics if available
    if pipeline:
        stats = pipeline.get_statistics()
        if stats:
            st.write("**Pipeline Statistics:**")
            st.json(stats)
    
    # Show recent results
    st.write("**Recent Analysis Results:**")
    
    for i, result in enumerate(results[-5:]):  # Show last 5 results
        with st.expander(f"Event {len(results) - 4 + i}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Original Log:**")
                st.json(result.get("row", {}))
                
                st.write("**Classification:**")
                st.json(result.get("classification", {}))
            
            with col2:
                st.write("**Validation:**")
                st.json(result.get("validation", {}))
                
                st.write("**Response Plan:**")
                st.markdown(result.get("response", "No response generated."))
            
            st.write("**Final Report:**")
            st.markdown(result.get("report", "No report generated."))

def create_summary_report(results):
    """Create a summary report of all findings"""
    if not results:
        return "No data to summarize."
    
    total_events = len(results)
    threat_events = sum(1 for r in results if r.get("validation", {}).get("threat_type", "").lower() != "benign")
    
    threat_types = [r.get("validation", {}).get("threat_type", "Unknown") for r in results]
    severities = [r.get("validation", {}).get("severity", "Unknown") for r in results]
    
    threat_dist = pd.Series(threat_types).value_counts()
    severity_dist = pd.Series(severities).value_counts()
    
    report = f"""
# 🛡️ CyberWatchdog Security Summary Report

## Executive Summary
- **Total Events Analyzed**: {total_events}
- **Threat Events Detected**: {threat_events}
- **Threat Rate**: {(threat_events/total_events*100):.1f}%

## Threat Distribution
{threat_dist.to_string()}

## Severity Distribution
{severity_dist.to_string()}

## Key Findings
- Most common threat type: {threat_dist.index[0] if len(threat_dist) > 0 else 'None'}
- Most common severity: {severity_dist.index[0] if len(severity_dist) > 0 else 'None'}
- Average confidence: {sum(r.get("validation", {}).get("confidence", 0) for r in results)/len(results):.2f}

## Recommendations
1. Monitor {threat_dist.index[0] if len(threat_dist) > 0 else 'all'} threats closely
2. Review security controls for {severity_dist.index[0] if len(severity_dist) > 0 else 'all'} severity events
3. Implement additional monitoring for detected IOCs
"""
    
    return report
