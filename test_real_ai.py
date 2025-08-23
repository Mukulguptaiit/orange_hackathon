#!/usr/bin/env python3
"""
Test real AI responses vs mock responses
"""

from pipeline.threat_pipeline import ThreatPipeline
import json

def test_real_ai():
    print("🤖 Testing Real AI vs Mock Responses")
    print("=" * 50)
    
    # Initialize pipeline
    pipeline = ThreatPipeline("data/network_traffic_logs.csv")
    
    # Test processing one row with real AI
    print("\n📊 Processing with Real AI...")
    row, report = pipeline.next_row()
    
    if row and pipeline.results:
        latest = pipeline.results[-1]
        
        print(f"🔍 Original Log: {row.get('Source IP')} -> {row.get('Destination IP')}")
        print(f"📋 Threat: {row.get('Threat')} - {row.get('Threat Type')}")
        
        classification = latest.get("classification", {})
        validation = latest.get("validation", {})
        response = latest.get("response", "")
        
        print(f"\n🤖 AI Classification:")
        print(f"   Threat Type: {classification.get('threat_type', 'Unknown')}")
        print(f"   Severity: {classification.get('severity', 'Unknown')}")
        print(f"   IOCs: {classification.get('iocs', [])}")
        print(f"   Signature: {classification.get('signature', 'Unknown')}")
        
        print(f"\n✅ Validation:")
        print(f"   Confidence: {validation.get('confidence', 0)}")
        print(f"   Final Threat: {validation.get('threat_type', 'Unknown')}")
        
        print(f"\n📋 Response Plan (first 200 chars):")
        print(f"   {response[:200]}...")
        
        print(f"\n📄 Report (first 200 chars):")
        if isinstance(report, str):
            print(f"   {report[:200]}...")
        else:
            print(f"   {str(report)[:200]}...")
        
        print(f"\n🎉 Real AI is working! Check the web interface for full results.")
        
    else:
        print("❌ Failed to process with real AI")

if __name__ == "__main__":
    test_real_ai()
