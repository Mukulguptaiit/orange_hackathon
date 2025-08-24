#!/usr/bin/env python3
"""
Test script for CyberWatchdog pipeline
"""

from pipeline.threat_pipeline import ThreatPipeline
import json

def test_pipeline():
    print("🛡️ Testing CyberWatchdog Pipeline")
    print("=" * 50)
    
    # Initialize pipeline
    pipeline = ThreatPipeline("data/network_traffic_logs.csv")
    
    # Test processing a few rows
    for i in range(3):
        print(f"\n📊 Processing row {i+1}...")
        row, report = pipeline.next_row()
        
        if row:
            print(f"✅ Row processed successfully")
            print(f"📝 Report length: {len(str(report))} characters")
            
            # Check if we have proper results
            if pipeline.results:
                latest = pipeline.results[-1]
                classification = latest.get("classification", {})
                validation = latest.get("validation", {})
                response = latest.get("response", "")
                
                print(f"🔍 Classification: {classification.get('threat_type', 'Unknown')}")
                print(f"⚡ Severity: {classification.get('severity', 'Unknown')}")
                print(f"🎯 Confidence: {validation.get('confidence', 0)}")
                print(f"📋 Response: {'Generated' if response else 'Missing'}")
        else:
            print(f"❌ Failed to process row: {report}")
    
    # Show statistics
    stats = pipeline.get_statistics()
    print(f"\n📈 Pipeline Statistics:")
    print(f"   Total processed: {stats.get('total_processed', 0)}")
    print(f"   Threat distribution: {stats.get('threat_distribution', {})}")
    
    print("\n🎉 Pipeline test completed!")

if __name__ == "__main__":
    test_pipeline()
