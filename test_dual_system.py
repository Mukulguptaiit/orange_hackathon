#!/usr/bin/env python3
"""
Test script for the new dual-system CyberWatchdog architecture
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from pipeline.network_pipeline import NetworkPipeline
from pipeline.system_pipeline import SystemPipeline

def test_network_pipeline():
    """Test the network pipeline"""
    print("🌐 Testing Network Pipeline...")
    print("=" * 50)
    
    try:
        pipeline = NetworkPipeline("data/network_traffic_logs.csv")
        print(f"✅ Network pipeline initialized")
        print(f"📊 Total rows: {pipeline.get_stats()['total_rows']}")
        
        # Process a batch
        results = pipeline.process_batch(batch_size=3)
        print(f"🔍 Processed batch: {len(results)} threats found")
        
        for i, result in enumerate(results):
            threat_type = result.get("validation", {}).get("threat_type", "Unknown")
            severity = result.get("validation", {}).get("severity", "Unknown")
            print(f"  {i+1}. {threat_type} ({severity})")
        
        return True
        
    except Exception as e:
        print(f"❌ Network pipeline test failed: {e}")
        return False

def test_system_pipeline():
    """Test the system pipeline"""
    print("\n💻 Testing System Pipeline...")
    print("=" * 50)
    
    try:
        pipeline = SystemPipeline("data/system_event_logs.csv")
        print(f"✅ System pipeline initialized")
        print(f"📊 Total rows: {pipeline.get_stats()['total_rows']}")
        
        # Process a batch
        results = pipeline.process_batch(batch_size=3)
        print(f"🔍 Processed batch: {len(results)} threats found")
        
        for i, result in enumerate(results):
            threat_type = result.get("validation", {}).get("threat_type", "Unknown")
            severity = result.get("validation", {}).get("severity", "Unknown")
            print(f"  {i+1}. {threat_type} ({severity})")
        
        return True
        
    except Exception as e:
        print(f"❌ System pipeline test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🛡️ Testing Dual-System CyberWatchdog")
    print("=" * 60)
    
    # Test network pipeline
    network_success = test_network_pipeline()
    
    # Test system pipeline
    system_success = test_system_pipeline()
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 Test Summary:")
    print(f"  🌐 Network Pipeline: {'✅ PASS' if network_success else '❌ FAIL'}")
    print(f"  💻 System Pipeline: {'✅ PASS' if system_success else '❌ FAIL'}")
    
    if network_success and system_success:
        print("\n🎉 All tests passed! Dual-system architecture is working.")
        print("🚀 You can now run the Streamlit application with:")
        print("   streamlit run main.py")
    else:
        print("\n❌ Some tests failed. Please check the error messages above.")
    
    return network_success and system_success

if __name__ == "__main__":
    main()
