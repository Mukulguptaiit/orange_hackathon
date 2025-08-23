import time
import threading
from datetime import datetime, timedelta
from .network_pipeline import NetworkPipeline
from .system_pipeline import SystemPipeline

class AutomatedLogger:
    """Automated logger that processes logs every 5 minutes"""
    
    def __init__(self):
        self.network_pipeline = NetworkPipeline("data/network_traffic_logs.csv")
        self.system_pipeline = SystemPipeline("data/system_event_logs.csv")
        self.is_running = False
        self.thread = None
        self.last_network_check = None
        self.last_system_check = None
        
        # Store results in memory instead of session state
        self.automated_results = []
        self.last_automated_run = None
        
        # Callback function to update UI (will be set by main.py)
        self.update_callback = None
    
    def set_update_callback(self, callback):
        """Set callback function to update UI when new threats are found"""
        self.update_callback = callback
    
    def start_automation(self):
        """Start the automated logging process"""
        if not self.is_running:
            self.is_running = True
            self.thread = threading.Thread(target=self._run_automation, daemon=True)
            self.thread.start()
            print("🚀 Automated logging started - processing logs every 5 minutes")
    
    def stop_automation(self):
        """Stop the automated logging process"""
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=1)
        print("⏹️ Automated logging stopped")
    
    def _run_automation(self):
        """Main automation loop"""
        while self.is_running:
            try:
                current_time = datetime.now()
                
                # Check if it's time to process logs (every 5 minutes)
                if (self.last_network_check is None or 
                    (current_time - self.last_network_check).total_seconds() >= 300):  # 5 minutes
                    
                    print(f"⏰ {current_time.strftime('%H:%M:%S')} - Processing logs...")
                    self._process_logs()
                    self.last_network_check = current_time
                    self.last_system_check = current_time
                
                # Sleep for 1 minute before next check
                time.sleep(60)
                
            except Exception as e:
                print(f"❌ Error in automation loop: {e}")
                time.sleep(60)
    
    def _process_logs(self):
        """Process both network and system logs"""
        try:
            # Process network logs (5 at a time)
            network_results = self.network_pipeline.process_batch(batch_size=5)
            
            # Process system logs (5 at a time)
            system_results = self.system_pipeline.process_batch(batch_size=5)
            
            # Combine results
            all_results = network_results + system_results
            
            # Only store results if threats were found
            if all_results:
                # Update local results
                self.automated_results.extend(all_results)
                self.last_automated_run = datetime.now()
                
                print(f"🔍 Found {len(all_results)} threats in automated scan")
                for result in all_results:
                    threat_type = result.get("validation", {}).get("threat_type", "Unknown")
                    severity = result.get("validation", {}).get("severity", "Unknown")
                    log_type = result.get("type", "Unknown")
                    print(f"  - {log_type.upper()}: {threat_type} ({severity})")
                
                # Call callback to update UI if available
                if self.update_callback:
                    try:
                        self.update_callback(all_results)
                    except Exception as e:
                        print(f"⚠️ Warning: Could not update UI: {e}")
            else:
                print("✅ No threats found in automated scan")
                
        except Exception as e:
            print(f"❌ Error processing logs: {e}")
    
    def get_status(self):
        """Get current automation status"""
        return {
            "is_running": self.is_running,
            "last_network_check": self.last_network_check,
            "last_system_check": self.last_system_check,
            "network_stats": self.network_pipeline.get_stats(),
            "system_stats": self.system_pipeline.get_stats(),
            "total_threats_found": len(self.automated_results)
        }
    
    def get_recent_threats(self, hours=24):
        """Get threats from the last N hours"""
        if not self.automated_results:
            return []
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_threats = []
        
        for result in self.automated_results:
            # Extract timestamp from the result
            timestamp_str = result.get("row", {}).get("Timestamp", "")
            if timestamp_str:
                try:
                    # Parse timestamp (handle different formats)
                    if " " in timestamp_str:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    else:
                        timestamp = datetime.strptime(timestamp_str, "%d/%m/%y %H:%M")
                    
                    if timestamp >= cutoff_time:
                        recent_threats.append(result)
                except:
                    # If timestamp parsing fails, include the result
                    recent_threats.append(result)
        
        return recent_threats
    
    def reset_pipelines(self):
        """Reset both pipelines to start from beginning"""
        self.network_pipeline = NetworkPipeline("data/network_traffic_logs.csv")
        self.system_pipeline = SystemPipeline("data/system_event_logs.csv")
        self.automated_results = []
        self.last_automated_run = None
        print("🔄 Pipelines reset - starting from beginning")
    
    def manual_scan(self):
        """Trigger a manual scan immediately"""
        print("🔍 Manual scan triggered...")
        self._process_logs()
        return len(self.automated_results)
    
    def get_results(self):
        """Get all automated results"""
        return self.automated_results.copy()
    
    def clear_results(self):
        """Clear all results"""
        self.automated_results = []
        self.last_automated_run = None
