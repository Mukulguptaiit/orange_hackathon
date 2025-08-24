import pandas as pd
import json
from agents.common import get_llm

class NetworkPipeline:
    """Pipeline for analyzing network traffic logs"""
    
    def __init__(self, data_path: str):
        self.df = pd.read_csv(data_path)
        self.index = 0
        self.results = []
        self.llm = get_llm()
        
        # Create baselines from first 100 rows
        self.baselines = self._create_baselines()
    
    def _create_baselines(self):
        """Create baseline statistics from first 100 rows"""
        baseline_df = self.df.head(100)
        return {
            "avg_packet_size": baseline_df["Packet Size (bytes)"].mean(),
            "avg_duration": baseline_df["Flow Duration (s)"].mean(),
            "protocol_distribution": baseline_df["Protocol"].value_counts().to_dict(),
            "threat_rate": (baseline_df["Threat"] == "Yes").mean()
        }
    
    def _execute_with_llm(self, prompt):
        """Execute prompt directly with LLM"""
        try:
            response = self.llm.invoke(prompt)
            return response.content
        except Exception as e:
            print(f"LLM execution failed: {e}")
            return None
    
    def _classify_network_threat(self, row):
        """Classify network threat using AI"""
        record_json = json.dumps(row, default=str)
        baseline_json = json.dumps(self.baselines, default=str)
        
        prompt = f"""Classify network log: {record_json}

Return JSON: {{"threat_type": "Port Scan|DDoS|Phishing|Malware|Data Exfiltration|Brute Force|Benign|Other", "severity": "Low|Medium|High|Critical", "iocs": ["ip1", "ip2"], "signature": "attack_type"}}"""
        
        result = self._execute_with_llm(prompt)
        if result:
            try:
                # Extract JSON from response
                json_str = result.strip()
                if json_str.startswith("```json"):
                    json_str = json_str.split("```json")[1].split("```")[0]
                elif json_str.startswith("```"):
                    json_str = json_str.split("```")[1].split("```")[0]
                
                return json.loads(json_str)
            except:
                pass
        
        # Fallback classification based on raw data
        threat_type = row.get("Threat Type", "")
        if pd.isna(threat_type) or threat_type == "":
            if row.get("Threat") == "Yes":
                return {
                    "threat_type": "Suspicious Activity",
                    "severity": "Medium",
                    "iocs": [row.get("Source IP", ""), row.get("Destination IP", "")],
                    "signature": "Unclassified Threat"
                }
            else:
                return {
                    "threat_type": "Benign",
                    "severity": "Low",
                    "iocs": [],
                    "signature": "Normal Traffic"
                }
        else:
            return {
                "threat_type": threat_type,
                "severity": "High" if threat_type in ["DDoS", "Port Scan"] else "Medium",
                "iocs": [row.get("Source IP", ""), row.get("Destination IP", "")],
                "signature": threat_type
            }
    
    def _validate_network_classification(self, row, classification):
        """Validate network classification using AI"""
        record_json = json.dumps(row, default=str)
        classification_json = json.dumps(classification, default=str)
        
        prompt = f"""Validate network classification: Record: {record_json}, Classification: {classification_json}

Return JSON: {{"threat_type": "final_type", "severity": "final_severity", "confidence": 0.95, "iocs": ["ip1"], "signature": "final_signature"}}"""
        
        result = self._execute_with_llm(prompt)
        if result:
            try:
                json_str = result.strip()
                if json_str.startswith("```json"):
                    json_str = json_str.split("```json")[1].split("```")[0]
                elif json_str.startswith("```"):
                    json_str = json_str.split("```")[1].split("```")[0]
                
                return json.loads(json_str)
            except:
                pass
        
        # Fallback validation
        return {
            "threat_type": classification.get("threat_type", "Unknown"),
            "severity": classification.get("severity", "Unknown"),
            "confidence": 0.8,
            "iocs": classification.get("iocs", []),
            "signature": classification.get("signature", "Unknown")
        }
    
    def _generate_network_response(self, threat_type, validated_json, record):
        """Generate network-specific response plan"""
        validated_json_str = json.dumps(validated_json, default=str)
        
        prompt = f"""Generate {threat_type} network response plan for: {validated_json_str}

Return markdown with: Immediate actions, Containment, Recovery, Monitoring"""
        
        result = self._execute_with_llm(prompt)
        if result:
            return result
        
        # Fallback response plans
        fallback_responses = {
            "port scan": "## Port Scan Response Plan\n- **Immediate Actions:**\n  - Block source IP\n  - Monitor for additional scans\n- **Containment:**\n  - Update firewall rules\n- **Recovery:**\n  - Review security policies\n- **Monitoring:**\n  - Watch for repeated attempts",
            "ddos": "## DDoS Response Plan\n- **Immediate Actions:**\n  - Activate DDoS protection\n  - Block attack sources\n- **Containment:**\n  - Implement rate limiting\n- **Recovery:**\n  - Scale infrastructure\n- **Monitoring:**\n  - Monitor traffic patterns",
            "phishing": "## Phishing Response Plan\n- **Immediate Actions:**\n  - Block sender domains\n  - Alert users\n- **Containment:**\n  - Update email filters\n- **Recovery:**\n  - Conduct security training\n- **Monitoring:**\n  - Scan for similar emails",
            "malware": "## Malware Response Plan\n- **Immediate Actions:**\n  - Isolate affected systems\n  - Block suspicious IPs\n- **Containment:**\n  - Disconnect from network\n- **Recovery:**\n  - Remove malware\n- **Monitoring:**\n  - Monitor for lateral movement"
        }
        
        return fallback_responses.get(threat_type.lower(), "## Network Response Plan\n- **Immediate Actions:**\n  - Assess the situation\n  - Contain the threat\n- **Next Steps:**\n  - Investigate root cause\n  - Implement preventive measures")
    
    def _generate_network_report(self, row, classification, validation, response):
        """Generate network incident report"""
        record_json = json.dumps(row, default=str)
        classification_json = json.dumps(classification, default=str)
        validation_json = json.dumps(validation, default=str)
        
        prompt = f"""Write network security report: Record: {record_json}, Class: {classification_json}, Validation: {validation_json}

Return markdown with: Summary, Details, Analysis, Actions, Recommendations"""
        
        result = self._execute_with_llm(prompt)
        if result:
            return result
        
        # Fallback report
        return f"""## Network Security Incident Report

### Executive Summary
Network security incident detected and analyzed using AI-powered threat detection.

### Incident Details
- **Threat Type:** {validation.get('threat_type', 'Unknown')}
- **Severity:** {validation.get('severity', 'Unknown')}
- **Confidence:** {validation.get('confidence', 0):.1%}
- **Source IP:** {row.get('Source IP', 'Unknown')}
- **Destination IP:** {row.get('Destination IP', 'Unknown')}
- **Protocol:** {row.get('Protocol', 'Unknown')}

### Threat Analysis
- **IOCs:** {', '.join(validation.get('iocs', []))}
- **Signature:** {validation.get('signature', 'Unknown')}
- **Packet Size:** {row.get('Packet Size (bytes)', 'Unknown')} bytes
- **Duration:** {row.get('Flow Duration (s)', 'Unknown')} seconds

### Response Actions
{response}

### Recommendations
1. Monitor similar traffic patterns
2. Update network security controls
3. Implement additional monitoring
4. Review firewall rules"""
    
    def process_batch(self, batch_size=5):
        """Process a batch of network logs"""
        batch_results = []
        
        for _ in range(batch_size):
            if self.index >= len(self.df):
                break
            
            row = self.df.iloc[self.index].to_dict()
            self.index += 1
            
            try:
                print(f"🔍 Classifying network threat for row {self.index}...")
                classification = self._classify_network_threat(row)
                
                print(f"✅ Validating network classification...")
                validation = self._validate_network_classification(row, classification)
                
                print(f"🛡️ Generating network response plan...")
                threat_type = validation.get("threat_type", "Unknown")
                response = self._generate_network_response(threat_type, validation, row)
                
                print(f"📋 Generating network report...")
                final_report = self._generate_network_report(row, classification, validation, response)
                
                # Only store results if there's a threat
                if validation.get("threat_type") != "Benign" and validation.get("confidence", 0) > 0.5:
                    result = {
                        "row": row,
                        "classification": classification,
                        "validation": validation,
                        "response": response,
                        "report": final_report,
                        "type": "network"
                    }
                    batch_results.append(result)
                    self.results.append(result)
                
                print(f"✅ Network row {self.index} processed successfully!")
                
            except Exception as e:
                error_msg = f"Error processing network row {self.index}: {str(e)}"
                print(f"❌ {error_msg}")
        
        return batch_results
    
    def get_stats(self):
        """Get pipeline statistics"""
        return {
            "total_rows": len(self.df),
            "processed": self.index,
            "threats_found": len(self.results),
            "remaining": len(self.df) - self.index
        }
