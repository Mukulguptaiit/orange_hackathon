import pandas as pd
import json
from agents.common import get_llm

class SystemPipeline:
    """Pipeline for analyzing system event logs"""
    
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
            "event_type_distribution": baseline_df["Event Type"].value_counts().to_dict(),
            "user_distribution": baseline_df["User"].value_counts().to_dict(),
            "success_rate": (baseline_df["Success"] == "Yes").mean(),
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
    
    def _classify_system_threat(self, row):
        """Classify system threat using AI"""
        record_json = json.dumps(row, default=str)
        baseline_json = json.dumps(self.baselines, default=str)
        
        prompt = f"""Classify system event: {record_json}

Return JSON: {{"threat_type": "Privilege Escalation|Malware|Data Breach|Brute Force|Insider Threat|Benign|Other", "severity": "Low|Medium|High|Critical", "iocs": ["user1", "event1"], "signature": "attack_type"}}"""
        
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
        event_type = row.get("Event Type", "")
        threat = row.get("Threat", "No")
        
        if threat == "Yes":
            if event_type == "Privilege Escalation":
                return {
                    "threat_type": "Privilege Escalation",
                    "severity": "High",
                    "iocs": [row.get("User", ""), event_type],
                    "signature": "Privilege Escalation Attempt"
                }
            elif event_type == "Malware Detected":
                return {
                    "threat_type": "Malware",
                    "severity": "Critical",
                    "iocs": [row.get("User", ""), event_type],
                    "signature": "Malware Detection"
                }
            else:
                return {
                    "threat_type": "Suspicious Activity",
                    "severity": "Medium",
                    "iocs": [row.get("User", ""), event_type],
                    "signature": "Unclassified Threat"
                }
        else:
            return {
                "threat_type": "Benign",
                "severity": "Low",
                "iocs": [],
                "signature": "Normal Activity"
            }
    
    def _validate_system_classification(self, row, classification):
        """Validate system classification using AI"""
        record_json = json.dumps(row, default=str)
        classification_json = json.dumps(classification, default=str)
        
        prompt = f"""Validate system classification: Record: {record_json}, Classification: {classification_json}

Return JSON: {{"threat_type": "final_type", "severity": "final_severity", "confidence": 0.95, "iocs": ["user1"], "signature": "final_signature"}}"""
        
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
    
    def _generate_system_response(self, threat_type, validated_json, record):
        """Generate system-specific response plan"""
        validated_json_str = json.dumps(validated_json, default=str)
        
        prompt = f"""Generate {threat_type} system response plan for: {validated_json_str}

Return markdown with: Immediate actions, Containment, Recovery, Monitoring"""
        
        result = self._execute_with_llm(prompt)
        if result:
            return result
        
        # Fallback response plans
        fallback_responses = {
            "privilege escalation": "## Privilege Escalation Response Plan\n- **Immediate Actions:**\n  - Revoke elevated privileges\n  - Lock compromised accounts\n- **Containment:**\n  - Monitor user activities\n- **Recovery:**\n  - Reset passwords\n- **Monitoring:**\n  - Watch for repeated attempts",
            "malware": "## Malware Response Plan\n- **Immediate Actions:**\n  - Isolate affected systems\n  - Block malicious processes\n- **Containment:**\n  - Disconnect from network\n- **Recovery:**\n  - Remove malware\n- **Monitoring:**\n  - Monitor for lateral movement",
            "data breach": "## Data Breach Response Plan\n- **Immediate Actions:**\n  - Contain the breach\n  - Preserve evidence\n- **Containment:**\n  - Secure affected systems\n- **Recovery:**\n  - Assess data loss\n- **Monitoring:**\n  - Monitor for data exfiltration",
            "brute force": "## Brute Force Response Plan\n- **Immediate Actions:**\n  - Block source IPs\n  - Lock accounts\n- **Containment:**\n  - Implement rate limiting\n- **Recovery:**\n  - Reset passwords\n- **Monitoring:**\n  - Watch for repeated attempts"
        }
        
        return fallback_responses.get(threat_type.lower(), "## System Response Plan\n- **Immediate Actions:**\n  - Assess the situation\n  - Contain the threat\n- **Next Steps:**\n  - Investigate root cause\n  - Implement preventive measures")
    
    def _generate_system_report(self, row, classification, validation, response):
        """Generate system incident report"""
        record_json = json.dumps(row, default=str)
        classification_json = json.dumps(classification, default=str)
        validation_json = json.dumps(validation, default=str)
        
        prompt = f"""Write system security report: Record: {record_json}, Class: {classification_json}, Validation: {validation_json}

Return markdown with: Summary, Details, Analysis, Actions, Recommendations"""
        
        result = self._execute_with_llm(prompt)
        if result:
            return result
        
        # Fallback report
        return f"""## System Security Incident Report

### Executive Summary
System security incident detected and analyzed using AI-powered threat detection.

### Incident Details
- **Threat Type:** {validation.get('threat_type', 'Unknown')}
- **Severity:** {validation.get('severity', 'Unknown')}
- **Confidence:** {validation.get('confidence', 0):.1%}
- **User:** {row.get('User', 'Unknown')}
- **Event Type:** {row.get('Event Type', 'Unknown')}
- **Success:** {row.get('Success', 'Unknown')}

### Threat Analysis
- **IOCs:** {', '.join(validation.get('iocs', []))}
- **Signature:** {validation.get('signature', 'Unknown')}
- **Timestamp:** {row.get('Timestamp', 'Unknown')}

### Response Actions
{response}

### Recommendations
1. Monitor user activities
2. Update access controls
3. Conduct security training
4. Implement additional monitoring"""
    
    def process_batch(self, batch_size=5):
        """Process a batch of system logs"""
        batch_results = []
        
        for _ in range(batch_size):
            if self.index >= len(self.df):
                break
            
            row = self.df.iloc[self.index].to_dict()
            self.index += 1
            
            try:
                print(f"🔍 Classifying system threat for row {self.index}...")
                classification = self._classify_system_threat(row)
                
                print(f"✅ Validating system classification...")
                validation = self._validate_system_classification(row, classification)
                
                print(f"🛡️ Generating system response plan...")
                threat_type = validation.get("threat_type", "Unknown")
                response = self._generate_system_response(threat_type, validation, row)
                
                print(f"📋 Generating system report...")
                final_report = self._generate_system_report(row, classification, validation, response)
                
                # Only store results if there's a threat
                if validation.get("threat_type") != "Benign" and validation.get("confidence", 0) > 0.5:
                    result = {
                        "row": row,
                        "classification": classification,
                        "validation": validation,
                        "response": response,
                        "report": final_report,
                        "type": "system"
                    }
                    batch_results.append(result)
                    self.results.append(result)
                
                print(f"✅ System row {self.index} processed successfully!")
                
            except Exception as e:
                error_msg = f"Error processing system row {self.index}: {str(e)}"
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
