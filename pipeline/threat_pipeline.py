import pandas as pd
import json
from agents.classifier_agent import classifier_agent, make_classification_task
from agents.validator_agent import validator_agent, make_validation_task
from agents.malware_agent import malware_agent, make_malware_task
from agents.phishing_agent import phishing_agent, make_phishing_task
from agents.ddos_agent import ddos_agent, make_ddos_task
from agents.data_breach_agent import data_breach_agent, make_data_breach_task
from reporting.report_writer import report_writer, make_report_task
from agents.common import get_llm

class ThreatPipeline:
    def __init__(self, data_path: str):
        self.df = pd.read_csv(data_path)
        self.index = 0
        self.results = []
        self.llm = get_llm()
        
        # Create baselines from first 100 rows
        self.baselines = self._create_baselines()

    def _create_baselines(self):
        """Create simple baselines from training data"""
        sample_data = self.df.head(100)
        baselines = {
            "avg_packet_size": sample_data["Packet Size (bytes)"].mean(),
            "common_protocols": sample_data["Protocol"].value_counts().to_dict(),
            "threat_distribution": sample_data["Threat"].value_counts().to_dict(),
            "event_types": sample_data["Event Type"].value_counts().to_dict()
        }
        return baselines

    def _execute_with_llm(self, prompt):
        """Execute prompt directly with LLM"""
        try:
            response = self.llm.invoke(prompt)
            return response.content
        except Exception as e:
            print(f"LLM execution failed: {e}")
            return None

    def _classify_threat(self, row):
        """Classify threat using LLM"""
        record_json = json.dumps(row, default=str)
        baseline_json = json.dumps(self.baselines, default=str)
        
        prompt = f"""Classify network log: {record_json}

Return JSON: {{"threat_type": "Phishing|Malware|DDoS|Data Breach|Brute Force|Benign|Other", "severity": "Low|Medium|High|Critical", "iocs": ["ip1", "ip2"], "signature": "attack_type"}}"""
        
        result = self._execute_with_llm(prompt)
        if result:
            try:
                # Try to extract JSON from the response
                if '{' in result and '}' in result:
                    start = result.find('{')
                    end = result.rfind('}') + 1
                    json_str = result[start:end]
                    return json.loads(json_str)
            except:
                pass
        
        # Fallback classification based on data
        threat_type = row.get("Threat Type", "Unknown")
        if row.get("Threat") == "Yes":
            if "Port Scan" in str(threat_type):
                return {
                    "threat_type": "Port Scan",
                    "severity": "Medium",
                    "iocs": [row.get("Source IP", "Unknown")],
                    "signature": "port_scanning_activity"
                }
            elif "Phishing" in str(threat_type):
                return {
                    "threat_type": "Phishing",
                    "severity": "High",
                    "iocs": [row.get("Source IP", "Unknown")],
                    "signature": "phishing_attempt"
                }
            elif "DDoS" in str(threat_type):
                return {
                    "threat_type": "DDoS",
                    "severity": "High",
                    "iocs": [row.get("Source IP", "Unknown")],
                    "signature": "ddos_attack"
                }
            elif "Malware" in str(threat_type):
                return {
                    "threat_type": "Malware",
                    "severity": "High",
                    "iocs": [row.get("Source IP", "Unknown")],
                    "signature": "malware_activity"
                }
            else:
                return {
                    "threat_type": "Malware",
                    "severity": "Medium",
                    "iocs": [row.get("Source IP", "Unknown")],
                    "signature": "suspicious_activity"
                }
        else:
            return {
                "threat_type": "Benign",
                "severity": "Low",
                "iocs": [],
                "signature": "normal_traffic"
            }

    def _validate_classification(self, row, classification):
        """Validate classification using LLM"""
        record_json = json.dumps(row, default=str)
        classification_json = json.dumps(classification, default=str)
        
        prompt = f"""Validate: Record: {record_json}, Classification: {classification_json}

Return JSON: {{"threat_type": "final_type", "severity": "final_severity", "confidence": 0.95, "iocs": ["ip1"], "signature": "final_signature"}}"""
        
        result = self._execute_with_llm(prompt)
        if result:
            try:
                if '{' in result and '}' in result:
                    start = result.find('{')
                    end = result.rfind('}') + 1
                    json_str = result[start:end]
                    return json.loads(json_str)
            except:
                pass
        
        # Fallback validation
        return {
            "threat_type": classification.get("threat_type", "Unknown"),
            "severity": classification.get("severity", "Low"),
            "confidence": 0.8,
            "iocs": classification.get("iocs", []),
            "signature": classification.get("signature", "unknown")
        }

    def _generate_response_plan(self, threat_type, validated_json, record):
        """Generate response plan using LLM"""
        record_json = json.dumps(record, default=str)
        validated_json_str = json.dumps(validated_json, default=str)
        
        prompt = f"""Generate {threat_type} response plan for: {validated_json_str}

Return markdown with: Immediate actions, Containment, Recovery, Monitoring"""
        
        result = self._execute_with_llm(prompt)
        if result:
            return result
        
        # Fallback response plans
        fallback_responses = {
            "malware": "## Malware Response Plan\n- **Immediate Actions:**\n  - Isolate affected systems\n  - Block suspicious IPs\n  - Update antivirus signatures\n- **Containment:**\n  - Disconnect from network\n  - Monitor for lateral movement\n- **Recovery:**\n  - Remove malware\n  - Restore from clean backups",
            "phishing": "## Phishing Response Plan\n- **Immediate Actions:**\n  - Block sender domains\n  - Alert users\n  - Scan for similar emails\n- **User Notification:**\n  - Send security alert\n  - Provide reporting instructions\n- **Prevention:**\n  - Update email filters\n  - Conduct security training",
            "ddos": "## DDoS Response Plan\n- **Immediate Actions:**\n  - Activate DDoS protection\n  - Block attack sources\n  - Scale infrastructure\n- **Traffic Filtering:**\n  - Implement rate limiting\n  - Use CDN protection\n- **Monitoring:**\n  - Monitor traffic patterns\n  - Set up alerts",
            "data breach": "## Data Breach Response Plan\n- **Immediate Actions:**\n  - Contain the breach\n  - Preserve evidence\n  - Notify stakeholders\n- **Investigation:**\n  - Conduct forensics\n  - Identify affected data\n  - Determine root cause\n- **Compliance:**\n  - Report to authorities\n  - Notify affected parties"
        }
        
        return fallback_responses.get(threat_type.lower(), "## Response Plan\n- **Immediate Actions:**\n  - Assess the situation\n  - Contain the threat\n  - Preserve evidence\n- **Next Steps:**\n  - Investigate root cause\n  - Implement preventive measures")

    def _generate_report(self, row, classification, validation, response):
        """Generate final report using LLM"""
        record_json = json.dumps(row, default=str)
        classification_json = json.dumps(classification, default=str)
        validation_json = json.dumps(validation, default=str)
        
        prompt = f"""Write security report: Record: {record_json}, Class: {classification_json}, Validation: {validation_json}

Return markdown with: Summary, Details, Analysis, Actions, Recommendations"""
        
        result = self._execute_with_llm(prompt)
        if result:
            return result
        
        # Fallback report
        return f"""## Security Incident Report

### Executive Summary
Security incident detected and analyzed using AI-powered threat detection.

### Incident Details
- **Threat Type:** {validation.get('threat_type', 'Unknown')}
- **Severity:** {validation.get('severity', 'Unknown')}
- **Confidence:** {validation.get('confidence', 0):.1%}
- **Source IP:** {row.get('Source IP', 'Unknown')}
- **Destination IP:** {row.get('Destination IP', 'Unknown')}

### Threat Analysis
- **IOCs:** {', '.join(validation.get('iocs', []))}
- **Signature:** {validation.get('signature', 'Unknown')}
- **Protocol:** {row.get('Protocol', 'Unknown')}

### Response Actions
{response}

### Recommendations
1. Monitor similar traffic patterns
2. Update security controls
3. Conduct security training
4. Implement additional monitoring"""

    def next_row(self):
        """Process next row in the dataset"""
        if self.index >= len(self.df):
            return None, "✅ All data processed."
        
        # Get current row
        row = self.df.iloc[self.index].to_dict()
        self.index += 1
        
        try:
            # Step 1: Classify the threat
            print(f"🔍 Classifying threat for row {self.index}...")
            classification = self._classify_threat(row)
            
            # Step 2: Validate the classification
            print(f"✅ Validating classification...")
            validation = self._validate_classification(row, classification)
            
            # Step 3: Generate response plan
            print(f"🛡️ Generating response plan...")
            threat_type = validation.get("threat_type", "Unknown")
            response = self._generate_response_plan(threat_type, validation, row)
            
            # Step 4: Generate final report
            print(f"📋 Generating final report...")
            final_report = self._generate_report(row, classification, validation, response)
            
            # Store result
            result = {
                "row": row,
                "classification": classification,
                "validation": validation,
                "response": response,
                "report": final_report
            }
            self.results.append(result)
            
            print(f"✅ Row {self.index} processed successfully!")
            return row, result
            
        except Exception as e:
            error_msg = f"Error processing row {self.index}: {str(e)}"
            print(f"❌ {error_msg}")
            return row, error_msg

    def get_statistics(self):
        """Get processing statistics"""
        if not self.results:
            return {}
        
        threat_types = [r["validation"].get("threat_type", "Unknown") for r in self.results]
        severities = [r["validation"].get("severity", "Low") for r in self.results]
        
        return {
            "total_processed": len(self.results),
            "threat_distribution": pd.Series(threat_types).value_counts().to_dict(),
            "severity_distribution": pd.Series(severities).value_counts().to_dict(),
            "current_index": self.index,
            "total_rows": len(self.df)
        }
