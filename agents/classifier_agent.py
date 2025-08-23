# agents/classifier_agent.py
import json
from crewai import Agent, Task
from .common import get_llm

THREAT_TYPES = ["Phishing","Malware","DDoS","Data Breach","Brute Force","Benign","Other"]
SEVERITIES   = ["Low","Medium","High","Critical"]

classifier_agent = Agent(
    role="Threat Classifier",
    goal="Classify a single network/security log into a threat type and severity with IOCs and signature.",
    backstory=(
        "You are a SOC classifier. You read one record at a time, "
        "use prior baselines, and return a strict JSON object."
    ),
    verbose=False,
    llm=get_llm()
)

def make_classification_task(record: dict, baselines: dict = None) -> Task:
    record_json = json.dumps(record, default=str)
    baseline_json = json.dumps(baselines or {}, default=str)

    prompt = f"""
You are a cybersecurity classifier.

Inputs:
1) Single network log (JSON):
{record_json}

2) Simple baselines from training:
{baseline_json}

Classify the log:
- threat_type: one of {THREAT_TYPES}
- severity: one of {SEVERITIES}
- iocs: list of observable indicators (IPs, URLs, domains, file hashes) if any
- signature: concise attack label (e.g., "HTTP flood", "credential stuffing", "ransomware beacon")

Return ONLY valid JSON:
{{
  "threat_type": "...",
  "severity": "...",
  "iocs": ["..."],
  "signature": "..."
}}
    """.strip()

    return Task(
        description=prompt,
        expected_output="Strict JSON with keys: threat_type, severity, iocs, signature",
        agent=classifier_agent
    )

# Default task for pipeline
classification_task = make_classification_task({})
