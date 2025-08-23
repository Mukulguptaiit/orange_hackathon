# agents/validator_agent.py
import json
from crewai import Agent, Task
from .common import get_llm

THREAT_TYPES = ["Phishing","Malware","DDoS","Data Breach","Brute Force","Benign","Other"]
SEVERITIES   = ["Low","Medium","High","Critical"]

validator_agent = Agent(
    role="Threat Validator",
    goal="Validate classification via 5x self-consistency and majority vote; refine severity.",
    backstory=(
        "You perform internal 5-pass self-consistency on the provided classification + raw record. "
        "You return a final JSON with the voted threat_type and severity, confidence score, and merged IOCs/signature."
    ),
    verbose=False,
    llm=get_llm()
)

def make_validation_task(record: dict, classification_json: str) -> Task:
    rec_json = json.dumps(record, default=str)

    prompt = f"""
You are a validator. You will VALIDATE the given classification with 5 internal passes (self-consistency)
on the raw JSON record and then output the MAJORITY VOTE.

Raw Record (JSON):
{rec_json}

Proposed Classification (JSON):
{classification_json}

Instructions:
- Internally run 5 independent assessments.
- Majority vote over threat_type and severity from these sets:
  - threat_type in {THREAT_TYPES}
  - severity in {SEVERITIES}
- Merge IOCs (union, deduplicate) and pick the most common signature if conflicting.
- Provide a confidence float ∈ [0,1] proportional to vote margin.

Return ONLY valid JSON:
{{
  "threat_type": "...",
  "severity": "...",
  "confidence": 0.0,
  "iocs": ["..."],
  "signature": "..."
}}
    """.strip()

    return Task(
        description=prompt,
        expected_output="Strict JSON (threat_type, severity, confidence, iocs, signature)",
        agent=validator_agent
    )
