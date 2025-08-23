# agents/data_breach_agent.py
import json
from crewai import Agent, Task
from .common import get_llm

data_breach_agent = Agent(
    role="Data Breach Response Agent",
    goal="Contain exfiltration, protect secrets, start IR, and legal/compliance notifications.",
    backstory="Incident response for leaks/exfil.",
    verbose=False,
    llm=get_llm()
)

def make_data_breach_task(validated_json: str, record: dict) -> Task:
    rec = json.dumps(record, default=str)
    prompt = f"""
You are the Data Breach Response Agent.

Validated Event (JSON):
{validated_json}

Original Record (JSON):
{rec}

Output a concise MARKDOWN action plan:
- Immediate containment (bullets)
- Credential/token rotation (bullets)
- Legal/compliance comms (bullets)
- Forensics & monitoring (1–2 bullets)
    """.strip()
    return Task(
        description=prompt,
        expected_output="Markdown action plan for data breach",
        agent=data_breach_agent
    )
