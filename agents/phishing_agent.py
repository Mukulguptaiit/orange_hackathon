# agents/phishing_agent.py
import json
from crewai import Agent, Task
from .common import get_llm

phishing_agent = Agent(
    role="Phishing Response Agent",
    goal="Mitigate phishing: block IOCs, educate users, takedown requests, sandbox attachments.",
    backstory="Expert in email and web phishing campaigns.",
    verbose=False,
    llm=get_llm()
)

def make_phishing_task(validated_json: str, record: dict) -> Task:
    rec = json.dumps(record, default=str)
    prompt = f"""
You are the Phishing Response Agent.

Validated Event (JSON):
{validated_json}

Original Record (JSON):
{rec}

Output a concise MARKDOWN action plan:
- Immediate actions (bullets)
- Blocking/Takedown (bullets)
- User comms/training (bullets)
- Monitoring (1–2 bullets)
    """.strip()
    return Task(
        description=prompt,
        expected_output="Markdown action plan for phishing",
        agent=phishing_agent
    )
