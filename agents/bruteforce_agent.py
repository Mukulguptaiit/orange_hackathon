# agents/bruteforce_agent.py
import json
from crewai import Agent, Task
from .common import get_llm

bruteforce_agent = Agent(
    role="Brute Force Response Agent",
    goal="Contain credential attacks: MFA, lockouts, IP blocks, adaptive rules.",
    backstory="Authentication abuse mitigation specialist.",
    verbose=False,
    llm=get_llm()
)

def make_bruteforce_task(validated_json: str, record: dict) -> Task:
    rec = json.dumps(record, default=str)
    prompt = f"""
You are the Brute Force Response Agent.

Validated Event (JSON):
{validated_json}

Original Record (JSON):
{rec}

Output a concise MARKDOWN action plan:
- Immediate actions (bullets)
- Auth policy changes (bullets)
- Network/IDP rules (bullets)
- Monitoring (1–2 bullets)
    """.strip()
    return Task(
        description=prompt,
        expected_output="Markdown action plan for brute force",
        agent=bruteforce_agent
    )
