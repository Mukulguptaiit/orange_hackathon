# agents/ddos_agent.py
import json
from crewai import Agent, Task
from .common import get_llm

ddos_agent = Agent(
    role="DDoS Response Agent",
    goal="Mitigate volumetric and application-layer DDoS.",
    backstory="Network defense, WAF rate-limits, ACLs, CDN shielding.",
    verbose=False,
    llm=get_llm()
)

def make_ddos_task(validated_json: str, record: dict) -> Task:
    rec = json.dumps(record, default=str)
    prompt = f"""
You are the DDoS Response Agent.

Validated Event (JSON):
{validated_json}

Original Record (JSON):
{rec}

Output a concise MARKDOWN action plan:
- Immediate actions (bullets)
- Network/WAF rules (bullets)
- Upstream coordination/CDN (bullets)
- Monitoring (1–2 bullets)
    """.strip()
    return Task(
        description=prompt,
        expected_output="Markdown action plan for DDoS",
        agent=ddos_agent
    )
