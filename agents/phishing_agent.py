# agents/phishing_agent.py
import json
from crewai import Agent, Task
from .common import get_llm

phishing_agent = Agent(
    role="Phishing Response Agent",
    goal="Propose precise, actionable steps to contain and mitigate phishing attacks.",
    backstory="Specialist in phishing, social engineering, credential harvesting, spear phishing.",
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
- User notification (bullets)
- Email filtering rules (bullets)
- Training recommendations (1–2 bullets)
    """.strip()
    return Task(
        description=prompt,
        expected_output="Markdown action plan for phishing",
        agent=phishing_agent
    )

# Default task for pipeline
phishing_task = make_phishing_task("{}", {})
