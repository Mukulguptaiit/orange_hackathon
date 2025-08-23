# reporting/report_writer.py
import json
from crewai import Agent, Task
from agents.common import get_llm  # reuse same LLM

report_writer = Agent(
    role="Cybersecurity Report Writer",
    goal="Produce an executive markdown summary with threats, severities, IOCs, signatures, and next steps.",
    backstory="Summarizes SOC activity into concise, actionable reports.",
    verbose=False,
    llm=get_llm()
)

def make_report_task(summary_context: dict) -> Task:
    prompt = f"""
Write an executive-ready MARKDOWN report for the SOC lead.

Context (JSON):
{json.dumps(summary_context, indent=2)}

Include:
- Time window analyzed
- Totals by threat type and severity (short table or bullets)
- Notable IOCs and common signatures
- 3–5 recommended actions for next 24h
- If applicable, highlight high/critical items

Keep it concise and structured with headings.
    """.strip()

    return Task(
        description=prompt,
        expected_output="Markdown report",
        agent=report_writer
    )
