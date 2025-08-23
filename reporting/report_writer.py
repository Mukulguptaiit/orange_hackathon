# reporting/report_writer.py
import json
from crewai import Agent, Task
from agents.common import get_llm

report_writer = Agent(
    role="Security Report Writer",
    goal="Generate comprehensive, structured security incident reports.",
    backstory="Expert in cybersecurity reporting, incident documentation, and executive summaries.",
    verbose=False,
    llm=get_llm()
)

def make_report_task(record: dict, classification: str, validation: str, response: str) -> Task:
    rec = json.dumps(record, default=str)
    prompt = f"""
You are the Security Report Writer.

Generate a comprehensive incident report from:

Original Record (JSON):
{rec}

Classification (JSON):
{classification}

Validation (JSON):
{validation}

Response Action Plan:
{response}

Output a structured MARKDOWN report with:
- Executive Summary
- Incident Details
- Threat Analysis
- Response Actions
- Recommendations
- Timeline
    """.strip()
    return Task(
        description=prompt,
        expected_output="Structured markdown incident report",
        agent=report_writer
    )

# Default task for pipeline
report_task = make_report_task({}, "{}", "{}", "")
