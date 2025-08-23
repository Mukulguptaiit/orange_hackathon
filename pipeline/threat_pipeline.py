import pandas as pd
from crewai import Crew, Process
from agents.classifier_agent import classifier_agent, classification_task
from agents.validator_agent import validation_agent, validation_task
from agents.malware_agent import malware_agent, malware_task
from agents.phishing_agent import phishing_agent, phishing_task
from agents.ddos_agent import ddos_agent, ddos_task
from agents.data_breach_agent import data_breach_agent, data_breach_task
from reporting.report_writer import report_writer, report_task

class ThreatPipeline:
    def __init__(self, data_path: str):
        self.df = pd.read_csv(data_path)
        self.train_df = self.df.iloc[:300]
        self.test_df = self.df.iloc[300:]
        self.index = 0  

        self.crew = Crew(
            agents=[
                classifier_agent, validation_agent,
                malware_agent, phishing_agent,
                ddos_agent, data_breach_agent,
                report_writer
            ],
            tasks=[
                classification_task, validation_task,
                malware_task, phishing_task,
                ddos_task, data_breach_task,
                report_task
            ],
            process=Process.sequential,
            verbose=2
        )

    def next_row(self):
        if self.index >= len(self.test_df):
            return None, "✅ All test data processed."
        row = self.test_df.iloc[self.index].to_dict()
        self.index += 1
        results = self.crew.kickoff(inputs={"data": row})
        return row, results["final_output"]
