import pandas as pd
from agents.classifier_agent import ClassifierAgent
from agents.validator_agent import ValidatorAgent
from agents.malware_agent import MalwareAgent
from agents.phishing_agent import PhishingAgent
from agents.ddos_agent import DDoSAgent
from agents.data_breach_agent import DataBreachAgent
from pipeline.threat_pipeline import run_pipeline
from reporting.dashboard import Dashboard
from reporting.report_writer import ReportWriter

def main():
    # Load network traffic logs
    data = pd.read_csv('data/network_traffic_logs.csv')

    # Initialize agents
    classifier_agent = ClassifierAgent()
    validator_agent = ValidatorAgent()
    malware_agent = MalwareAgent()
    phishing_agent = PhishingAgent()
    ddos_agent = DDoSAgent()
    data_breach_agent = DataBreachAgent()

    # Validate data
    if not validator_agent.validate(data):
        print("Data validation failed.")
        return

    # Run threat detection pipeline
    threats = run_pipeline(data, classifier_agent, malware_agent, phishing_agent, ddos_agent, data_breach_agent)

    # Generate reports
    report_writer = ReportWriter()
    report_writer.generate_report(threats)

    # Visualize results
    dashboard = Dashboard()
    dashboard.visualize(threats)

if __name__ == "__main__":
    main()