def run_pipeline():
    from agents.classifier_agent import ClassifierAgent
    from agents.validator_agent import ValidatorAgent
    from agents.malware_agent import MalwareAgent
    from agents.phishing_agent import PhishingAgent
    from agents.ddos_agent import DDoSAgent
    from agents.data_breach_agent import DataBreachAgent

    # Initialize agents
    validator = ValidatorAgent()
    classifier = ClassifierAgent()
    malware_detector = MalwareAgent()
    phishing_detector = PhishingAgent()
    ddos_detector = DDoSAgent()
    data_breach_detector = DataBreachAgent()

    # Validate data
    if not validator.validate_data('data/network_traffic_logs.csv'):
        print("Data validation failed.")
        return

    # Run threat detection
    traffic_data = validator.load_data('data/network_traffic_logs.csv')
    
    classifier_results = classifier.classify(traffic_data)
    malware_results = malware_detector.detect(traffic_data)
    phishing_results = phishing_detector.detect(traffic_data)
    ddos_results = ddos_detector.detect(traffic_data)
    data_breach_results = data_breach_detector.detect(traffic_data)

    # Aggregate results
    results = {
        "classification": classifier_results,
        "malware": malware_results,
        "phishing": phishing_results,
        "ddos": ddos_results,
        "data_breach": data_breach_results
    }

    return results