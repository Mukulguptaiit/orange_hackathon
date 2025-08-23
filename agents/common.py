# agents/common.py
import os
from langchain_groq import ChatGroq
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

load_dotenv()

def get_llm():
    """Get LLM with fallback options"""
    # Try Groq first
    groq_api_key = os.getenv("GROQ_API_KEY")
    if groq_api_key:
        try:
            return ChatGroq(temperature=0, model_name="llama3-70b-8192")
        except Exception as e:
            print(f"Groq failed: {e}")
    
    # Try OpenAI as fallback
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if openai_api_key:
        try:
            return ChatOpenAI(temperature=0, model="gpt-3.5-turbo")
        except Exception as e:
            print(f"OpenAI failed: {e}")
    
    # Mock LLM for demo purposes
    print("⚠️ No API keys found. Using mock LLM for demo.")
    return MockLLM()

class MockLLM:
    """Mock LLM for demo purposes when no API keys are available"""
    def invoke(self, prompt, **kwargs):
        # Simple rule-based responses for demo
        if "classify" in prompt.lower():
            return MockResponse('{"threat_type": "Malware", "severity": "Medium", "iocs": ["192.168.1.100"], "signature": "suspicious_connection"}')
        elif "validate" in prompt.lower():
            return MockResponse('{"threat_type": "Malware", "severity": "Medium", "confidence": 0.8, "iocs": ["192.168.1.100"], "signature": "suspicious_connection"}')
        else:
            return MockResponse("Mock response for demo purposes")

class MockResponse:
    def __init__(self, content):
        self.content = content
