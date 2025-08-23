# agents/common.py
import os
from langchain_groq import ChatGroq

# Expect env: GROQ_API_KEY
def get_llm():
    # Temperature 0 for deterministic ops in a SOC pipeline
    return ChatGroq(temperature=0, model_name="llama3-70b-8192")
