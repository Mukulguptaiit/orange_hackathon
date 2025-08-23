#!/usr/bin/env python3
"""
Test API connection for CyberWatchdog
"""

import os
from dotenv import load_dotenv
from agents.common import get_llm

load_dotenv()

def test_api_connection():
    print("🔑 Testing API Connection...")
    print("=" * 40)
    
    # Check environment variables
    groq_key = os.getenv("GROQ_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    
    print(f"Groq API Key: {'✅ Set' if groq_key and groq_key != 'your_groq_api_key_here' else '❌ Not set'}")
    print(f"OpenAI API Key: {'✅ Set' if openai_key and openai_key != 'your_openai_api_key_here' else '❌ Not set'}")
    
    # Test LLM initialization
    print("\n🤖 Testing LLM initialization...")
    try:
        llm = get_llm()
        print(f"✅ LLM initialized: {type(llm).__name__}")
        
        # Test a simple prompt
        print("\n🧪 Testing simple prompt...")
        test_prompt = "Classify this as a simple test. Return only 'TEST_OK' if you understand."
        
        try:
            response = llm.invoke(test_prompt)
            print(f"✅ API Response: {response.content[:100]}...")
            print("🎉 API connection successful!")
            return True
        except Exception as e:
            print(f"❌ API call failed: {e}")
            return False
            
    except Exception as e:
        print(f"❌ LLM initialization failed: {e}")
        return False

if __name__ == "__main__":
    test_api_connection()
