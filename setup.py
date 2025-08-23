#!/usr/bin/env python3
"""
CyberWatchdog Setup Script
Helps users set up the project with proper dependencies and configuration.
"""

import os
import sys
import subprocess
import shutil

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        sys.exit(1)

def create_env_file():
    """Create .env file if it doesn't exist"""
    env_file = ".env"
    if not os.path.exists(env_file):
        print("🔧 Creating .env file...")
        with open(env_file, "w") as f:
            f.write("# CyberWatchdog Environment Variables\n")
            f.write("# Add your API keys here\n\n")
            f.write("# LLM API Keys (optional - demo mode available)\n")
            f.write("GROQ_API_KEY=your_groq_api_key_here\n")
            f.write("OPENAI_API_KEY=your_openai_api_key_here\n\n")
            f.write("# Optional Configuration\n")
            f.write("LOG_LEVEL=INFO\n")
        print("✅ .env file created")
    else:
        print("✅ .env file already exists")

def check_data_file():
    """Check if data file exists"""
    data_file = "data/network_traffic_logs.csv"
    if os.path.exists(data_file):
        print("✅ Data file found")
    else:
        print("⚠️  Data file not found. Please ensure data/network_traffic_logs.csv exists")

def main():
    """Main setup function"""
    print("🛡️ CyberWatchdog Setup")
    print("=" * 40)
    
    check_python_version()
    install_dependencies()
    create_env_file()
    check_data_file()
    
    print("\n🎉 Setup complete!")
    print("\nNext steps:")
    print("1. Add your API keys to the .env file (optional)")
    print("2. Run: streamlit run main.py")
    print("3. Open your browser to the displayed URL")
    print("\nFor more information, see README.md")

if __name__ == "__main__":
    main()
