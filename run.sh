#!/bin/bash

# CyberWatchdog Quick Start Script
echo "🛡️ Starting CyberWatchdog..."

# Activate conda environment
source ~/miniconda3/etc/profile.d/conda.sh
conda activate cyberwatchdog

# Check if environment is activated
if [[ "$CONDA_DEFAULT_ENV" != "cyberwatchdog" ]]; then
    echo "❌ Failed to activate cyberwatchdog environment"
    exit 1
fi

echo "✅ Environment activated: $CONDA_DEFAULT_ENV"

# Run the application
echo "🚀 Starting Streamlit application..."
streamlit run main.py
