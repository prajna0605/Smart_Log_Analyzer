#!/bin/bash

# Synthesize initial dataset if data/logs.csv does not exist
if [ ! -f "data/logs.csv" ]; then
    echo "Generating initial synthetic dataset..."
    python backend/synthesizer.py
fi

# Start FastAPI backend in background
echo "Starting FastAPI Backend Server on port 8000..."
uvicorn backend.main:app --host 0.0.0.0 --port 8000 &

# Wait for backend startup
sleep 3

# Start Streamlit frontend in foreground
echo "Starting Streamlit Frontend Dashboard on port 8501..."
streamlit run frontend/app.py --server.port 8501 --server.address 0.0.0.0
