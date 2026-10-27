#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
echo
echo "Starting Sentinel DLP at http://127.0.0.1:8000"
echo "Open http://127.0.0.1:8000/docs for API testing."
exec uvicorn main:app --host 127.0.0.1 --port 8000
