#!/bin/bash
set -e
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt -q

if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
fi

python main.py
