#!/bin/bash
cd "$(dirname "$0")/backend"
uvicorn app:app --host 0.0.0.0 --port 9000

