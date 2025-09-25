#!/bin/bash

printf "================================= Starting Caddy Server =================================\n"
caddy start --config /app/Caddyfile

printf "\n================================== Starting API Server ==================================\n"
uv run pylint app.py src/ > /logs/omni.lint      

uv run uvicorn app:app --host 0.0.0.0 --port 8000
