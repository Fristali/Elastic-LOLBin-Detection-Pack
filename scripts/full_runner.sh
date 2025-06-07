#!/bin/bash
set -e

mkdir -p logs
python3 scripts/generate_logs.py --hosts 25 --total 3e7 --days 1

ls -lh logs/
echo "Full log generation complete." 