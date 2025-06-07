#!/bin/bash
set -e

mkdir -p logs
python3 scripts/generate_logs.py --mini

ls -lh logs/
echo "Mini log generation complete." 