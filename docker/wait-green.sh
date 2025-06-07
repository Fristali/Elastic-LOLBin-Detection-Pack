#!/bin/bash
# Wait for Kibana to be green
set -e
TIMEOUT=120
INTERVAL=5
ELAPSED=0
KIBANA_URL="http://localhost:5601/api/status"

while [ $ELAPSED -lt $TIMEOUT ]; do
  STATUS=$(curl -s $KIBANA_URL | grep -o '"overall":{"level":"[a-z]*"' | cut -d '"' -f6)
  if [ "$STATUS" = "available" ]; then
    echo "Kibana is green."
    exit 0
  fi
  sleep $INTERVAL
  ELAPSED=$((ELAPSED + INTERVAL))
done

echo "Timed out waiting for Kibana to be green."
exit 1 