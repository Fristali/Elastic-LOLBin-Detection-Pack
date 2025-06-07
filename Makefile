# Makefile for elastic-lolbin-detection-pack

.PHONY: setup ingest dashboard test-rules clean-docker doctor

setup:
	@echo "[setup] Bring up Elastic Stack and dependencies (stub)"

ingest:
	@echo "[ingest] Ingest mock logs into Elasticsearch"
	@if [ "$$FULL" = "1" ]; then \
	  bash scripts/full_runner.sh; \
	else \
	  bash scripts/mini_runner.sh; \
	fi
	docker build -f docker/Dockerfile.logstash -t lolbin-logstash docker/
	curl -X PUT -H "Content-Type: application/json" -u elastic:changeme \
	  http://localhost:9200/_index_template/logs-lolbin \
	  -d @docker/index_template.json || true
	docker run --rm --network host lolbin-logstash

dashboard:
	@echo "[dashboard] Import Kibana dashboards and open browser (stub)"

test-rules:
	@echo "[test-rules] Run Sigma/pytest harness"
	python -m pytest tests/ -v

clean-docker:
	@echo "[clean-docker] Teardown all Docker containers and volumes (stub)"

doctor:
	@echo "[doctor] Run pre-flight checks for Docker, RAM, and ports (stub)" 