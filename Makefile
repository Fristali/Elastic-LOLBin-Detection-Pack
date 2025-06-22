# Makefile for elastic-lolbin-detection-pack

.PHONY: setup ingest dashboard test-rules clean-docker doctor secure demo gen-certs help

# Default target
help:
	@echo "Elastic LOLBin Detection Pack - Make Targets"
	@echo "============================================="
	@echo "setup        - Set up Elastic Stack with security enabled"
	@echo "demo         - Quick demo setup (security disabled)"
	@echo "secure       - Generate certificates and enable security"
	@echo "doctor       - Run pre-flight system checks"
	@echo "ingest       - Generate and ingest logs (use FULL=1 for full scale)"
	@echo "dashboard    - Import Kibana dashboards"
	@echo "test-rules   - Run Sigma rule tests"
	@echo "test-int     - Run integration tests"
	@echo "clean-docker - Stop and remove all containers and volumes"
	@echo "gen-certs    - Generate self-signed certificates"
	@echo "help         - Show this help message"

doctor:
	@echo "[doctor] Running pre-flight system checks..."
	@if command -v pwsh >/dev/null 2>&1; then \
		pwsh -File scripts/doctor.ps1; \
	elif command -v powershell >/dev/null 2>&1; then \
		powershell -File scripts/doctor.ps1; \
	else \
		echo "PowerShell not found. Please install PowerShell 7+"; \
		exit 1; \
	fi

gen-certs:
	@echo "[gen-certs] Generating self-signed certificates..."
	@mkdir -p certs
	@if command -v pwsh >/dev/null 2>&1; then \
		pwsh -File scripts/gen_certs.ps1; \
	elif command -v powershell >/dev/null 2>&1; then \
		powershell -File scripts/gen_certs.ps1; \
	else \
		openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout certs/elasticsearch.key -out certs/elasticsearch.crt \
		-subj "/C=US/ST=State/L=City/O=Organization/CN=elasticsearch"; \
		cp certs/elasticsearch.crt certs/ca.crt; \
	fi

secure: gen-certs
	@echo "[secure] Setting up secure mode with TLS..."
	@if [ ! -f .env ]; then \
		echo "Copying env-example to .env..."; \
		cp env-example .env; \
	fi
	@echo "Please edit .env file with your secure passwords and keys"
	@echo "Then run: make setup"

setup: doctor
	@echo "[setup] Setting up Elastic Stack..."
	@if [ ! -f .env ]; then \
		echo "Warning: .env file not found. Using defaults."; \
		echo "Run 'make secure' for production setup."; \
	fi
	@cd docker && docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 30
	@echo "Setting up index template..."
	@curl -X PUT -H "Content-Type: application/json" \
		-u $${ELASTIC_USERNAME:-elastic}:$${ELASTIC_PASSWORD:-changeme} \
		http://localhost:9200/_index_template/logs-lolbin \
		-d @docker/index_template.json || true

demo:
	@echo "[demo] Setting up demo mode (security disabled)..."
	@export DEMO_MODE=true ELASTIC_SECURITY_ENABLED=false ELASTIC_TLS_ENABLED=false
	@cd docker && docker-compose up -d
	@echo "Demo mode started. Access Kibana at http://localhost:5601"

ingest:
	@echo "[ingest] Generating and ingesting logs..."
	@mkdir -p logs
	@if [ "$$FULL" = "1" ]; then \
		echo "Running full-scale simulation (30M events)..."; \
		bash scripts/full_runner.sh; \
	else \
		echo "Running mini simulation (10k events)..."; \
		bash scripts/mini_runner.sh; \
	fi
	@echo "Building and running Logstash pipeline..."
	@cd docker && docker build -f Dockerfile.logstash -t lolbin-logstash .
	@cd docker && docker run --rm --network elastic-lolbin-detection-pack_elastic \
		-v $(PWD)/logs:/usr/share/logstash/logs:ro \
		-v $(PWD)/docker/logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro \
		lolbin-logstash

dashboard:
	@echo "[dashboard] Importing Kibana dashboards..."
	@sleep 5
	@curl -X POST "localhost:5601/api/saved_objects/_import" \
		-H "kbn-xsrf: true" \
		-H "Content-Type: application/json" \
		-u $${ELASTIC_USERNAME:-elastic}:$${ELASTIC_PASSWORD:-changeme} \
		--form file=@dashboards/lolbin_dashboard.ndjson || true
	@echo "Opening Kibana in browser..."
	@if command -v start >/dev/null 2>&1; then \
		start http://localhost:5601; \
	elif command -v open >/dev/null 2>&1; then \
		open http://localhost:5601; \
	elif command -v xdg-open >/dev/null 2>&1; then \
		xdg-open http://localhost:5601; \
	else \
		echo "Please open http://localhost:5601 in your browser"; \
	fi

test-rules:
	@echo "[test-rules] Running Sigma rule tests..."
	@python -m pytest tests/test_sigma_to_eql.py -v

test-int:
	@echo "[test-int] Running integration tests..."
	@RUN_INTEGRATION_TESTS=1 python -m pytest tests/ -v -m integration

test: test-rules
	@echo "[test] Running all tests..."
	@python -m pytest tests/ -v --cov=. --cov-report=html

clean-docker:
	@echo "[clean-docker] Stopping and removing containers and volumes..."
	@cd docker && docker-compose down -v
	@docker system prune -f
	@docker volume prune -f
	@echo "All containers and volumes removed"

logs-clean:
	@echo "[logs-clean] Cleaning generated log files..."
	@rm -rf logs/*.ndjson
	@echo "Log files cleaned"

reset: clean-docker logs-clean
	@echo "[reset] Complete reset of environment..."
	@rm -rf certs/
	@echo "Environment reset complete" 