# elastic-lolbin-detection-pack

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)  [![Build Status](https://github.com/Fristali/Elastic-LOLBin-Detection-Pack/actions/workflows/ci.yml/badge.svg)](https://github.com/Fristali/Elastic-LOLBin-Detection-Pack/actions)  [![Coverage Status](https://coveralls.io/repos/github/Fristali/Elastic-LOLBin-Detection-Pack/badge.svg?branch=main)](https://coveralls.io/github/Fristali/Elastic-LOLBin-Detection-Pack?branch=main)

---

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/Fristali/Elastic-LOLBin-Detection-Pack.git
cd Elastic-LOLBin-Detection-Pack

# Setup environment (requires Docker & Python 3.8+)
make setup      # pulls Docker images, installs Python deps, builds test data

# Ingest sample logs into Elasticsearch
env LOAD_MODE=mini make ingest

# Import Kibana dashboards and open UI
make dashboard

# Run rule tests and unit tests
env RUN_INT=1 make test-rules
```

---

## 🎯 Project Overview

Elastic-LOLBin-Detection-Pack simulates a realistic endpoint detection pipeline for Living-Off-The-Land Binaries (LOLBins) using the Elastic Stack. It provides:

* High-volume log generation (up to 30M events/day).
* Sigma and YARA/EQL rule conversion and testing.
* Kibana dashboards for interactive analysis.
* CI/CD integration for rule validation.

Designed for educational and demonstration purposes in detection engineering.

---

## 🏗️ Architecture

```text
+---------------+    +-------------+    +---------------+    +---------+
| Log Generator | -> | Logstash    | -> | Elasticsearch | -> | Kibana  |
+---------------+    +-------------+    +---------------+    +---------+
       |                    |                  |                   
       v                    v                  v                   
   Sigma Rules         YARA/EQL Engine     Filebeat/Alerts       Dashboards
```

* **Log Generator** streams NDJSON logs in configurable benign/attack ratios.
* **Logstash** applies enrichment, tagging, and ECS mapping.
* **Elasticsearch** indexes data into ECS-compliant indices.
* **Kibana** visualizes detections via dashboards and lens.

---

## ⚙️ Features

* **Scale Simulation**: Mini (10k events) and Full (30M events) modes.
* **Sigma Rule Automation**: Converts and validates Sigma rules with Sigma-C.
* **EQL & YARA**: Example queries and file-scanning integration.
* **ElastAlert2**: Alerts to Slack/Email/PagerDuty.
* **CI/CD**: GitHub Actions with coverage, lint, and integration tests.
* **Security**: TLS, env-driven credentials, pre-flight checks.

---

## 📝 Installation Prerequisites

* **Docker Desktop** (Linux containers)
* **Python 3.8+**
* **PowerShell 7+** (for YARA scans)

**Important**: Use the pinned requirements & constraints.txt to avoid resolver errors:
```bash
pip install -r requirements.txt -c constraints.txt
```

Optional: RSAT for real endpoint data ingestion.

---

## 📂 Project Structure

```
.github/                  # GitHub workflows and issue templates
.env                      # Environment variables (not committed)
alerting/                 # ElastAlert2 configs & alerting rules
dashboards/               # Kibana dashboard exports
docker/                   # Docker Compose and service configs
docs/                     # Documentation (architecture, setup, troubleshooting)
eql/                      # EQL query examples
logs/                     # Log files and JSONL outputs
notebooks/                # Jupyter notebooks for analysis
rules/                    # Sigma rule definitions and conversions
scripts/                  # PowerShell and helper scripts (doctor, gen_certs)
src/                      # Python modules and pipeline code
tests/                    # Unit and integration tests
yara/                     # YARA rules and scan scripts

.pre-commit-config.yaml   # Pre-commit hooks configuration
env-example               # Sample environment variable definitions
LICENSE                   # MIT License
Makefile                  # Task automation via make targets
README.md                 # Project documentation
requirements.txt          # Python dependencies
sigma_config.yml          # Sigma configuration
system_prompt.md          # System prompt definitions
```

---

## 🛠️ Make Targets

* `make setup`      : Pulls Docker images, installs Python deps, builds data
* `make ingest`     : Loads simulated logs
* `make dashboard`  : Imports dashboards and opens Kibana
* `make test-rules` : Runs Sigma & pytest suites
* `make doctor`     : Pre-flight environment checks
* `make secure`     : TLS cert generation & secure stack

---

## 🔧 Testing

* **Unit Tests**: `pytest tests/ -q`
* **Integration Tests**: `RUN_INT=1 pytest tests/test_docker_stack.py`
* **Coverage**: `pytest --cov=src --cov-fail-under=90`

---

## 📜 License

MIT © Fristali

---

## 📅 Phase Progress

* [x] Phase 0: Pre-flight & Tooling
* [x] Phase 1: Elastic Stack
* [x] Phase 2: Log Generator
* [x] Phase 3: Ingestion & Indices
* [x] Phase 4: Sigma & Alerts
* [x] Phase 5: Testing & CI
* [x] Phase 6: Dashboards & Docs

---

*For full details, refer to the `docs/` directory.*