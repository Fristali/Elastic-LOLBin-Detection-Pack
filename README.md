# elastic-lolbin-detection-pack

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Quick-Start TL;DR

```bash
git clone <https://github.com/Fristali/Elastic-LOLBin>
cd elastic-lolbin-detection-pack
make setup          # pulls Docker images, installs python deps, builds test data
make ingest         # loads mock logs into Elasticsearch
make dashboard      # imports Kibana objects & opens browser
make test-rules     # runs sigmac & pytest harness
```

---

## Project Story

- Designed and implemented a scalable LOLBin detection simulation using Elastic Stack, Sigma, and YARA.
- Demonstrated realistic detection at 30M events/day, with mini/full simulation modes for resource efficiency.
- Automated CI/CD, rule conversion, and test harness for robust detection engineering workflows.
- Provided MITRE ATT&CK mapping and advanced threat hunting integrations (EQL, YARA).

---

## Architecture Diagram

```
+-------------------+      +-------------------+      +-------------------+
|  Log Generator    | ---> |   Logstash        | ---> |  Elasticsearch    |
| (Python, NDJSON)  |      | (Pipeline, Tag)   |      |  (ECS, Index)     |
+-------------------+      +-------------------+      +-------------------+
        |                        |                        |
        v                        v                        v
   Sigma Rules             YARA/EQL                Kibana Dashboards
```

---

## How Scale Simulation Works

- The log generator streams up to 30 million events/day, with 90% benign, 9% near-miss, and 1% true attacks.
- Mini mode (10k events) enables fast local testing; full mode demonstrates realistic scale.
- File rotation and per-host NDJSON output ensure efficient ingestion and demo.
- Adaptability: The pipeline can ingest real endpoint logs if you adjust the logstash input and mapping to match your data format.

---

## Known Limitations / Next Steps

- No real endpoint telemetry; all data is synthetic.
- YARA/EQL integration is stubbed (not live-scanning).
- Next: Add SOAR/Jira integration, more MITRE coverage, and real-time alerting.

---

## Intended Use

- Demonstration of detection engineering and Elastic pipeline configuration
- Educational and interview prep for detection engineering roles
- Not intended for production use without further adaptation

---

## Phase Progress

- [x] Phase 0: Pre-flight & Tooling
- [x] Phase 1: Elastic Stack Up
- [x] Phase 2: Mock Log Generator
- [x] Phase 3: Ingestion Pipeline
- [x] Phase 4: Sigma Rules
- [x] Phase 5: Rule Testing & CI
- [x] Phase 6: Kibana Dashboard
- [x] Phase 7: Docs & Polish 