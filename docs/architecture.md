# Architecture

## Overview

The Elastic LOLBin Detection Pack is a comprehensive cybersecurity simulation platform designed to demonstrate realistic LOLBin (Living off the Land Binaries) detection capabilities using the Elastic Stack, Sigma rules, YARA scanning, and automated alerting.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            ELASTIC LOLBIN DETECTION PACK                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐            │
│  │  Log Generator  │───▶│    Logstash     │───▶│ Elasticsearch   │            │
│  │ (Python NDJSON) │    │ (Pipeline/Tag)  │    │  (ECS Index)    │            │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘            │
│           │                       │                       │                    │
│           ▼                       ▼                       ▼                    │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐            │
│  │   Sigma Rules   │    │   YARA Rules    │    │ Kibana Dashboard │            │
│  │   Detection     │    │   Binary Scan   │    │  Visualization  │            │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘            │
│           │                       │                       │                    │
│           ▼                       ▼                       ▼                    │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐            │
│  │  ElastAlert2    │    │   Filebeat      │    │   EQL Queries   │            │
│  │   Alerting      │    │ Log Collection  │    │ Threat Hunting  │            │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘            │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Data Generation Layer
- **Log Generator (`scripts/generate_logs.py`)**: Creates synthetic Windows process execution logs
- **Scale Modes**: Mini (10k events) for testing, Full (30M events) for realistic simulation
- **Attack Simulation**: 90% benign, 9% near-miss, 1% true LOLBin attacks
- **Output Format**: NDJSON files per host with ECS-compatible fields

### 2. Data Processing Pipeline
- **Logstash**: Ingests NDJSON logs, applies ECS field normalization
- **Index Templates**: Pre-configured Elasticsearch mappings for optimal performance
- **Data Streams**: Modern Elasticsearch indexing with automatic rollover

### 3. Storage & Search
- **Elasticsearch**: Primary data store with security and TLS enabled
- **Index Strategy**: Time-based data streams (`logs-lolbin-*`)
- **Field Mapping**: ECS-compliant schema for interoperability

### 4. Detection & Analytics
- **Sigma Rules**: MITRE ATT&CK mapped detection rules converted to ES-QL
- **YARA Rules**: Binary pattern scanning for file-based detection
- **EQL Queries**: Advanced threat hunting and correlation queries
- **Custom Dashboards**: Pre-built Kibana visualizations and analytics

### 5. Alerting & Response
- **ElastAlert2**: Real-time alerting engine with Slack integration
- **Alert Types**: Threshold, frequency, and spike detection
- **SOAR Integration**: Webhook-based integration points for external systems

### 6. Monitoring & Observability
- **Filebeat**: Log shipping and centralized collection
- **Health Checks**: Automated service health monitoring
- **Log Rotation**: Automated cleanup and archival policies

## Data Flow

### 1. Log Generation
```
scripts/generate_logs.py → logs/*.ndjson
├── Benign: calc.exe, notepad.exe, explorer.exe
├── Near-miss: powershell.exe -nop, certutil.exe -decode
└── Attacks: powershell.exe -enc, certutil.exe -urlcache, wmiprvse.exe spawn
```

### 2. Processing Pipeline
```
Logstash Input → Filter → Output
├── Input: File input from logs/*.ndjson
├── Filter: Attack tagging, ECS field normalization
└── Output: Elasticsearch data streams
```

### 3. Detection Workflow
```
Elasticsearch Index → Sigma Rules → ElastAlert2 → Slack/SOAR
├── Real-time: ElastAlert2 monitors for rule matches
├── Batch: Scheduled Sigma rule execution
└── Manual: EQL threat hunting queries
```

## Security Architecture

### Authentication & Authorization
- **Built-in Security**: Elasticsearch security features enabled
- **TLS Encryption**: End-to-end encrypted communication
- **Role-Based Access**: Kibana user roles and permissions
- **API Keys**: Secure service-to-service authentication

### Network Security
- **Internal Networks**: Docker bridge networks for service isolation
- **Port Exposure**: Minimal external port exposure
- **Certificate Management**: Automated self-signed certificate generation

### Data Protection
- **Encryption at Rest**: Elasticsearch index encryption
- **Encryption in Transit**: TLS for all communications
- **Audit Logging**: Security event tracking and retention

## Deployment Modes

### Demo Mode (Default)
- Security disabled for easy demonstration
- Default credentials for quick setup
- Minimal resource requirements
- Ideal for training and education

### Production Mode
- Full security stack enabled
- Custom certificates and credentials
- Enhanced monitoring and alerting
- Suitable for realistic testing environments

## Sigma Rule Conversion

Sigma rules in `rules/` are converted to Elasticsearch Query DSL using `sigmac` with the custom configuration in `sigma_config.yml`. The conversion process:

1. **Field Mapping**: Maps Sigma fields to ECS schema
2. **Query Generation**: Converts detection logic to ES-QL
3. **Rule Storage**: Saves converted rules to `rules/es/`
4. **Testing**: Validates rules against known data sets

## Performance Characteristics

### Ingestion Rates
- **Mini Mode**: ~1k events/second
- **Full Mode**: ~10k events/second sustained
- **Retention**: 30 days default, configurable

### Resource Requirements
- **Minimum**: 4GB RAM, 2 CPU cores
- **Recommended**: 8GB RAM, 4 CPU cores
- **Storage**: 10GB per million events

### Scaling Considerations
- **Horizontal**: Add Elasticsearch nodes for larger datasets
- **Vertical**: Increase heap size for faster queries
- **Sharding**: Configure based on expected data volume

## Integration Points

### External Systems
- **SIEM Integration**: Syslog output for external SIEM systems
- **SOAR Platforms**: Webhook-based alert forwarding
- **Threat Intelligence**: API endpoints for IOC enrichment

### Development Workflow
- **CI/CD**: Automated testing and deployment pipelines
- **Version Control**: Git-based rule and configuration management
- **Quality Gates**: Automated testing before deployment