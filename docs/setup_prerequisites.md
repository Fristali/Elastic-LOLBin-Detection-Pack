# Setup Prerequisites

## System Requirements

### Operating System Support
- **Windows**: Windows 10/11 with WSL2 or Windows Server 2019+
- **macOS**: macOS 10.15+ (Intel/Apple Silicon)
- **Linux**: Ubuntu 20.04+, CentOS 8+, or equivalent

### Hardware Requirements

#### Minimum (Demo Mode)
- **CPU**: 2 cores, 2.5GHz+
- **RAM**: 4GB available
- **Storage**: 20GB free space
- **Network**: Broadband internet connection

#### Recommended (Production Mode)
- **CPU**: 4+ cores, 3.0GHz+
- **RAM**: 8GB+ available
- **Storage**: 100GB+ SSD storage
- **Network**: Low-latency network connection

#### Full Scale Simulation
- **CPU**: 8+ cores, 3.5GHz+
- **RAM**: 16GB+ available
- **Storage**: 500GB+ NVMe SSD
- **Network**: High-bandwidth connection

## Software Dependencies

### Core Requirements

#### Docker & Container Runtime
```powershell
# Windows (PowerShell as Administrator)
# Install Docker Desktop for Windows
winget install Docker.DockerDesktop

# Verify installation
docker --version
docker-compose --version
```

```bash
# Linux (Ubuntu/Debian)
sudo apt update
sudo apt install docker.io docker-compose
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Verify installation
docker --version
docker-compose --version
```

```bash
# macOS (using Homebrew)
brew install docker docker-compose
# Or install Docker Desktop from https://docker.com

# Verify installation
docker --version
docker-compose --version
```

#### Python 3.8+
```powershell
# Windows
winget install Python.Python.3.11

# Verify installation
python --version
pip --version
```

```bash
# Linux (Ubuntu/Debian)
sudo apt install python3 python3-pip python3-venv

# Verify installation
python3 --version
pip3 --version
```

#### Git
```powershell
# Windows
winget install Git.Git

# Verify installation
git --version
```

#### PowerShell 7+ (Windows)
```powershell
# Install PowerShell 7
winget install Microsoft.PowerShell

# Verify installation
pwsh --version
```

### Python Dependencies
```bash
# Install required Python packages
pip install -r requirements.txt

# Or install individually:
pip install pytest
pip install sigma-cli
pip install docker
pip install pyyaml
pip install requests
```

## Network Configuration

### Required Ports
| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| Elasticsearch | 9200 | TCP | HTTP API |
| Elasticsearch | 9300 | TCP | Node Communication |
| Kibana | 5601 | TCP | Web Interface |
| Logstash | 5044 | TCP | Beats Input |
| Filebeat | 6060 | TCP | Monitoring |

### Firewall Configuration
```powershell
# Windows Firewall (PowerShell as Administrator)
New-NetFirewallRule -DisplayName "Elasticsearch HTTP" -Direction Inbound -Port 9200 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kibana Web" -Direction Inbound -Port 5601 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Logstash Beats" -Direction Inbound -Port 5044 -Protocol TCP -Action Allow
```

```bash
# Linux (Ubuntu/Debian with ufw)
sudo ufw allow 9200/tcp
sudo ufw allow 5601/tcp
sudo ufw allow 5044/tcp
sudo ufw reload
```

## Environment Variables

### Required Environment Variables
Create a `.env` file in the project root with the following variables:

```bash
# Elasticsearch Configuration
ELASTIC_VERSION=8.13.4
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=your_secure_password_here
ELASTIC_CLUSTER_NAME=lolbin-cluster

# Security Configuration
ELASTIC_SECURITY_ENABLED=true
ELASTIC_TLS_ENABLED=true
ELASTIC_CERT_PATH=./certs
ELASTIC_CA_PASSWORD=your_ca_password_here

# Kibana Configuration
KIBANA_ENCRYPTION_KEY=your_32_character_encryption_key
KIBANA_SECURITY_ENABLED=true

# Logstash Configuration
LOGSTASH_MONITORING_ENABLED=true

# Alerting Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
ALERT_EMAIL=security@yourcompany.com

# Resource Limits
ES_JAVA_OPTS=-Xms2g -Xmx2g
LS_JAVA_OPTS=-Xms1g -Xmx1g

# Demo Mode (Optional)
DEMO_MODE=false
SKIP_SECURITY=false
```

### Environment Variable Descriptions

#### Security Settings
- **ELASTIC_PASSWORD**: Strong password for Elasticsearch superuser (minimum 12 characters)
- **KIBANA_ENCRYPTION_KEY**: 32-character key for Kibana encryption
- **ELASTIC_CA_PASSWORD**: Password for certificate authority

#### Performance Tuning
- **ES_JAVA_OPTS**: JVM heap size for Elasticsearch (50% of available RAM max)
- **LS_JAVA_OPTS**: JVM heap size for Logstash

#### Integration Settings
- **SLACK_WEBHOOK_URL**: Webhook URL for Slack alerting integration
- **ALERT_EMAIL**: Email address for alert notifications

## Pre-Installation Checklist

### System Preparation
- [ ] Verify OS compatibility and version
- [ ] Ensure adequate hardware resources
- [ ] Check available disk space (minimum 20GB)
- [ ] Verify network connectivity and port availability
- [ ] Install Docker and Docker Compose
- [ ] Install Python 3.8+ and pip
- [ ] Install Git for repository cloning
- [ ] Install PowerShell 7+ (Windows only)

### Security Preparation
- [ ] Generate strong passwords for all services
- [ ] Create service certificates or plan for auto-generation
- [ ] Configure firewall rules for required ports
- [ ] Set up secure environment variable storage
- [ ] Plan backup and recovery procedures

### Integration Preparation
- [ ] Obtain Slack webhook URL (if using alerting)
- [ ] Configure email server settings (if using email alerts)
- [ ] Plan SIEM integration endpoints (if applicable)
- [ ] Prepare threat intelligence feed URLs (if applicable)

## Installation Validation

### Quick System Check
Run the built-in doctor script to validate your system:

```powershell
# Windows PowerShell
.\scripts\doctor.ps1

# Expected output:
# ✓ Docker Engine running
# ✓ Docker Compose available
# ✓ Python 3.8+ installed
# ✓ Required ports available
# ✓ Sufficient RAM (4GB+)
# ✓ Sufficient disk space (20GB+)
# ✓ Environment variables configured
```

### Manual Verification
```bash
# Check Docker
docker run hello-world

# Check Docker Compose
docker-compose --version

# Check Python
python --version

# Check available resources
docker system info | grep -E "(CPUs|Total Memory)"

# Check port availability
netstat -tuln | grep -E ":9200|:5601|:5044"
```

## Troubleshooting Common Issues

### Docker Issues
- **Docker daemon not running**: Start Docker Desktop or service
- **Permission denied**: Add user to docker group (Linux)
- **Port conflicts**: Check for services using required ports

### Resource Issues
- **Insufficient memory**: Elasticsearch requires minimum 2GB heap
- **Disk space**: Ensure adequate space for logs and indices
- **CPU constraints**: Monitor CPU usage during full-scale simulation

### Network Issues
- **Port binding failures**: Check firewall and existing services
- **DNS resolution**: Ensure proper hostname resolution
- **Certificate errors**: Verify certificate generation and paths

## Next Steps

After completing the prerequisites:

1. **Clone Repository**: `git clone <repository-url>`
2. **Configure Environment**: Copy `.env.example` to `.env` and customize
3. **Run Doctor Script**: `.\scripts\doctor.ps1` (Windows) or `./scripts/doctor.sh` (Linux/macOS)
4. **Start Installation**: `make setup`

For detailed installation instructions, see the main [README.md](../README.md) file. 