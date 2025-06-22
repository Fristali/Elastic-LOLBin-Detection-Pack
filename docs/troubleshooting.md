# Troubleshooting Guide

## Common Issues and Solutions

### Docker and Container Issues

#### Docker Daemon Not Running
**Symptoms**: `Cannot connect to the Docker daemon` error

**Solutions**:
```powershell
# Windows - Start Docker Desktop
Start-Process "Docker Desktop"

# Check Docker service status
Get-Service -Name "Docker Desktop Service"

# Restart Docker service if needed
Restart-Service -Name "Docker Desktop Service"
```

```bash
# Linux - Start Docker daemon
sudo systemctl start docker
sudo systemctl enable docker

# Check Docker status
sudo systemctl status docker
```

#### Port Conflicts
**Symptoms**: `Port already in use` or `bind: address already in use`

**Diagnosis**:
```powershell
# Windows - Check what's using the port
netstat -ano | findstr ":9200"
netstat -ano | findstr ":5601"

# Kill process using the port (replace PID)
taskkill /PID <process_id> /F
```

```bash
# Linux/macOS - Check port usage
sudo lsof -i :9200
sudo lsof -i :5601
sudo lsof -i :5044

# Kill process using port
sudo kill -9 <process_id>
```

**Solutions**:
1. Stop conflicting services
2. Change port mapping in `docker-compose.yml`
3. Use different ports in `.env` configuration

#### Container Health Check Failures
**Symptoms**: Containers showing `unhealthy` status

**Diagnosis**:
```bash
# Check container logs
docker logs elasticsearch
docker logs kibana
docker logs logstash

# Check container health
docker inspect elasticsearch --format='{{.State.Health}}'
```

**Solutions**:
```bash
# Restart unhealthy containers
docker restart elasticsearch kibana logstash

# Increase health check timeout in docker-compose.yml
# Verify services are accessible on their ports
curl -f http://localhost:9200/_cluster/health
curl -f http://localhost:5601/api/status
```

### Elasticsearch Issues

#### Elasticsearch Won't Start
**Symptoms**: Container exits immediately or fails health checks

**Common Causes & Solutions**:

1. **Insufficient Memory**:
```bash
# Check available memory
free -h  # Linux
Get-ComputerInfo -Property TotalPhysicalMemory  # Windows

# Reduce heap size in .env
ES_JAVA_OPTS=-Xms1g -Xmx1g
```

2. **Virtual Memory Settings (Linux)**:
```bash
# Check current setting
cat /proc/sys/vm/max_map_count

# Temporarily increase (requires root)
sudo sysctl -w vm.max_map_count=262144

# Permanently increase
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

3. **File Permissions**:
```bash
# Fix data directory permissions
sudo chown -R 1000:1000 ./data/elasticsearch
sudo chmod -R 755 ./data/elasticsearch
```

#### Elasticsearch Cluster Yellow/Red Status
**Symptoms**: Cluster health shows yellow or red status

**Diagnosis**:
```bash
# Check cluster health
curl "localhost:9200/_cluster/health?pretty"

# Check node status
curl "localhost:9200/_cat/nodes?v"

# Check index status
curl "localhost:9200/_cat/indices?v"
```

**Solutions**:
```bash
# For single-node setup, update index settings
curl -X PUT "localhost:9200/_settings" -H 'Content-Type: application/json' -d'
{
  "index.number_of_replicas": 0
}'

# Delete problematic indices if needed
curl -X DELETE "localhost:9200/problem-index-name"
```

### Kibana Issues

#### Kibana Not Accessible
**Symptoms**: Browser shows "This site can't be reached" or timeouts

**Diagnosis**:
```bash
# Check if Kibana container is running
docker ps | grep kibana

# Check Kibana logs
docker logs kibana

# Test connectivity
curl http://localhost:5601/api/status
```

**Solutions**:
1. **Wait for Elasticsearch**: Kibana requires Elasticsearch to be healthy first
2. **Check firewall**: Ensure port 5601 is open
3. **Browser cache**: Clear browser cache and cookies
4. **Network mode**: If using WSL2, try accessing via WSL2 IP

#### Kibana Security Configuration Issues
**Symptoms**: Authentication loops or access denied errors

**Solutions**:
```bash
# Reset Kibana data
docker-compose down
docker volume rm elastic-lolbin-detection-pack_kibana_data
docker-compose up -d

# Check Kibana configuration
docker exec kibana cat /usr/share/kibana/config/kibana.yml
```

### Logstash Issues

#### Logstash Pipeline Failures
**Symptoms**: No data appearing in Elasticsearch

**Diagnosis**:
```bash
# Check Logstash logs
docker logs logstash

# Check pipeline status
curl "localhost:9600/_node/stats/pipelines?pretty"

# Verify input files exist
ls -la logs/*.ndjson
```

**Solutions**:
1. **File permissions**: Ensure Logstash can read log files
```bash
sudo chmod 644 logs/*.ndjson
```

2. **File path mapping**: Check volume mounts in docker-compose.yml
3. **Pipeline configuration**: Validate logstash.conf syntax

#### Slow Logstash Performance
**Symptoms**: Very slow log ingestion rates

**Solutions**:
```bash
# Increase Logstash heap size
LS_JAVA_OPTS=-Xms2g -Xmx2g

# Optimize pipeline settings
pipeline.workers: 4
pipeline.batch.size: 1000
```

### Authentication and Security Issues

#### Default Password Rejection
**Symptoms**: Elasticsearch rejects default passwords

**Solutions**:
```bash
# Set new password for elastic user
docker exec -it elasticsearch /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic

# Update .env file with new password
ELASTIC_PASSWORD=new_secure_password
```

#### Certificate Issues
**Symptoms**: TLS/SSL connection errors

**Diagnosis**:
```bash
# Check certificate files
ls -la certs/

# Test TLS connection
openssl s_client -connect localhost:9200 -servername localhost
```

**Solutions**:
```bash
# Regenerate certificates
./scripts/gen_certs.ps1  # Windows
./scripts/gen_certs.sh   # Linux/macOS

# Update certificate permissions
chmod 644 certs/*.crt
chmod 600 certs/*.key
```

### Log Generation Issues

#### Python Script Failures
**Symptoms**: Log generation script crashes or produces no output

**Diagnosis**:
```bash
# Check Python version
python --version

# Test script with mini mode
python scripts/generate_logs.py --mini

# Check disk space
df -h  # Linux/macOS
Get-PSDrive -PSProvider FileSystem  # Windows
```

**Solutions**:
1. **Install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Disk space**: Ensure adequate space for log files
3. **Permissions**: Check write permissions to logs/ directory

#### Stagnant Log Generation
**Symptoms**: Script appears hung during full-scale generation

**Solutions**:
```bash
# Use mini mode for testing
python scripts/generate_logs.py --mini

# Monitor progress
tail -f logs/host-01.ndjson

# Check system resources
top  # Linux/macOS
Get-Process | Sort-Object CPU -Descending  # Windows
```

### Data Ingestion Issues

#### No Data in Elasticsearch
**Symptoms**: Empty indices or no search results

**Diagnosis**:
```bash
# Check if indices exist
curl "localhost:9200/_cat/indices?v"

# Check document count
curl "localhost:9200/logs-lolbin-*/_count"

# Search for recent documents
curl "localhost:9200/logs-lolbin-*/_search?size=1&sort=@timestamp:desc"
```

**Solutions**:
1. **Re-run ingestion**: `make ingest`
2. **Check Logstash**: Verify pipeline is processing files
3. **Index template**: Ensure template is correctly applied

### Performance Issues

#### High Memory Usage
**Symptoms**: System becomes slow or unresponsive

**Solutions**:
```bash
# Reduce heap sizes in .env
ES_JAVA_OPTS=-Xms1g -Xmx1g
LS_JAVA_OPTS=-Xms512m -Xmx512m

# Use mini mode for testing
MINI=1 make ingest

# Monitor memory usage
docker stats
```

#### Slow Query Performance
**Symptoms**: Dashboard loading slowly or timeouts

**Solutions**:
1. **Reduce time range**: Use shorter time windows in Kibana
2. **Add more RAM**: Increase system memory
3. **Optimize queries**: Use more specific filters
4. **Index optimization**: Force merge indices

### Testing Issues

#### Pytest Failures
**Symptoms**: Tests fail with import or connection errors

**Diagnosis**:
```bash
# Run tests with verbose output
python -m pytest tests/ -v -s

# Check test environment
python -c "import pytest, docker, yaml; print('Dependencies OK')"
```

**Solutions**:
```bash
# Install test dependencies
pip install pytest docker pyyaml requests

# Skip integration tests if needed
python -m pytest tests/ -m "not integration"

# Run specific test file
python -m pytest tests/test_sigma_to_eql.py -v
```

### Dashboard and Visualization Issues

#### Dashboard Import Failures
**Symptoms**: `make dashboard` fails or dashboards don't appear

**Solutions**:
```bash
# Wait for Kibana to be ready
curl http://localhost:5601/api/status

# Manually import dashboard
curl -X POST "localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  --form file=@dashboards/lolbin_dashboard.ndjson
```

#### Missing Data in Dashboards
**Symptoms**: Empty visualizations or "No results found"

**Solutions**:
1. **Check time range**: Ensure time picker covers data period
2. **Verify data exists**: Use Discover tab to search for data
3. **Index patterns**: Ensure index patterns match actual indices
4. **Refresh**: Force refresh of visualizations

## Advanced Debugging

### Enable Debug Logging
```bash
# Elasticsearch debug logs
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "transient": {
    "logger.org.elasticsearch": "DEBUG"
  }
}'

# Logstash debug mode
# Add to logstash.yml:
log.level: debug
```

### Container Debugging
```bash
# Access container shell
docker exec -it elasticsearch /bin/bash
docker exec -it kibana /bin/bash
docker exec -it logstash /bin/bash

# Check container resource usage
docker stats --no-stream

# Inspect container configuration
docker inspect elasticsearch
```

### Network Debugging
```bash
# Test container-to-container communication
docker exec kibana curl elasticsearch:9200/_cluster/health

# Check Docker networks
docker network ls
docker network inspect elastic-lolbin-detection-pack_default
```

## Getting Help

### Log Collection
When seeking help, collect the following information:

```bash
# System information
docker --version
docker-compose --version
python --version

# Container status
docker ps -a

# Recent logs (last 100 lines)
docker logs --tail 100 elasticsearch > es_logs.txt
docker logs --tail 100 kibana > kibana_logs.txt
docker logs --tail 100 logstash > logstash_logs.txt

# Cluster status
curl "localhost:9200/_cluster/health?pretty" > cluster_health.json

# System resources
docker system df
```

### Support Channels
- **GitHub Issues**: Submit bug reports with log files
- **Documentation**: Check [docs/](../docs/) directory for additional guides
- **Community**: Elastic community forums for Elastic Stack issues

### Emergency Recovery
If the system is completely broken:

```bash
# Nuclear option - complete reset
docker-compose down -v
docker system prune -a
rm -rf logs/* data/*
make setup
```

**Note**: This will delete all data and require complete re-ingestion. 