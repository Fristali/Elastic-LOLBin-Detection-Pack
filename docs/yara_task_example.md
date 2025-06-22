# YARA Scanning Scheduled Task Configuration

## Overview

This document provides instructions for setting up automated YARA scanning using scheduled tasks on Windows, cron jobs on Linux/macOS, and integration with the Elastic LOLBin Detection Pack.

## Windows Scheduled Task

### PowerShell Script Setup

Create a wrapper script for the YARA scanner:

```powershell
# File: scripts/scheduled_yara_scan.ps1

param(
    [string]$LogPath = "C:\temp\yara_scan.log",
    [string]$ResultsPath = "C:\temp\yara_results.json"
)

# Set execution policy for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Change to script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

try {
    # Run YARA scan
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - Starting YARA scan" | Out-File -FilePath $LogPath -Append
    
    # Scan common directories for LOLBin abuse
    $scanTargets = @(
        "C:\Windows\System32",
        "C:\Windows\SysWOW64", 
        "C:\Users\*\AppData\Local\Temp",
        "C:\Users\*\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    
    foreach ($target in $scanTargets) {
        if (Test-Path $target) {
            "$timestamp - Scanning: $target" | Out-File -FilePath $LogPath -Append
            
            .\yara\scan_lolbins.ps1 -TargetPath $target -Recursive -OutputPath $ResultsPath -Verbose
            
            if ($LASTEXITCODE -eq 1) {
                "$timestamp - THREATS DETECTED in $target" | Out-File -FilePath $LogPath -Append
                # Send alert (implement your notification method here)
                Send-Alert -Message "YARA threats detected in $target" -Severity "High"
            }
        }
    }
    
    "$timestamp - YARA scan completed" | Out-File -FilePath $LogPath -Append
} catch {
    "$timestamp - ERROR: $($_.Exception.Message)" | Out-File -FilePath $LogPath -Append
}
```

### Task Creation via PowerShell

```powershell
# Create scheduled task for YARA scanning

# Task configuration
$TaskName = "YARALOLBinScan"
$Description = "Automated YARA scanning for LOLBin detection"
$ScriptPath = "C:\path\to\elastic-lolbin-detection-pack\scripts\scheduled_yara_scan.ps1"

# Create task action
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`""

# Create task trigger (daily at 2 AM)
$Trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"

# Create task settings
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Create task principal (run as SYSTEM for full access)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Register the task
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description $Description

Write-Host "Scheduled task '$TaskName' created successfully"
Write-Host "Task will run daily at 2:00 AM"
```

### Task Creation via XML Import

```xml
<!-- File: yara_scan_task.xml -->
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Automated YARA scanning for LOLBin detection</Description>
    <Author>Elastic LOLBin Detection Pack</Author>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-01-01T02:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\path\to\elastic-lolbin-detection-pack\scripts\scheduled_yara_scan.ps1"</Arguments>
    </Exec>
  </Actions>
</Task>
```

Import the task:
```cmd
schtasks /create /xml "yara_scan_task.xml" /tn "YARALOLBinScan"
```

## Linux/macOS Cron Job

### Cron Script Setup

```bash
#!/bin/bash
# File: scripts/scheduled_yara_scan.sh

LOG_PATH="/var/log/yara_scan.log"
RESULTS_PATH="/tmp/yara_results.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log_message() {
    echo "$(timestamp) - $1" >> "$LOG_PATH"
}

send_alert() {
    local message="$1"
    local severity="$2"
    
    # Send email alert (configure sendmail/postfix)
    echo "YARA Alert: $message" | mail -s "LOLBin Detection Alert" admin@company.com
    
    # Send to syslog
    logger -p security.warning "YARA LOLBin Detection: $message"
    
    # Send to Slack (if webhook configured)
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 YARA Alert: $message\"}" \
            "$SLACK_WEBHOOK_URL"
    fi
}

log_message "Starting YARA scan"

# Scan targets (adjust paths as needed)
SCAN_TARGETS=(
    "/usr/bin"
    "/usr/local/bin"
    "/tmp"
    "/var/tmp"
    "/home/*/Downloads"
    "/home/*/Desktop"
)

for target in "${SCAN_TARGETS[@]}"; do
    if [ -d "$target" ] || [ -f "$target" ]; then
        log_message "Scanning: $target"
        
        # Run YARA scan (assuming YARA is installed and in PATH)
        if pwsh -File ./yara/scan_lolbins.ps1 -TargetPath "$target" -Recursive -OutputPath "$RESULTS_PATH" -Verbose; then
            if [ $? -eq 1 ]; then
                log_message "THREATS DETECTED in $target"
                send_alert "YARA threats detected in $target" "High"
            fi
        else
            log_message "ERROR: YARA scan failed for $target"
        fi
    fi
done

log_message "YARA scan completed"
```

### Crontab Configuration

```bash
# Edit crontab
crontab -e

# Add YARA scan job (daily at 2 AM)
0 2 * * * /path/to/elastic-lolbin-detection-pack/scripts/scheduled_yara_scan.sh

# Weekly comprehensive scan (Sundays at 3 AM)
0 3 * * 0 /path/to/elastic-lolbin-detection-pack/scripts/weekly_yara_scan.sh

# Real-time monitoring of sensitive directories
*/15 * * * * /path/to/elastic-lolbin-detection-pack/scripts/realtime_yara_monitor.sh
```

## Integration with Elastic Stack

### Filebeat Configuration for YARA Results

```yaml
# Add to filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/yara_scan.log
    - C:\temp\yara_scan.log
  fields:
    logtype: yara_scan
    scanner: yara_lolbin
  fields_under_root: true
  
- type: log
  enabled: true
  paths:
    - /tmp/yara_results.json
    - C:\temp\yara_results.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    logtype: yara_results
    scanner: yara_lolbin
  fields_under_root: true

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_docker_metadata: ~
- add_kubernetes_metadata: ~
```

### Logstash Pipeline for YARA Data

```ruby
# Add to logstash pipeline
input {
  beats {
    port => 5044
  }
}

filter {
  if [logtype] == "yara_results" {
    # Parse YARA scan results
    mutate {
      add_tag => ["yara", "threat_detection"]
    }
    
    # Extract IOCs
    if [ThreatIntelligence][IOCs] {
      split { field => "[ThreatIntelligence][IOCs]" }
    }
    
    # Add severity mapping
    if [ScanMetadata][Statistics][TotalMatches] and [ScanMetadata][Statistics][TotalMatches] > 0 {
      mutate {
        add_field => { "alert_severity" => "high" }
        add_field => { "alert_type" => "yara_detection" }
      }
    }
  }
  
  if [logtype] == "yara_scan" {
    # Parse scan logs
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:scan_timestamp} - %{GREEDYDATA:scan_message}" }
    }
    
    if "THREATS DETECTED" in [message] {
      mutate {
        add_tag => ["threat_detected", "high_priority"]
        add_field => { "alert_severity" => "critical" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "yara-scans-%{+YYYY.MM.dd}"
  }
  
  # Send high-priority alerts to dedicated index
  if "threat_detected" in [tags] {
    elasticsearch {
      hosts => ["elasticsearch:9200"] 
      index => "security-alerts-%{+YYYY.MM.dd}"
    }
  }
}
```

## Real-time Monitoring

### PowerShell FileSystemWatcher

```powershell
# File: scripts/realtime_yara_monitor.ps1

param(
    [string[]]$WatchPaths = @("C:\Users\*\Downloads", "C:\temp"),
    [string]$YaraRulesPath = ".\yara"
)

# Create FileSystemWatcher for each path
$watchers = @()

foreach ($path in $WatchPaths) {
    if (Test-Path $path) {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $path
        $watcher.Filter = "*.*"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        
        # Event handler for file creation
        $action = {
            $file = $Event.SourceEventArgs.FullPath
            $changeType = $Event.SourceEventArgs.ChangeType
            
            if ($changeType -eq "Created" -and (Test-Path $file -PathType Leaf)) {
                # Scan new file with YARA
                Start-Sleep -Seconds 2  # Wait for file to be fully written
                
                try {
                    & .\yara\scan_lolbins.ps1 -TargetPath $file -OutputPath "realtime_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                    
                    if ($LASTEXITCODE -eq 1) {
                        Write-Host "⚠️ THREAT DETECTED: $file" -ForegroundColor Red
                        # Immediate alert
                        Send-Alert -Message "Real-time YARA detection: $file" -Severity "Critical"
                    }
                } catch {
                    Write-Warning "Error scanning $file`: $($_.Exception.Message)"
                }
            }
        }
        
        Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action $action
        $watchers += $watcher
        
        Write-Host "Monitoring: $path" -ForegroundColor Green
    }
}

Write-Host "Real-time YARA monitoring active. Press Ctrl+C to stop." -ForegroundColor Yellow

try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
} finally {
    # Cleanup
    foreach ($watcher in $watchers) {
        $watcher.EnableRaisingEvents = $false
        $watcher.Dispose()
    }
    Write-Host "Monitoring stopped." -ForegroundColor Yellow
}
```

## Alerting Configuration

### Email Notifications

```powershell
function Send-EmailAlert {
    param(
        [string]$Subject,
        [string]$Body,
        [string]$To = "security@company.com",
        [string]$From = "yara-scanner@company.com",
        [string]$SmtpServer = "smtp.company.com"
    )
    
    Send-MailMessage -To $To -From $From -Subject $Subject -Body $Body -SmtpServer $SmtpServer
}
```

### Slack Integration

```powershell
function Send-SlackAlert {
    param(
        [string]$Message,
        [string]$WebhookUrl = $env:SLACK_WEBHOOK_URL,
        [string]$Channel = "#security-alerts"
    )
    
    $payload = @{
        channel = $Channel
        username = "YARA-Scanner"
        text = $Message
        icon_emoji = ":warning:"
    } | ConvertTo-Json
    
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType "application/json"
}
```

### SOAR Integration

```powershell
function Send-SOARIncident {
    param(
        [string]$Title,
        [string]$Description,
        [hashtable]$IOCs,
        [string]$Severity = "High"
    )
    
    $incident = @{
        title = $Title
        description = $Description
        severity = $Severity
        iocs = $IOCs
        source = "YARA-Scanner"
        timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    } | ConvertTo-Json -Depth 5
    
    $headers = @{
        "Authorization" = "Bearer $env:SOAR_API_KEY"
        "Content-Type" = "application/json"
    }
    
    Invoke-RestMethod -Uri "$env:SOAR_WEBHOOK_URL/incidents" -Method Post -Body $incident -Headers $headers
}
```

## Best Practices

### Performance Optimization

1. **Exclude System Files**: Avoid scanning Windows system files that don't change
2. **File Size Limits**: Skip very large files (>100MB) to prevent timeouts
3. **Concurrent Scanning**: Use multiple YARA processes for large directories
4. **Rule Optimization**: Regularly review and optimize YARA rules for performance

### Security Considerations

1. **Privilege Escalation**: Run scheduled tasks with minimal required privileges
2. **Log Rotation**: Implement log rotation to prevent disk space issues
3. **Alert Throttling**: Prevent alert spam with rate limiting
4. **Encrypted Storage**: Store scan results securely

### Monitoring and Maintenance

1. **Health Checks**: Monitor scheduled task execution status
2. **Rule Updates**: Regularly update YARA rules for new threats
3. **Performance Metrics**: Track scan duration and resource usage
4. **False Positive Management**: Maintain allowlists for legitimate files

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure task runs with appropriate privileges
2. **YARA Not Found**: Verify YARA is installed and in system PATH
3. **PowerShell Execution Policy**: Set appropriate execution policy for scripts
4. **Network Connectivity**: Check firewall rules for alert delivery

### Debugging Commands

```powershell
# Test YARA installation
yara --version

# Test PowerShell script manually
.\yara\scan_lolbins.ps1 -TargetPath "C:\temp" -Verbose

# Check scheduled task status
Get-ScheduledTask -TaskName "YARALOLBinScan" | Get-ScheduledTaskInfo

# View task history
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-TaskScheduler/Operational"; ID=200,201}
``` 