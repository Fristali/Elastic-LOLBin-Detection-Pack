# LOLBin EQL Queries

## Overview

Event Query Language (EQL) provides powerful threat hunting capabilities for detecting LOLBin (Living off the Land Binaries) abuse patterns. This collection includes detection queries, threat hunting searches, and behavioral analytics.

## PowerShell LOLBin Detection

### Encoded Command Execution
```eql
process where process.name == "powershell.exe" and 
  process.command_line like "*-enc*" or 
  process.command_line like "*-EncodedCommand*"
```

### Base64 Encoded PowerShell
```eql
process where process.name == "powershell.exe" and 
  process.command_line regex ".*-[Ee]nc.*[A-Za-z0-9+/]{20,}.*"
```

### Hidden Window PowerShell
```eql
process where process.name == "powershell.exe" and 
  (process.command_line like "*-WindowStyle Hidden*" or 
   process.command_line like "*-w hidden*")
```

### Non-Interactive PowerShell
```eql
process where process.name == "powershell.exe" and 
  (process.command_line like "*-NonInteractive*" or 
   process.command_line like "*-noni*" or 
   process.command_line like "*-nop*")
```

### Suspicious PowerShell Downloads
```eql
process where process.name == "powershell.exe" and 
  (process.command_line like "*DownloadString*" or 
   process.command_line like "*DownloadFile*" or 
   process.command_line like "*WebClient*" or 
   process.command_line like "*Invoke-WebRequest*" or 
   process.command_line like "*wget*" or 
   process.command_line like "*curl*")
```

## Certutil LOLBin Detection

### URL Cache Downloads
```eql
process where process.name == "certutil.exe" and 
  (process.command_line like "*-urlcache*" or 
   process.command_line like "*-UrlCache*")
```

### File Splitting Operations
```eql
process where process.name == "certutil.exe" and 
  process.command_line like "*-split*"
```

### Certificate Store Manipulation
```eql
process where process.name == "certutil.exe" and 
  (process.command_line like "*-addstore*" or 
   process.command_line like "*-delstore*" or 
   process.command_line like "*-store*")
```

### Base64 Decoding
```eql
process where process.name == "certutil.exe" and 
  (process.command_line like "*-decode*" or 
   process.command_line like "*-decodehex*")
```

### Suspicious Certutil HTTP Activity
```eql
process where process.name == "certutil.exe" and 
  process.command_line regex ".*https?://.*"
```

## WMI LOLBin Detection

### WMI Process Creation
```eql
process where process.name == "wmiprvse.exe" and 
  process.command_line like "*spawn*"
```

### WMI Remote Execution
```eql
process where process.name == "wmic.exe" and 
  (process.command_line like "*process call create*" or 
   process.command_line like "*service*" or 
   process.command_line like "*/node:*")
```

### WMI Event Subscription
```eql
process where process.name == "wmic.exe" and 
  process.command_line like "*__EventFilter*"
```

## Behavioral Analytics

### Sequence: PowerShell followed by Network Activity
```eql
sequence by host.name
  [process where process.name == "powershell.exe" and 
   process.command_line like "*-enc*"]
  [network where destination.port in (80, 443, 8080, 8443)]
```

### Sequence: Certutil Download followed by Execution
```eql
sequence by host.name
  [process where process.name == "certutil.exe" and 
   process.command_line like "*-urlcache*"]
  [process where process.name != "certutil.exe"]
```

### Sequence: Multiple LOLBin Tools in Short Timeframe
```eql
sequence by host.name with maxspan=5m
  [process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe")]
  [process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe")]
  [process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe")]
```

## Process Tree Analysis

### Parent-Child Relationships
```eql
process where process.parent.name in ("cmd.exe", "explorer.exe") and 
  process.name in ("powershell.exe", "certutil.exe", "wmic.exe") and 
  process.command_line like "*http*"
```

### Unusual Parent Processes
```eql
process where process.name in ("powershell.exe", "certutil.exe") and 
  process.parent.name in ("winword.exe", "excel.exe", "outlook.exe", 
                          "acrord32.exe", "foxit reader.exe")
```

### Process Spawning Chain
```eql
process where process.name == "powershell.exe" and 
  descendant of [process where process.name in ("winword.exe", "excel.exe")]
```

## File System Activity

### LOLBin File Creation
```eql
file where file.name like "*.exe" and 
  process.name in ("powershell.exe", "certutil.exe", "bitsadmin.exe")
```

### Temporary File Creation
```eql
file where file.path like "*\\Temp\\*" and 
  process.name in ("certutil.exe", "powershell.exe") and 
  file.extension in ("exe", "dll", "bat", "ps1", "vbs")
```

### Suspicious File Extensions
```eql
file where process.name == "certutil.exe" and 
  file.extension in ("exe", "dll", "scr", "com", "pif")
```

## Network-Based Detection

### DNS Queries from LOLBin Tools
```eql
dns where process.name in ("powershell.exe", "certutil.exe", "bitsadmin.exe") and 
  not dns.question.name like "*.microsoft.com" and 
  not dns.question.name like "*.windows.com"
```

### HTTP Requests with Suspicious User Agents
```eql
network where process.name in ("powershell.exe", "certutil.exe") and 
  http.request.headers.user_agent like "*PowerShell*"
```

### Outbound Connections to Non-Standard Ports
```eql
network where process.name in ("powershell.exe", "certutil.exe", "wmic.exe") and 
  destination.port not in (80, 443, 53, 25, 110, 143, 993, 995) and 
  network.direction == "outbound"
```

## Registry Activity

### PowerShell Execution Policy Changes
```eql
registry where registry.path like "*ExecutionPolicy*" and 
  process.name in ("powershell.exe", "reg.exe", "regedit.exe")
```

### WMI Persistence Registry Modifications
```eql
registry where registry.path like "*__EventFilter*" or 
  registry.path like "*__EventConsumer*" or 
  registry.path like "*__FilterToConsumerBinding*"
```

### Suspicious Registry Autorun Entries
```eql
registry where registry.path like "*\\Run\\*" and 
  registry.data.strings like "*powershell*" and 
  registry.data.strings like "*-enc*"
```

## Time-Based Analytics

### LOLBin Activity Outside Business Hours
```eql
process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe") and 
  @timestamp.hour < 7 or @timestamp.hour > 19
```

### Weekend LOLBin Activity
```eql
process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe") and 
  @timestamp.day_of_week > 5
```

### Burst of LOLBin Activity
```eql
process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe")
| stats count(*) by host.name, process.name, bin(@timestamp, "1m")
| where count > 10
```

## Advanced Threat Hunting

### Rare LOLBin Command Line Patterns
```eql
process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe")
| rare process.command_line by host.name
```

### LOLBin Process Duration Analysis
```eql
process where process.name in ("powershell.exe", "certutil.exe") and 
  event.type == "end" and 
  process.uptime > 300000  // More than 5 minutes
```

### Cross-Host LOLBin Correlation
```eql
process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe")
| stats count(*) by process.command_line, bin(@timestamp, "5m")
| where count > 1  // Same command on multiple hosts
```

### LOLBin with Unusual Network Destinations
```eql
sequence by process.entity_id
  [process where process.name in ("powershell.exe", "certutil.exe")]
  [network where destination.ip not in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
```

## Evasion Technique Detection

### Obfuscated Command Lines
```eql
process where process.name == "powershell.exe" and 
  (process.command_line like "*`*" or 
   process.command_line like "*^*" or 
   process.command_line like "*'+'*" or 
   process.command_line regex ".*[A-Za-z]\\{.*\\}.*")
```

### Alternative Data Streams (ADS)
```eql
file where file.path like "*:*" and 
  process.name in ("powershell.exe", "certutil.exe", "wmic.exe")
```

### Living-off-the-Land with Renamed Binaries
```eql
process where process.original_file_name in ("powershell.exe", "certutil.exe", "wmic.exe") and 
  process.name != process.original_file_name
```

## Response and Enrichment

### Gather Related Process Activity
```eql
process where host.name == "HOST-01" and 
  @timestamp between ("2024-01-01T00:00:00.000Z", "2024-01-01T23:59:59.999Z") and 
  (process.name in ("powershell.exe", "certutil.exe", "wmic.exe") or 
   process.parent.name in ("powershell.exe", "certutil.exe", "wmic.exe") or 
   descendant of [process where process.name in ("powershell.exe", "certutil.exe", "wmic.exe")])
```

### Timeline Reconstruction
```eql
any where host.name == "HOST-01" and 
  @timestamp between ("2024-01-01T10:00:00.000Z", "2024-01-01T11:00:00.000Z") and 
  (process.name in ("powershell.exe", "certutil.exe", "wmic.exe") or 
   file.name like "*.exe" or 
   network.direction == "outbound")
| sort @timestamp
```

## Hunting Queries for False Positive Reduction

### Legitimate PowerShell Administration
```eql
process where process.name == "powershell.exe" and 
  process.command_line like "*Get-*" and 
  not process.command_line like "*-enc*" and 
  process.parent.name in ("explorer.exe", "cmd.exe")
```

### Legitimate Certutil Usage
```eql
process where process.name == "certutil.exe" and 
  (process.command_line like "*-verify*" or 
   process.command_line like "*-store*" or 
   process.command_line like "*-viewstore*") and 
  not process.command_line like "*http*"
```

### Whitelisted Processes by Hash
```eql
process where process.name in ("powershell.exe", "certutil.exe") and 
  process.hash.sha256 in ("known_good_hash1", "known_good_hash2")
```

## Usage Examples

### Running EQL Queries in Kibana
1. Navigate to Kibana → Security → Timelines
2. Create new timeline
3. Switch to EQL tab
4. Paste query and adjust time range
5. Execute and analyze results

### Running EQL Queries via API
```bash
curl -X POST "localhost:9200/logs-lolbin-*/_eql/search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "process where process.name == \"powershell.exe\" and process.command_line like \"*-enc*\""
  }'
```

### Automated Hunting with EQL
Create scheduled searches that run these queries hourly/daily and alert on matches above baseline thresholds.

## Best Practices

1. **Time Range Optimization**: Use appropriate time ranges to balance performance and coverage
2. **Field Normalization**: Ensure ECS field mappings are consistent across data sources
3. **False Positive Management**: Build allowlists for known-good processes and command lines
4. **Correlation**: Combine multiple weak signals into stronger detection logic
5. **Context Enrichment**: Include parent process, user, and network context in queries
6. **Performance Tuning**: Use indexed fields and avoid wildcard patterns at the beginning of strings 