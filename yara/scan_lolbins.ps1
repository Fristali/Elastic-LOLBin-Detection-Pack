# YARA LOLBin Scanner for Elastic Detection Pack
# Scans target files/directories using YARA rules and outputs JSON results

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetPath,
    [string]$RulesPath = "./yara",
    [string]$OutputPath = "yara_scan_results.json",
    [switch]$Recursive,
    [switch]$Verbose,
    [int]$TimeoutSeconds = 300
)

# Set strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ANSI color codes
$Green = "`e[32m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Red = "`e[31m"
$Reset = "`e[0m"

# Initialize results array
$ScanResults = @()
$Statistics = @{
    TotalFiles = 0
    MatchedFiles = 0
    TotalMatches = 0
    ScanDuration = 0
    RulesLoaded = 0
    Errors = 0
}

function Write-Status {
    param([string]$Message, [string]$Color = $Blue)
    if ($Verbose) {
        Write-Host "${Color}[YARA]${Reset} $Message"
    }
}

function Write-Success {
    param([string]$Message)
    Write-Host "${Green}✓${Reset} $Message"
}

function Write-Warning {
    param([string]$Message)
    Write-Host "${Yellow}⚠${Reset} $Message"
}

function Write-Error {
    param([string]$Message)
    Write-Host "${Red}✗${Reset} $Message"
}

# Test if YARA is available
function Test-YaraAvailable {
    try {
        $null = yara --version 2>$null
        return $true
    } catch {
        return $false
    }
}

# Get all YARA rule files
function Get-YaraRules {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Error "YARA rules path not found: $Path"
        return @()
    }
    
    $ruleFiles = Get-ChildItem -Path $Path -Filter "*.yar" -Recurse
    if ($ruleFiles.Count -eq 0) {
        $ruleFiles = Get-ChildItem -Path $Path -Filter "*.yara" -Recurse
    }
    
    return $ruleFiles
}

# Validate YARA rule syntax
function Test-YaraRule {
    param([string]$RuleFile)
    
    try {
        $null = yara -c $RuleFile 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

# Get files to scan
function Get-TargetFiles {
    param([string]$Path, [bool]$Recurse)
    
    if (-not (Test-Path $Path)) {
        Write-Error "Target path not found: $Path"
        return @()
    }
    
    if (Test-Path $Path -PathType Leaf) {
        return @(Get-Item $Path)
    }
    
    # Define file extensions of interest for LOLBin detection
    $extensions = @("*.exe", "*.dll", "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js", "*.jar", "*.com", "*.scr", "*.pif")
    $files = @()
    
    foreach ($ext in $extensions) {
        if ($Recurse) {
            $files += Get-ChildItem -Path $Path -Filter $ext -Recurse -File -ErrorAction SilentlyContinue
        } else {
            $files += Get-ChildItem -Path $Path -Filter $ext -File -ErrorAction SilentlyContinue
        }
    }
    
    return $files
}

# Parse YARA output
function Parse-YaraOutput {
    param([string]$Output, [string]$FilePath)
    
    $matches = @()
    $lines = $Output -split "`n"
    
    foreach ($line in $lines) {
        $line = $line.Trim()
        if ($line -and $line -notmatch "^yara:" -and $line -notmatch "^warning:") {
            # YARA output format: rule_name file_path
            if ($line -match "^(\S+)\s+(.+)$") {
                $ruleName = $matches[1]
                $filePath = $matches[2]
                
                $matches += @{
                    RuleName = $ruleName
                    FilePath = $filePath
                    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                }
            }
        }
    }
    
    return $matches
}

# Scan single file with YARA
function Invoke-YaraScan {
    param([string]$RuleFile, [string]$TargetFile)
    
    try {
        Write-Status "Scanning $TargetFile with $(Split-Path $RuleFile -Leaf)"
        
        $startTime = Get-Date
        $result = yara $RuleFile $TargetFile 2>&1
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalMilliseconds
        
        $matches = Parse-YaraOutput -Output $result -FilePath $TargetFile
        
        if ($matches.Count -gt 0) {
            $Statistics.MatchedFiles++
            $Statistics.TotalMatches += $matches.Count
            
            Write-Success "Found $($matches.Count) matches in $TargetFile"
        }
        
        return @{
            Success = $true
            File = $TargetFile
            Rule = $RuleFile
            Matches = $matches
            Duration = $duration
            Error = $null
        }
    } catch {
        $Statistics.Errors++
        Write-Error "Error scanning $TargetFile`: $($_.Exception.Message)"
        
        return @{
            Success = $false
            File = $TargetFile
            Rule = $RuleFile
            Matches = @()
            Duration = 0
            Error = $_.Exception.Message
        }
    }
}

# Enhanced file analysis
function Get-FileAnalysis {
    param([string]$FilePath)
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        $hash = Get-FileHash $FilePath -Algorithm SHA256 -ErrorAction Stop
        
        # Try to get file version info if it's an executable
        $versionInfo = $null
        try {
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
        } catch {
            # File doesn't have version info
        }
        
        return @{
            Name = $fileInfo.Name
            FullPath = $fileInfo.FullName
            Size = $fileInfo.Length
            Extension = $fileInfo.Extension
            CreationTime = $fileInfo.CreationTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            LastWriteTime = $fileInfo.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            SHA256 = $hash.Hash
            FileVersion = if ($versionInfo) { $versionInfo.FileVersion } else { $null }
            ProductName = if ($versionInfo) { $versionInfo.ProductName } else { $null }
            CompanyName = if ($versionInfo) { $versionInfo.CompanyName } else { $null }
            Description = if ($versionInfo) { $versionInfo.FileDescription } else { $null }
        }
    } catch {
        Write-Warning "Could not analyze file: $FilePath"
        return @{
            Name = Split-Path $FilePath -Leaf
            FullPath = $FilePath
            Error = $_.Exception.Message
        }
    }
}

# Main scanning function
function Start-YaraScan {
    Write-Status "Starting YARA LOLBin scan..."
    Write-Status "Target: $TargetPath"
    Write-Status "Rules: $RulesPath"
    Write-Status "Recursive: $Recursive"
    
    $overallStartTime = Get-Date
    
    # Check YARA availability
    if (-not (Test-YaraAvailable)) {
        Write-Error "YARA is not available. Please install YARA first."
        Write-Error "Download from: https://github.com/VirusTotal/yara/releases"
        return $false
    }
    
    Write-Success "YARA is available"
    
    # Get YARA rules
    $ruleFiles = Get-YaraRules -Path $RulesPath
    if ($ruleFiles.Count -eq 0) {
        Write-Error "No YARA rules found in: $RulesPath"
        return $false
    }
    
    Write-Success "Found $($ruleFiles.Count) YARA rule files"
    $Statistics.RulesLoaded = $ruleFiles.Count
    
    # Validate rules
    $validRules = @()
    foreach ($ruleFile in $ruleFiles) {
        if (Test-YaraRule -RuleFile $ruleFile.FullName) {
            $validRules += $ruleFile
            Write-Status "Valid rule: $($ruleFile.Name)"
        } else {
            Write-Warning "Invalid rule syntax: $($ruleFile.Name)"
        }
    }
    
    if ($validRules.Count -eq 0) {
        Write-Error "No valid YARA rules found"
        return $false
    }
    
    Write-Success "Validated $($validRules.Count) rules"
    
    # Get target files
    $targetFiles = Get-TargetFiles -Path $TargetPath -Recurse $Recursive
    if ($targetFiles.Count -eq 0) {
        Write-Warning "No target files found in: $TargetPath"
        return $true
    }
    
    Write-Success "Found $($targetFiles.Count) files to scan"
    $Statistics.TotalFiles = $targetFiles.Count
    
    # Scan files
    foreach ($ruleFile in $validRules) {
        Write-Status "Using rule: $($ruleFile.Name)"
        
        foreach ($targetFile in $targetFiles) {
            $scanResult = Invoke-YaraScan -RuleFile $ruleFile.FullName -TargetFile $targetFile.FullName
            
            if ($scanResult.Matches.Count -gt 0) {
                # Add file analysis for matched files
                $fileAnalysis = Get-FileAnalysis -FilePath $targetFile.FullName
                
                $ScanResults += @{
                    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                    RuleFile = $ruleFile.Name
                    File = $fileAnalysis
                    Matches = $scanResult.Matches
                    ScanDuration = $scanResult.Duration
                    Success = $scanResult.Success
                    Error = $scanResult.Error
                }
            }
        }
    }
    
    $overallEndTime = Get-Date
    $Statistics.ScanDuration = ($overallEndTime - $overallStartTime).TotalSeconds
    
    return $true
}

# Export results to JSON
function Export-Results {
    param([string]$OutputFile)
    
    $finalResults = @{
        ScanMetadata = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            Scanner = "YARA LOLBin Scanner"
            Version = "1.0"
            TargetPath = $TargetPath
            RulesPath = $RulesPath
            Recursive = $Recursive
            Statistics = $Statistics
        }
        Results = $ScanResults
        ThreatIntelligence = @{
            IOCs = @()
            Recommendations = @()
        }
    }
    
    # Add IOCs for detected threats
    foreach ($result in $ScanResults) {
        if ($result.Matches.Count -gt 0) {
            $finalResults.ThreatIntelligence.IOCs += @{
                Type = "file_hash"
                Value = $result.File.SHA256
                Context = "YARA rule match: $($result.RuleFile)"
                Severity = "high"
            }
            
            $finalResults.ThreatIntelligence.IOCs += @{
                Type = "file_name"
                Value = $result.File.Name
                Context = "Suspicious file detected"
                Severity = "medium"
            }
        }
    }
    
    # Add recommendations
    if ($ScanResults.Count -gt 0) {
        $finalResults.ThreatIntelligence.Recommendations += "Investigate detected files for potential LOLBin abuse"
        $finalResults.ThreatIntelligence.Recommendations += "Review process execution logs for these files"
        $finalResults.ThreatIntelligence.Recommendations += "Consider quarantining or monitoring these files"
    }
    
    try {
        $finalResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-Success "Results exported to: $OutputFile"
        return $true
    } catch {
        Write-Error "Failed to export results: $($_.Exception.Message)"
        return $false
    }
}

# Generate summary report
function Write-SummaryReport {
    Write-Host ""
    Write-Host "${Blue}===============================================${Reset}"
    Write-Host "${Blue}YARA LOLBin Scan Summary${Reset}"
    Write-Host "${Blue}===============================================${Reset}"
    Write-Host "Files Scanned: $($Statistics.TotalFiles)"
    Write-Host "Files with Matches: $($Statistics.MatchedFiles)"
    Write-Host "Total Matches: $($Statistics.TotalMatches)"
    Write-Host "Rules Used: $($Statistics.RulesLoaded)"
    Write-Host "Scan Duration: $([math]::Round($Statistics.ScanDuration, 2)) seconds"
    Write-Host "Errors: $($Statistics.Errors)"
    Write-Host "${Blue}===============================================${Reset}"
    
    if ($Statistics.TotalMatches -gt 0) {
        Write-Host "${Red}⚠ THREATS DETECTED: Review results immediately${Reset}"
    } else {
        Write-Host "${Green}✓ No threats detected${Reset}"
    }
}

# Main execution
try {
    $success = Start-YaraScan
    
    if ($success) {
        # Export results
        Export-Results -OutputFile $OutputPath
        
        # Display summary
        Write-SummaryReport
        
        # Exit with appropriate code
        exit $(if ($Statistics.TotalMatches -gt 0) { 1 } else { 0 })
    } else {
        Write-Error "Scan failed"
        exit 1
    }
} catch {
    Write-Error "Scan error: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
} 