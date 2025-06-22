# Elastic LOLBin Detection Pack - System Doctor Script
# Pre-flight checks for Windows PowerShell 7+

param(
    [switch]$Verbose,
    [switch]$Fix,
    [string]$ConfigFile = ".env"
)

# Set strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ANSI color codes for output
$Red = "`e[31m"
$Green = "`e[32m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Reset = "`e[0m"

# Check results tracking
$CheckResults = @()
$FailedChecks = 0
$TotalChecks = 0

function Write-CheckResult {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Message,
        [string]$FixCommand = ""
    )
    
    $TotalChecks++
    if ($Passed) {
        Write-Host "${Green}✓${Reset} $Name" -NoNewline
        if ($Verbose) { Write-Host " - $Message" }
        else { Write-Host "" }
    } else {
        Write-Host "${Red}✗${Reset} $Name" -NoNewline
        Write-Host " - $Message" -ForegroundColor Red
        if ($FixCommand -and $Fix) {
            Write-Host "  ${Blue}Fix:${Reset} $FixCommand" -ForegroundColor Blue
        }
        $FailedChecks++
    }
    
    $CheckResults += [PSCustomObject]@{
        Name = $Name
        Passed = $Passed
        Message = $Message
        FixCommand = $FixCommand
    }
}

function Test-CommandExists {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Test-PortAvailable {
    param([int]$Port)
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Start()
        $listener.Stop()
        return $true
    } catch {
        return $false
    }
}

function Get-MemoryInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    return [PSCustomObject]@{
        TotalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        FreeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    }
}

function Get-DiskSpace {
    param([string]$Path = $PWD.Path)
    try {
        $fullPath = Resolve-Path $Path
        $driveLetter = $fullPath.Drive.Name
        $drive = Get-PSDrive -Name $driveLetter.TrimEnd(':')
        return [PSCustomObject]@{
            FreeGB = [math]::Round($drive.Free / 1GB, 2)
            UsedGB = [math]::Round($drive.Used / 1GB, 2)
            TotalGB = [math]::Round(($drive.Free + $drive.Used) / 1GB, 2)
        }
    } catch {
        # Fallback using WMI
        $disk = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object -First 1
        return [PSCustomObject]@{
            FreeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            UsedGB = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
            TotalGB = [math]::Round($disk.Size / 1GB, 2)
        }
    }
}

function Test-EnvironmentFile {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            $content = Get-Content $Path -Raw
            $requiredVars = @(
                'ELASTIC_PASSWORD',
                'KIBANA_ENCRYPTION_KEY',
                'ELASTIC_VERSION'
            )
            
            $missingVars = @()
            foreach ($var in $requiredVars) {
                if ($content -notmatch "^$var=") {
                    $missingVars += $var
                }
            }
            
            if ($missingVars.Count -eq 0) {
                return @{ Valid = $true; Message = "All required variables present" }
            } else {
                return @{ Valid = $false; Message = "Missing variables: $($missingVars -join ', ')" }
            }
        } catch {
            return @{ Valid = $false; Message = "Error reading file: $($_.Exception.Message)" }
        }
    } else {
        return @{ Valid = $false; Message = "Environment file not found" }
    }
}

# Main diagnostic function
function Start-SystemCheck {
    Write-Host "${Blue}===============================================${Reset}"
    Write-Host "${Blue}Elastic LOLBin Detection Pack - System Doctor${Reset}"
    Write-Host "${Blue}===============================================${Reset}"
    Write-Host ""

    # Check PowerShell Version
    $psVersion = $PSVersionTable.PSVersion
    $psVersionOK = $psVersion.Major -ge 7
    Write-CheckResult -Name "PowerShell Version" -Passed $psVersionOK -Message "Version $psVersion (Requires 7.0+)" -FixCommand "Install PowerShell 7: winget install Microsoft.PowerShell"

    # Check Docker Engine
    $dockerExists = Test-CommandExists "docker"
    Write-CheckResult -Name "Docker Engine" -Passed $dockerExists -Message $(if ($dockerExists) { "Docker is installed" } else { "Docker not found" }) -FixCommand "Install Docker: winget install Docker.DockerDesktop"

    if ($dockerExists) {
        # Check Docker Daemon
        try {
            $null = docker info 2>$null
            $dockerRunning = $LASTEXITCODE -eq 0
            Write-CheckResult -Name "Docker Daemon" -Passed $dockerRunning -Message $(if ($dockerRunning) { "Docker daemon is running" } else { "Docker daemon not running" }) -FixCommand "Start Docker Desktop"
        } catch {
            Write-CheckResult -Name "Docker Daemon" -Passed $false -Message "Cannot connect to Docker daemon" -FixCommand "Start Docker Desktop"
        }
    }

    # Check Docker Compose
    $composeExists = Test-CommandExists "docker-compose"
    Write-CheckResult -Name "Docker Compose" -Passed $composeExists -Message $(if ($composeExists) { "Docker Compose is available" } else { "Docker Compose not found" }) -FixCommand "Install Docker Compose with Docker Desktop"

    # Check Python
    $pythonExists = Test-CommandExists "python"
    if ($pythonExists) {
        try {
            $pythonVersion = python --version 2>&1
            $versionMatch = $pythonVersion -match "Python (\d+)\.(\d+)"
            if ($versionMatch) {
                $major = [int]$matches[1]
                $minor = [int]$matches[2]
                $pythonOK = ($major -eq 3 -and $minor -ge 8) -or $major -gt 3
                Write-CheckResult -Name "Python Version" -Passed $pythonOK -Message "$pythonVersion (Requires 3.8+)" -FixCommand "Install Python 3.11: winget install Python.Python.3.11"
            } else {
                Write-CheckResult -Name "Python Version" -Passed $false -Message "Cannot determine Python version" -FixCommand "Reinstall Python"
            }
        } catch {
            Write-CheckResult -Name "Python Version" -Passed $false -Message "Error checking Python version" -FixCommand "Install Python: winget install Python.Python.3.11"
        }
    } else {
        Write-CheckResult -Name "Python Version" -Passed $false -Message "Python not found" -FixCommand "Install Python: winget install Python.Python.3.11"
    }

    # Check Git
    $gitExists = Test-CommandExists "git"
    Write-CheckResult -Name "Git" -Passed $gitExists -Message $(if ($gitExists) { "Git is installed" } else { "Git not found" }) -FixCommand "Install Git: winget install Git.Git"

    # Check required ports
    $requiredPorts = @(9200, 5601, 5044, 9300, 9600)
    foreach ($port in $requiredPorts) {
        $portAvailable = Test-PortAvailable -Port $port
        $serviceName = switch ($port) {
            9200 { "Elasticsearch HTTP" }
            9300 { "Elasticsearch Transport" }
            5601 { "Kibana" }
            5044 { "Logstash Beats" }
            9600 { "Logstash API" }
        }
        Write-CheckResult -Name "Port $port ($serviceName)" -Passed $portAvailable -Message $(if ($portAvailable) { "Available" } else { "In use" }) -FixCommand "Stop service using port $port or change configuration"
    }

    # Check system memory
    $memory = Get-MemoryInfo
    $memoryOK = $memory.TotalGB -ge 4
    $memoryMessage = "Total: $($memory.TotalGB)GB, Free: $($memory.FreeGB)GB"
    Write-CheckResult -Name "System Memory" -Passed $memoryOK -Message "$memoryMessage (Requires 4GB+)" -FixCommand "Add more RAM or close other applications"

    # Check disk space
    $disk = Get-DiskSpace
    $diskOK = $disk.FreeGB -ge 20
    $diskMessage = "Free: $($disk.FreeGB)GB of $($disk.TotalGB)GB"
    Write-CheckResult -Name "Disk Space" -Passed $diskOK -Message "$diskMessage (Requires 20GB+)" -FixCommand "Free up disk space"

    # Check environment configuration
    $envCheck = Test-EnvironmentFile -Path $ConfigFile
    Write-CheckResult -Name "Environment Config" -Passed $envCheck.Valid -Message $envCheck.Message -FixCommand "Copy env-example to .env and configure"

    # Check Windows features (if running on Windows)
    if ($PSVersionTable.Platform -eq "Win32NT" -or $null -eq $PSVersionTable.Platform) {
        try {
            $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction SilentlyContinue
            $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
            
            $containerSupport = ($wslFeature -and $wslFeature.State -eq "Enabled") -or ($hyperVFeature -and $hyperVFeature.State -eq "Enabled")
            Write-CheckResult -Name "Container Support" -Passed $containerSupport -Message $(if ($containerSupport) { "WSL2 or Hyper-V enabled" } else { "No container platform enabled" }) -FixCommand "Enable WSL2: wsl --install"
        } catch {
            Write-CheckResult -Name "Container Support" -Passed $true -Message "Cannot check Windows features (assuming Docker Desktop handles this)"
        }
    }

    # Network connectivity check
    try {
        $dockerHubTest = Test-NetConnection -ComputerName "registry-1.docker.io" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
        Write-CheckResult -Name "Docker Hub Connectivity" -Passed $dockerHubTest -Message $(if ($dockerHubTest) { "Can reach Docker Hub" } else { "Cannot reach Docker Hub" }) -FixCommand "Check internet connection and firewall"
    } catch {
        Write-CheckResult -Name "Docker Hub Connectivity" -Passed $false -Message "Network test failed" -FixCommand "Check internet connection"
    }

    # Performance recommendations
    Write-Host ""
    Write-Host "${Blue}Performance Recommendations:${Reset}"
    if ($memory.TotalGB -lt 8) {
        Write-Host "${Yellow}⚠${Reset} Consider upgrading to 8GB+ RAM for better performance"
    }
    if ($disk.FreeGB -lt 50) {
        Write-Host "${Yellow}⚠${Reset} Consider having 50GB+ free space for full-scale simulation"
    }

    # Security recommendations
    Write-Host ""
    Write-Host "${Blue}Security Recommendations:${Reset}"
    Write-Host "${Yellow}⚠${Reset} Change default passwords in .env file"
    Write-Host "${Yellow}⚠${Reset} Enable security features for production use"
    Write-Host "${Yellow}⚠${Reset} Configure firewall rules for required ports"

    # Summary
    Write-Host ""
    Write-Host "${Blue}===============================================${Reset}"
    $PassedChecks = $TotalChecks - $FailedChecks
    if ($FailedChecks -eq 0) {
        Write-Host "${Green}✓ All checks passed! ($PassedChecks/$TotalChecks)${Reset}"
        Write-Host "${Green}System is ready for Elastic LOLBin Detection Pack${Reset}"
    } else {
        Write-Host "${Red}✗ $FailedChecks checks failed ($PassedChecks/$TotalChecks passed)${Reset}"
        Write-Host "${Red}Please address the issues above before proceeding${Reset}"
        
        if ($Fix) {
            Write-Host ""
            Write-Host "${Blue}Auto-fix suggestions:${Reset}"
            foreach ($result in $CheckResults | Where-Object { -not $_.Passed -and $_.FixCommand }) {
                Write-Host "${Blue}→${Reset} $($result.FixCommand)"
            }
        } else {
            Write-Host ""
            Write-Host "${Blue}Run with -Fix parameter to see auto-fix suggestions${Reset}"
        }
    }
    Write-Host "${Blue}===============================================${Reset}"

    return $FailedChecks -eq 0
}

# Export results to JSON if requested
function Export-Results {
    param([string]$OutputPath)
    $results = @{
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        TotalChecks = $TotalChecks
        PassedChecks = $TotalChecks - $FailedChecks
        FailedChecks = $FailedChecks
        SystemReady = $FailedChecks -eq 0
        Checks = $CheckResults
        SystemInfo = @{
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Platform = $PSVersionTable.Platform
            OS = $PSVersionTable.OS
            Memory = (Get-MemoryInfo)
            DiskSpace = (Get-DiskSpace)
        }
    }
    
    $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Results exported to: $OutputPath"
}

# Main execution
try {
    $success = Start-SystemCheck
    
    # Export results if verbose
    if ($Verbose) {
        Export-Results -OutputPath "doctor-results.json"
    }
    
    # Exit with appropriate code
    exit $(if ($success) { 0 } else { 1 })
} catch {
    Write-Host "${Red}Error running system check: $($_.Exception.Message)${Reset}" -ForegroundColor Red
    exit 1
} 