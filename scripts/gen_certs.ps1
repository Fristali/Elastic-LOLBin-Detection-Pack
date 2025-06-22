# Certificate Generation Script for Elastic LOLBin Detection Pack
# Generates self-signed certificates for TLS encryption

param(
    [string]$CertPath = "./certs",
    [int]$ValidityDays = 365,
    [string]$Organization = "Elastic LOLBin Detection Pack",
    [string]$Country = "US",
    [string]$State = "State",
    [string]$City = "City",
    [int]$KeySize = 2048,
    [switch]$Force
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

function Write-Status {
    param([string]$Message, [string]$Color = $Blue)
    Write-Host "${Color}[CERT]${Reset} $Message"
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

# Check if OpenSSL is available
function Test-OpenSSL {
    try {
        $null = openssl version 2>$null
        return $true
    } catch {
        return $false
    }
}

# Generate certificate using OpenSSL
function New-OpenSSLCertificate {
    param(
        [string]$Name,
        [string]$Subject,
        [string]$KeyFile,
        [string]$CertFile,
        [string[]]$AltNames = @()
    )
    
    Write-Status "Generating certificate for $Name using OpenSSL..."
    
    # Create configuration file for SAN
    $configFile = Join-Path $CertPath "$Name.conf"
    $configContent = @"
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
$Subject

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $Name
IP.1 = 127.0.0.1
IP.2 = ::1
"@
    
    # Add additional SAN entries
    $sanIndex = 3
    foreach ($altName in $AltNames) {
        if ($altName -match '^\d+\.\d+\.\d+\.\d+$') {
            $configContent += "`nIP.$($sanIndex) = $altName"
        } else {
            $configContent += "`nDNS.$($sanIndex) = $altName"
        }
        $sanIndex++
    }
    
    $configContent | Out-File -FilePath $configFile -Encoding UTF8
    
    # Generate private key and certificate
    openssl req -x509 -nodes -days $ValidityDays -newkey rsa:$KeySize `
        -keyout $KeyFile -out $CertFile -config $configFile
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Certificate generated: $CertFile"
        Write-Success "Private key generated: $KeyFile"
        Remove-Item $configFile -Force
        return $true
    } else {
        Write-Error "Failed to generate certificate for $Name"
        return $false
    }
}

# Generate certificate using PowerShell (Windows only)
function New-PowerShellCertificate {
    param(
        [string]$Name,
        [string]$Subject,
        [string]$KeyFile,
        [string]$CertFile,
        [string[]]$AltNames = @()
    )
    
    Write-Status "Generating certificate for $Name using PowerShell..."
    
    try {
        # Create SAN list
        $sanList = @("localhost", $Name, "127.0.0.1")
        $sanList += $AltNames
        
        # Generate certificate
        $cert = New-SelfSignedCertificate `
            -Subject $Subject `
            -DnsName $sanList `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddDays($ValidityDays) `
            -KeyAlgorithm RSA `
            -KeyLength $KeySize `
            -KeyUsage DigitalSignature, KeyEncipherment `
            -Type SSLServerAuthentication
        
        # Export private key
        $password = ConvertTo-SecureString -String "temp" -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath "$CertPath\temp.pfx" -Password $password | Out-Null
        
        # Convert to PEM format using OpenSSL if available
        if (Test-OpenSSL) {
            openssl pkcs12 -in "$CertPath\temp.pfx" -out $CertFile -nokeys -passin pass:temp
            openssl pkcs12 -in "$CertPath\temp.pfx" -out $KeyFile -nocerts -nodes -passin pass:temp
            Remove-Item "$CertPath\temp.pfx" -Force
        } else {
            # Export as base64 if OpenSSL not available
            $certData = [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
            "-----BEGIN CERTIFICATE-----`n$certData`n-----END CERTIFICATE-----" | Out-File -FilePath $CertFile -Encoding ASCII
            Write-Warning "Private key export requires OpenSSL. Certificate only exported."
        }
        
        # Remove from store
        Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
        
        Write-Success "Certificate generated: $CertFile"
        if (Test-Path $KeyFile) {
            Write-Success "Private key generated: $KeyFile"
        }
        return $true
    } catch {
        Write-Error "Failed to generate certificate for $Name`: $($_.Exception.Message)"
        return $false
    }
}

# Main certificate generation function
function New-Certificate {
    param(
        [string]$Name,
        [string]$CommonName,
        [string[]]$AltNames = @()
    )
    
    $subject = "C=$Country/ST=$State/L=$City/O=$Organization/CN=$CommonName"
    $keyFile = Join-Path $CertPath "$Name.key"
    $certFile = Join-Path $CertPath "$Name.crt"
    
    # Check if certificate already exists
    if ((Test-Path $keyFile) -and (Test-Path $certFile) -and -not $Force) {
        Write-Warning "Certificate for $Name already exists. Use -Force to regenerate."
        return $true
    }
    
    # Try OpenSSL first, then PowerShell
    if (Test-OpenSSL) {
        return New-OpenSSLCertificate -Name $Name -Subject $subject -KeyFile $keyFile -CertFile $certFile -AltNames $AltNames
    } elseif ($IsWindows -or $null -eq $PSVersionTable.Platform) {
        return New-PowerShellCertificate -Name $Name -Subject $subject -KeyFile $keyFile -CertFile $certFile -AltNames $AltNames
    } else {
        Write-Error "Neither OpenSSL nor PowerShell certificate generation is available"
        return $false
    }
}

# Validate certificate
function Test-Certificate {
    param([string]$CertFile)
    
    if (-not (Test-Path $CertFile)) {
        return $false
    }
    
    if (Test-OpenSSL) {
        try {
            openssl x509 -in $CertFile -text -noout | Out-Null
            return $LASTEXITCODE -eq 0
        } catch {
            return $false
        }
    }
    
    return $true
}

# Main execution
try {
    Write-Status "Starting certificate generation..."
    Write-Status "Output directory: $CertPath"
    Write-Status "Validity period: $ValidityDays days"
    Write-Status "Key size: $KeySize bits"
    
    # Create certificate directory
    if (-not (Test-Path $CertPath)) {
        New-Item -ItemType Directory -Path $CertPath -Force | Out-Null
        Write-Success "Created certificate directory: $CertPath"
    }
    
    # Check prerequisites
    $hasOpenSSL = Test-OpenSSL
    $hasPowerShell = $IsWindows -or $null -eq $PSVersionTable.Platform
    
    Write-Status "OpenSSL available: $(if ($hasOpenSSL) { 'Yes' } else { 'No' })"
    Write-Status "PowerShell cert generation: $(if ($hasPowerShell) { 'Yes' } else { 'No' })"
    
    if (-not $hasOpenSSL -and -not $hasPowerShell) {
        Write-Error "No certificate generation method available. Please install OpenSSL."
        exit 1
    }
    
    # Generate Elasticsearch certificate
    $success = New-Certificate -Name "elasticsearch" -CommonName "elasticsearch" -AltNames @("es01", "elastic")
    if (-not $success) {
        Write-Error "Failed to generate Elasticsearch certificate"
        exit 1
    }
    
    # Generate Kibana certificate
    $success = New-Certificate -Name "kibana" -CommonName "kibana" -AltNames @("kibana-server")
    if (-not $success) {
        Write-Error "Failed to generate Kibana certificate"
        exit 1
    }
    
    # Generate Logstash certificate
    $success = New-Certificate -Name "logstash" -CommonName "logstash" -AltNames @("logstash-server")
    if (-not $success) {
        Write-Error "Failed to generate Logstash certificate"
        exit 1
    }
    
    # Generate CA certificate (copy of Elasticsearch cert for simplicity)
    $esCert = Join-Path $CertPath "elasticsearch.crt"
    $caCert = Join-Path $CertPath "ca.crt"
    if (Test-Path $esCert) {
        Copy-Item $esCert $caCert -Force
        Write-Success "CA certificate created: $caCert"
    }
    
    # Validate generated certificates
    Write-Status "Validating generated certificates..."
    $certFiles = @("elasticsearch.crt", "kibana.crt", "logstash.crt", "ca.crt")
    $allValid = $true
    
    foreach ($certFile in $certFiles) {
        $fullPath = Join-Path $CertPath $certFile
        if (Test-Certificate -CertFile $fullPath) {
            Write-Success "Valid: $certFile"
        } else {
            Write-Error "Invalid: $certFile"
            $allValid = $false
        }
    }
    
    if ($allValid) {
        Write-Success "All certificates generated successfully!"
        Write-Status "Certificate files created in: $CertPath"
        Write-Status "Update your .env file with: ELASTIC_CERT_PATH=$CertPath"
        Write-Status "Enable TLS with: ELASTIC_TLS_ENABLED=true"
    } else {
        Write-Error "Some certificates failed validation"
        exit 1
    }
    
} catch {
    Write-Error "Certificate generation failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    exit 1
} 