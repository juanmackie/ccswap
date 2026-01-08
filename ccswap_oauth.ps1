# ccswap_oauth.ps1 - OAuth2 helper functions for ccswap (Windows)
# Version: 2.0.0

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("login", "logout", "status", "refresh", "check-deps")]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [string]$Profile,

    [Parameter(Mandatory=$false)]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [switch]$Quiet
)

# Color output functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput $Message "Green"
}

function Write-Error {
    param([string]$Message)
    Write-Host "Error: $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-ColorOutput $Message "Cyan"
}

# Check for required dependencies
function Test-Dependencies {
    $missing = @()

    # Check for curl (built-in on Windows 10 1803+)
    if (!(Get-Command curl -ErrorAction SilentlyContinue)) {
        $missing += "curl"
    }

    # Check for jq
    if (!(Get-Command jq -ErrorAction SilentlyContinue)) {
        $missing += "jq"
    }

    if ($missing.Count -gt 0) {
        Write-Error "Missing dependencies: $($missing -join ', ')"
        Write-Host ""
        Write-Host "Please install missing dependencies:"
        Write-Host "  jq: choco install jq"
        Write-Host "     Or download from: https://stedolan.github.io/jq/download/"
        return $false
    }

    return $true
}

# Detect if a profile is OAuth2 type
function Get-AuthType {
    param(
        [string]$ProfileFile
    )

    if (!(Test-Path $ProfileFile)) {
        return "error"
    }

    $content = Get-Content $ProfileFile -Raw

    if ($content -match '"auth_type"\s*:\s*"oauth2"') {
        return "oauth2"
    } elseif ($content -match '"auth_type"') {
        return "apikey"
    } else {
        return "apikey"  # Default to apikey for backward compatibility
    }
}

# Encrypt token file using AES-256-CBC with PBKDF2
function Protect-Tokens {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [string]$Password
    )

    if ([string]::IsNullOrEmpty($Password)) {
        Write-Error "Password is required for encryption"
        return $false
    }

    if (!(Test-Path $InputFile)) {
        Write-Error "Input file not found"
        return $false
    }

    try {
        # Generate random salt (16 bytes)
        $salt = New-Object byte[] 16
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $rng.GetBytes($salt)

        # Derive key and IV using PBKDF2
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 100000)
        $key = $pbkdf2.GetBytes(32)  # 256 bits
        $iv = $pbkdf2.GetBytes(16)   # 128 bits

        # Read plaintext
        $plaintext = [System.IO.File]::ReadAllBytes($InputFile)

        # Encrypt
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $encryptor = $aes.CreateEncryptor()
        $encrypted = $encryptor.TransformFinalBlock($plaintext, 0, $plaintext.Length)

        # Write salt + encrypted data
        $fs = [System.IO.File]::Open($OutputFile, 'Create', 'Write')
        $fs.Write($salt, 0, $salt.Length)
        $fs.Write($encrypted, 0, $encrypted.Length)
        $fs.Close()

        # Set restrictive permissions
        $acl = Get-Acl $OutputFile
        $acl.SetAccessRuleProtection($true, $false)
        $userAccess = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $env:USERNAME,
            "FullControl",
            "Allow"
        )
        $acl.SetAccessRule($userAccess)
        Set-Acl $OutputFile $acl

        return $true
    } catch {
        Write-Error "Encryption failed: $_"
        return $false
    }
}

# Decrypt token file
function Unprotect-Tokens {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [string]$Password
    )

    if (!(Test-Path $InputFile)) {
        Write-Error "Token file not found"
        return $false
    }

    if ([string]::IsNullOrEmpty($Password)) {
        Write-Error "Password is required for decryption"
        return $false
    }

    try {
        # Read file
        $data = [System.IO.File]::ReadAllBytes($InputFile)

        if ($data.Length -lt 32) {
            Write-Error "Invalid token file format"
            return $false
        }

        # Extract salt (first 16 bytes)
        $salt = $data[0..15]
        $encrypted = $data[16..($data.Length - 1)]

        # Derive key and IV
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 100000)
        $key = $pbkdf2.GetBytes(32)
        $iv = $pbkdf2.GetBytes(16)

        # Decrypt
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        $decryptor = $aes.CreateDecryptor()
        $decrypted = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)

        [System.IO.File]::WriteAllBytes($OutputFile, $decrypted)
        return $true
    } catch {
        Write-Error "Decryption failed (wrong password?)"
        return $false
    }
}

# Check if token needs refresh
function Test-TokenExpired {
    param([string]$TokensFile)

    if (!(Test-Path $TokensFile)) {
        return $false
    }

    try {
        $content = Get-Content $TokensFile -Raw | ConvertFrom-Json
        $expiresAt = $content.expires_at

        if ([string]::IsNullOrEmpty($expiresAt) -or $expiresAt -eq 0) {
            return $false
        }

        $currentTime = [int][double]::Parse((Get-Date -UFormat %s))
        $bufferSeconds = 300  # 5 minutes

        return (($currentTime + $bufferSeconds) -ge $expiresAt)
    } catch {
        return $false
    }
}

# OAuth Device Code Flow Login
function Invoke-OAuthDeviceLogin {
    param(
        [string]$ProfileFile,
        [string]$Password,
        [string]$ProfileName
    )

    # Load OAuth config from profile
    try {
        $profileJson = Get-Content $ProfileFile -Raw | ConvertFrom-Json

        $clientId = if ($profileJson.oauth2) { $profileJson.oauth2.client_id } else { $null }
        $clientSecret = if ($profileJson.oauth2) { $profileJson.oauth2.client_secret } else { $null }
        $deviceCodeEndpoint = if ($profileJson.oauth2) { $profileJson.oauth2.device_code_endpoint } else { $null }
        $tokenEndpoint = if ($profileJson.oauth2) { $profileJson.oauth2.token_endpoint } else { $null }
        $scopes = if ($profileJson.oauth2.scopes) { $profileJson.oauth2.scopes } else { "openid profile email offline_access" }

        if ([string]::IsNullOrEmpty($clientId) -or [string]::IsNullOrEmpty($deviceCodeEndpoint) -or [string]::IsNullOrEmpty($tokenEndpoint)) {
            Write-Error "Invalid OAuth2 configuration in profile"
            Write-Host "Profile must have: oauth2.client_id, oauth2.device_code_endpoint, oauth2.token_endpoint"
            return $false
        }

        # Step 1: Request device code
        Write-Info "Initiating OAuth2 Device Code Flow..."
        Write-Host ""

        $body = @{
            client_id = $clientId
            scope = $scopes
        }

        $credPair = "$($clientId):$($clientSecret)"
        $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))

        try {
            $deviceResponse = Invoke-RestMethod -Uri $deviceCodeEndpoint -Method Post -Body $body -TimeoutSec 30 -ErrorAction Stop
        } catch {
            Write-Error "Failed to get device code: $($_.Exception.Message)"
            return $false
        }

        $deviceCode = $deviceResponse.device_code
        $userCode = $deviceResponse.user_code
        $verificationUri = $deviceResponse.verification_uri
        $verificationUriComplete = if ($deviceResponse.verification_uri_complete) { $deviceResponse.verification_uri_complete } else { $null }
        $expiresIn = if ($deviceResponse.expires_in) { $deviceResponse.expires_in } else { 1800 }
        $interval = if ($deviceResponse.interval) { $deviceResponse.interval } else { 5 }

        if ([string]::IsNullOrEmpty($deviceCode) -or [string]::IsNullOrEmpty($userCode)) {
            Write-Error "Invalid device code response"
            return $false
        }

        # Step 2: Display instructions
        Write-Host "===========================================" -ForegroundColor Blue
        Write-Host "OAuth2 Authorization Required" -ForegroundColor Blue
        Write-Host "===========================================" -ForegroundColor Blue
        Write-Host ""
        Write-Warning "Please complete the following steps:"
        Write-Host ""
        Write-Host "  1. " -NoNewline; Write-Info "Visit this URL: $verificationUri"
        if ($verificationUriComplete) {
            Write-Host "     " -NoNewline; Write-Info "Or click: $verificationUriComplete"
        }
        Write-Host ""
        Write-Host "  2. " -NoNewline; Write-Host "Enter this code: " -NoNewline; Write-Success $userCode
        Write-Host ""
        Write-Warning "Note: This code expires in $([int]($expiresIn / 60)) minutes"
        Write-Host "===========================================" -ForegroundColor Blue
        Write-Host ""
        Write-Info "Waiting for you to complete authorization..."
        Write-Info "(Press Ctrl+C to abort)"
        Write-Host ""

        # Step 3: Poll for token
        $startTime = [int][double]::Parse((Get-Date -UFormat %s))
        $endTime = $startTime + $expiresIn
        $pollInterval = $interval

        while ([int][double]::Parse((Get-Date -UFormat %s)) -lt $endTime) {
            Start-Sleep -Seconds $pollInterval

            $tokenBody = @{
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                device_code = $deviceCode
                client_id = $clientId
            }

            try {
                $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $tokenBody -Headers @{ Authorization = "Basic $encodedCreds" } -TimeoutSec 30 -ErrorAction Stop
            } catch {
                $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
                $error = if ($errorResponse.error) { $errorResponse.error } else { $null }

                switch ($error) {
                    "authorization_pending" {
                        Write-Host "." -NoNewline
                    }
                    "slow_down" {
                        $pollInterval = $pollInterval * 2
                        Write-Host "-" -NoNewline
                    }
                    "access_denied" {
                        Write-Host ""
                        Write-Error "Authorization was denied"
                        Write-Host "Please try again and approve the authorization"
                        return $false
                    }
                    "expired_token" {
                        Write-Host ""
                        Write-Error "Device code has expired"
                        Write-Host "Please run 'ccswap oauth login ${ProfileName}' to start a new authentication"
                        return $false
                    }
                    default {
                        if ($error) {
                            Write-Host ""
                            Write-Error "OAuth error - $error"
                            return $false
                        } else {
                            Write-Host "?" -NoNewline
                        }
                    }
                }
                continue
            }

            # Success!
            Write-Host ""
            Write-Success "Authorization successful!"

            $accessToken = $tokenResponse.access_token
            $refreshToken = $tokenResponse.refresh_token
            $tokenExpiresIn = if ($tokenResponse.expires_in) { $tokenResponse.expires_in } else { 3600 }
            $tokenType = if ($tokenResponse.token_type) { $tokenResponse.token_type } else { "Bearer" }
            $tokenScope = if ($tokenResponse.scope) { $tokenResponse.scope } else { "" }

            if ([string]::IsNullOrEmpty($accessToken)) {
                Write-Error "No access token in response"
                return $false
            }

            # Calculate expiration time
            $currentTime = [int][double]::Parse((Get-Date -UFormat %s))
            $expiresAt = $currentTime + $tokenExpiresIn

            # Create token JSON
            $tokensJson = @{
                access_token = $accessToken
                refresh_token = $refreshToken
                expires_at = $expiresAt
                token_type = $tokenType
                scope = $tokenScope
            } | ConvertTo-Json

            # Get profile directory and token file path
            $profileDir = Split-Path $ProfileFile -Parent
            $profileBasename = [System.IO.Path]::GetFileNameWithoutExtension($ProfileFile)
            $tokenFile = Join-Path $profileDir "${profileBasename}_tokens.enc"

            # Save to temp file first
            $tempTokensFile = [System.IO.Path]::GetTempFileName()
            $tokensJson | Out-File -FilePath $tempTokensFile -Encoding UTF8

            # Encrypt and save tokens
            if (Protect-Tokens -InputFile $tempTokensFile -OutputFile $tokenFile -Password $Password) {
                Remove-Item $tempTokensFile -Force
                Write-Success "OAuth tokens encrypted and saved to: $tokenFile"
                Write-Host ""
                Write-Info "Token expires in: $([int]($tokenExpiresIn / 60)) minutes"
                return $true
            } else {
                Remove-Item $tempTokensFile -Force -ErrorAction SilentlyContinue
                Write-Error "Failed to save OAuth tokens"
                return $false
            }
        }

        Write-Host ""
        Write-Error "Authorization timed out"
        Write-Host "Please run 'ccswap oauth login ${ProfileName}' to try again"
        return $false

    } catch {
        Write-Error "Error loading profile: $_"
        return $false
    }
}

# Token Refresh
function Invoke-OAuthTokenRefresh {
    param(
        [string]$ProfileFile,
        [string]$TokensFile,
        [string]$Password
    )

    try {
        $profileJson = Get-Content $ProfileFile -Raw | ConvertFrom-Json
        $tokensJson = Get-Content $TokensFile -Raw | ConvertFrom-Json

        $clientId = if ($profileJson.oauth2) { $profileJson.oauth2.client_id } else { $null }
        $clientSecret = if ($profileJson.oauth2) { $profileJson.oauth2.client_secret } else { $null }
        $tokenEndpoint = if ($profileJson.oauth2) { $profileJson.oauth2.token_endpoint } else { $null }
        $refreshToken = $tokensJson.refresh_token

        if ([string]::IsNullOrEmpty($clientId) -or [string]::IsNullOrEmpty($tokenEndpoint) -or [string]::IsNullOrEmpty($refreshToken)) {
            Write-Error "Missing OAuth configuration or refresh token"
            return $false
        }

        $credPair = "$($clientId):$($clientSecret)"
        $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))

        $body = @{
            grant_type = "refresh_token"
            refresh_token = $refreshToken
        }

        try {
            $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -Headers @{ Authorization = "Basic $encodedCreds" } -TimeoutSec 30
        } catch {
            Write-Error "Token refresh failed: $($_.Exception.Message)"
            return $false
        }

        $currentTime = [int][double]::Parse((Get-Date -UFormat %s))
        $expiresIn = if ($response.expires_in) { $response.expires_in } else { 3600 }
        $expiresAt = $currentTime + $expiresIn
        $newAccessToken = $response.access_token
        $newRefreshToken = if ($response.refresh_token) { $response.refresh_token } else { $refreshToken }

        # Update tokens JSON
        $tokensJson.access_token = $newAccessToken
        $tokensJson.refresh_token = $newRefreshToken
        $tokensJson.expires_at = $expiresAt

        $tokensJson | ConvertTo-Json | Out-File -FilePath $TokensFile -Encoding UTF8
        return $true

    } catch {
        Write-Error "Token refresh failed: $_"
        return $false
    }
}

# Display OAuth token status
function Show-OAuthTokenStatus {
    param([string]$TokensFile)

    if (!(Test-Path $TokensFile)) {
        Write-Host "No OAuth tokens found"
        return $false
    }

    try {
        $tokens = Get-Content $TokensFile -Raw | ConvertFrom-Json

        $accessToken = $tokens.access_token
        $expiresAt = $tokens.expires_at
        $scope = if ($tokens.scope) { $tokens.scope } else { "" }
        $tokenType = if ($tokens.token_type) { $tokens.token_type } else { "Bearer" }

        if ([string]::IsNullOrEmpty($accessToken)) {
            Write-Error "Invalid token file"
            return $false
        }

        $currentTime = [int][double]::Parse((Get-Date -UFormat %s))
        $expiresInSeconds = $expiresAt - $currentTime

        Write-Host ""
        Write-Host "OAuth2 Token Status" -ForegroundColor Blue
        Write-Host "===========================================" -ForegroundColor Blue
        Write-Host "Authentication Type: " -NoNewline; Write-Success "OAuth2"
        Write-Host "Token Type: $tokenType"

        # Show truncated access token
        if ($accessToken.Length -gt 20) {
            $tokenStart = $accessToken.Substring(0, 10)
            $tokenEnd = $accessToken.Substring($accessToken.Length - 10)
            Write-Host "Access Token: ${tokenStart}...${tokenEnd}"
        } else {
            Write-Host "Access Token: $accessToken"
        }

        # Show expiration status
        if ($expiresInSeconds -gt 0) {
            $minutes = [int]($expiresInSeconds / 60)
            $seconds = $expiresInSeconds % 60
            Write-Host "Status: " -NoNewline; Write-Success "Active"
            Write-Host "Expires: " -NoNewline; Write-Warning "${minutes}m ${seconds}s" -NoNewline; Write-Host " from now"
        } else {
            Write-Host "Status: " -NoNewline; Write-Error "Expired"
            Write-Host "Action: " -NoNewline; Write-Warning "Token refresh required"
        }

        if (-not [string]::IsNullOrEmpty($scope)) {
            Write-Host "Scopes: $scope"
        }

        Write-Host "===========================================" -ForegroundColor Blue
        Write-Host ""

        return $true

    } catch {
        Write-Error "Failed to read token file: $_"
        return $false
    }
}

# Main execution based on Action
switch ($Action) {
    "check-deps" {
        $depsOk = Test-Dependencies
        exit $(if ($depsOk) { 0 } else { 1 })
    }
    "login" {
        if (-not $Profile) {
            Write-Error "Profile name required"
            Write-Host "Usage: ccswap oauth login <profile>"
            exit 1
        }

        $pdir = Join-Path $env:USERPROFILE ".claude\profiles"
        $profileFile = Join-Path $pdir "${Profile}.json"

        if (!(Test-Path $profileFile)) {
            Write-Error "Profile '$Profile' not found"
            exit 1
        }

        # Check if OAuth2 profile
        $authType = Get-AuthType -ProfileFile $profileFile
        if ($authType -ne "oauth2") {
            Write-Error "Profile '$Profile' is not an OAuth2 profile"
            exit 1
        }

        # Test dependencies
        if (-not (Test-Dependencies)) {
            exit 1
        }

        # Get password
        if (-not $Password) {
            $Password1 = Read-Host "Enter encryption password for OAuth tokens" -AsSecureString
            $Password2 = Read-Host "Confirm password" -AsSecureString

            $pwd1_ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password1)
            $pwd2_ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2)

            $Password1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pwd1_ptr)
            $Password2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pwd2_ptr)

            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pwd1_ptr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pwd2_ptr)

            if ($Password1 -ne $Password2) {
                Write-Error "Passwords do not match"
                exit 1
            }

            $Password = $Password1
        }

        $result = Invoke-OAuthDeviceLogin -ProfileFile $profileFile -Password $Password -ProfileName $Profile
        exit $(if ($result) { 0 } else { 1 })
    }
    "status" {
        if (-not $Profile) {
            Write-Error "Profile name required"
            Write-Host "Usage: ccswap oauth status <profile>"
            exit 1
        }

        $pdir = Join-Path $env:USERPROFILE ".claude\profiles"
        $tokenFile = Join-Path $pdir "${Profile}_tokens.enc"

        if (!(Test-Path $tokenFile)) {
            Write-Host "No OAuth tokens found for profile '$Profile'"
            Write-Host "Run 'ccswap oauth login ${Profile}' to authenticate"
            exit 1
        }

        # Get password
        if (-not $Password) {
            $PasswordSecure = Read-Host "Enter password to decrypt OAuth tokens" -AsSecureString
            $pwd_ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pwd_ptr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pwd_ptr)
        }

        # Decrypt to temp file
        $tempTokens = [System.IO.Path]::GetTempFileName()
        if (Unprotect-Tokens -InputFile $tokenFile -OutputFile $tempTokens -Password $Password) {
            Show-OAuthTokenStatus -TokensFile $tempTokens
            Remove-Item $tempTokens -Force
            exit 0
        } else {
            Remove-Item $tempTokens -Force -ErrorAction SilentlyContinue
            exit 1
        }
    }
    "logout" {
        if (-not $Profile) {
            Write-Error "Profile name required"
            Write-Host "Usage: ccswap oauth logout <profile>"
            exit 1
        }

        $pdir = Join-Path $env:USERPROFILE ".claude\profiles"
        $tokenFile = Join-Path $pdir "${Profile}_tokens.enc"

        if (!(Test-Path $tokenFile)) {
            Write-Host "No OAuth tokens found for profile '$Profile'"
            exit 0
        }

        $confirmation = Read-Host "Delete OAuth tokens for '${Profile}'? (y/N)"
        if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
            Remove-Item $tokenFile -Force
            Write-Success "OAuth tokens deleted for profile '${Profile}'"
            exit 0
        } else {
            Write-Host "Cancelled"
            exit 0
        }
    }
    "refresh" {
        if (-not $Profile) {
            Write-Error "Profile name required"
            exit 1
        }

        $pdir = Join-Path $env:USERPROFILE ".claude\profiles"
        $profileFile = Join-Path $pdir "${Profile}.json"
        $tokenFile = Join-Path $pdir "${Profile}_tokens.enc"

        # Get password
        if (-not $Password) {
            $PasswordSecure = Read-Host "Enter password for OAuth tokens" -AsSecureString
            $pwd_ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSecure)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pwd_ptr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pwd_ptr)
        }

        # Decrypt, refresh, re-encrypt
        $tempTokens = [System.IO.Path]::GetTempFileName()
        if (Unprotect-Tokens -InputFile $tokenFile -OutputFile $tempTokens -Password $Password) {
            if (Invoke-OAuthTokenRefresh -ProfileFile $profileFile -TokensFile $tempTokens -Password $Password) {
                Protect-Tokens -InputFile $tempTokens -OutputFile $tokenFile -Password $Password
                Remove-Item $tempTokens -Force
                Write-Success "Token refreshed successfully"
                exit 0
            }
        }
        Remove-Item $tempTokens -Force -ErrorAction SilentlyContinue
        exit 1
    }
    default {
        Write-Host "Usage: ccswap oauth <login|logout|status|refresh> <profile> [options]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  login    Authenticate using OAuth2 Device Code Flow"
        Write-Host "  logout   Remove OAuth credentials"
        Write-Host "  status   Show OAuth token status"
        Write-Host "  refresh  Manually refresh OAuth token"
        exit 1
    }
}
