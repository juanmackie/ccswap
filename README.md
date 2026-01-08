# ccswap
A lightweight, cross-platform command-line tool for managing multiple Claude Code configuration profiles. It allows users to easily switch between different sets of configurations, such as API keys, endpoints, and model mappings, using simple commands like `ccswap use <profile>`. The tool supports both API key and OAuth2 authentication methods.

**Version:** 2.0.0 (with OAuth2 Device Code Flow support)

Built with ❤️ by JUAN MACKIE

-------------

## Windows Installation

### Method 1: System32 (Easiest)
1. Download `ccswap.bat`
2. Copy to `C:\Windows\System32\ccswap.bat`
3. Open new Command Prompt and run: `ccswap`

### Method 2: Custom Tools Directory
1. Create `C:\tools` directory
2. Copy `ccswap.bat` to `C:\tools\ccswap.bat`
3. Add to PATH:
   - Press `Win + R`, type `sysdm.cpl`
   - Go to "Advanced" → "Environment Variables"
   - Edit "Path" → add `C:\tools`
4. Restart Command Prompt and run: `ccswap`

## Unix/Linux/macOS Installation

### Method 1: System-wide (Recommended)
```bash
# Make executable
chmod +x ccswap

# Move to system path
sudo mv ccswap /usr/local/bin/

# Test
ccswap help
```

### Method 2: User Local
```bash
# Create bin directory
mkdir -p ~/bin

# Move script
mv ccswap ~/bin/

# Add to PATH (add to ~/.bashrc or ~/.zshrc)
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Test
ccswap help
```

## Verification

After installation, verify it works:

```bash
# Windows
ccswap help

# Unix/Linux/macOS  
ccswap help
```

You should see the usage information if installed correctly.

## First Use

1. Run Claude Code at least once to create `settings.json`
2. Save your first profile: `ccswap save default`
3. Create additional profiles as needed

## Example profile for GLM 4.6
```
{
  "env": {
    "ANTHROPIC_AUTH_TOKEN": "REDACTED-INSERT YOUR KEY",
    "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
    "API_TIMEOUT_MS": "3000000",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "glm-4.5-air",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "glm-4.6",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "glm-4.6"
  }
}
```
## Example profile for Kimi K2-thinking
```
{
  "env": {
    "ANTHROPIC_AUTH_TOKEN": "REDACTED-INSERT YOUR KEY",
    "ANTHROPIC_BASE_URL": "https://api.moonshot.ai/anthropic",
    "API_TIMEOUT_MS": "3000000",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "kimi-k2-thinking",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "kimi-k2-thinking",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "kimi-k2-thinking"
  }
}
```
## Example profile for MiniMax M2
```
{
  "env": {
    "ANTHROPIC_AUTH_TOKEN": "REDACTED-INSERT YOUR KEY",
    "ANTHROPIC_BASE_URL": "https://api.minimax.io/anthropic",
    "API_TIMEOUT_MS": "3000000",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "MiniMax-M2",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "MiniMax-M2",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "MiniMax-M2"
  }
}
```

## File Structure After Installation

 
# Windows
%USERPROFILE%\.claude\
├── settings.json          # Active Claude Code config
├── profiles\              # Profile storage
│   ├── default.json
│   ├── work.json
│   └── personal.json
└── _current.txt          # Active profile tracker

# Unix/Linux/macOS
$HOME/.claude/
├── settings.json          # Active Claude Code config
├── profiles/              # Profile storage
│   ├── default.json
│   ├── work.json
│   └── personal.json
└── active_profile         # Active profile tracker
```

## Troubleshooting

### Windows Issues
- **"ccswap not recognized"**: Add to PATH or use full path
- **"Access denied"**: Run Command Prompt as Administrator
- **PowerShell issues**: Use Command Prompt instead

### Unix Issues
- **"Permission denied"**: Run `chmod +x ccswap`
- **"command not found"**: Add to PATH or use full path
- **"No such file"**: Create `~/.claude/` directory first

## Uninstallation

### Windows
```bash
# Remove from System32
del C:\Windows\System32\ccswap.bat

# Or remove from tools directory
del C:\tools\ccswap.bat
```

### Unix/Linux/macOS
```bash
# Remove from system
sudo rm /usr/local/bin/ccswap

# Or remove from user directory
rm ~/bin/ccswap
```

Your profiles and settings remain in `~/.claude/` for future use.

-------------
# OAuth2 Authentication

ccswap v2.0.0 adds support for OAuth2 Device Code Flow authentication, enabling you to use enterprise SSO or custom OAuth2 providers with Claude Code.

## Prerequisites for OAuth2

OAuth2 support requires additional tools:

### Linux
```bash
# Debian/Ubuntu
sudo apt-get install curl jq openssl

# RHEL/CentOS/Fedora
sudo dnf install curl jq openssl
```

### macOS
```bash
brew install curl jq openssl
```

### Windows
- `curl` - Built-in on Windows 10 1803+
- `PowerShell 5.1+` - Built-in on Windows 10+
- `jq` - Install via:
  ```powershell
  choco install jq
  ```
  Or download from: https://stedolan.github.io/jq/download/

## Creating an OAuth2 Profile

OAuth2 profiles include an `auth_type` field and an `oauth2` configuration object:

```json
{
  "auth_type": "oauth2",
  "oauth2": {
    "client_id": "your_client_id_here",
    "client_secret": "your_client_secret_here",
    "device_code_endpoint": "https://auth.example.com/oauth/device_code",
    "token_endpoint": "https://auth.example.com/oauth/token",
    "scopes": "openid profile email offline_access"
  },
  "env": {
    "ANTHROPIC_BASE_URL": "https://api.anthropic.com",
    "API_TIMEOUT_MS": "3000000",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "claude-3-haiku-20240307",
    "ANTHROPIC_DEFAULT_SONNET_MODEL": "claude-3-5-sonnet-20241022",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "claude-3-opus-20240229"
  }
}
```

### OAuth2 Profile Fields

| Field | Description | Required |
|-------|-------------|----------|
| `auth_type` | Must be `"oauth2"` | Yes |
| `oauth2.client_id` | OAuth2 client ID | Yes |
| `oauth2.client_secret` | OAuth2 client secret | Yes* |
| `oauth2.device_code_endpoint` | Device authorization endpoint | Yes |
| `oauth2.token_endpoint` | Token endpoint | Yes |
| `oauth2.scopes` | OAuth2 scopes (default: openid profile email offline_access) | No |

*Some OAuth2 providers (public clients) don't require a client secret for Device Code Flow.

## OAuth2 Commands

### Login

Authenticate a profile using OAuth2 Device Code Flow:

```bash
ccswap oauth login <profile>
```

**Example:**
```bash
ccswap oauth login work
```

**What happens:**
1. You'll be prompted to create an encryption password for storing OAuth tokens
2. A device code is obtained from your OAuth2 provider
3. You'll see instructions to visit a URL and enter a code
4. Once you complete authorization in your browser, tokens are automatically retrieved
5. Tokens are encrypted with your password and stored securely

### Status

Check the current OAuth2 token status:

```bash
ccswap oauth status <profile>
```

**Example:**
```bash
ccswap oauth status work
```

**Output:**
```
Enter password to decrypt OAuth tokens: ********

OAuth2 Token Status
===========================================
Authentication Type: OAuth2
Token Type: Bearer
Access Token: eyJhbGci...VzI1Ni
Status: Active
Expires: 45m 23s from now
Scopes: openid profile email offline_access
===========================================
```

### Logout

Remove OAuth2 credentials from a profile:

```bash
ccswap oauth logout <profile>
```

**Example:**
```bash
ccswap oauth logout work
```

This deletes the encrypted token file. The profile itself remains and can be re-authenticated.

## Using OAuth2 Profiles

OAuth2 profiles work seamlessly with existing ccswap commands:

### Switch to OAuth2 Profile

```bash
ccswap use work_oauth
```

**What happens:**
1. Detects that the profile uses OAuth2
2. Prompts for your token decryption password
3. Checks if the access token is expired
4. Automatically refreshes if needed (using the refresh token)
5. Updates `settings.json` with the fresh access token

### Save OAuth2 Profile

```bash
ccswap save work_backup
```

If the currently active profile is OAuth2, the encrypted tokens are also copied to the new profile.

### List Profiles

```bash
ccswap ls
```

OAuth2 profiles are marked with `[OAuth2]`:

```
Available profiles:
  * default
    work [OAuth2]
    personal [OAuth2] (active)
```

### Delete OAuth2 Profile

```bash
ccswap rm work
```

Both the profile JSON and the encrypted token file are deleted.

## Token Storage

OAuth2 tokens are stored encrypted in your profiles directory:

**Unix/Linux/macOS:**
```
~/.claude/profiles/
├── work.json          # Profile configuration
└── work_tokens.enc    # Encrypted OAuth tokens
```

**Windows:**
```
%USERPROFILE%\.claude\profiles\
├── work.json          # Profile configuration
└── work_tokens.enc    # Encrypted OAuth tokens
```

### Encryption Details

- **Algorithm:** AES-256-CBC
- **Key Derivation:** PBKDF2 with 100,000 iterations
- **File Permissions:** 600 (user read/write only on Unix/macOS)
- **Password:** User-provided, not stored anywhere

## Token Refresh

OAuth2 access tokens typically expire after 1 hour. ccswap automatically handles token refresh:

1. When you use an OAuth2 profile, it checks if the token is expired (or within 5 minutes of expiration)
2. If expiring, it automatically uses the refresh token to get a new access token
3. The new token is re-encrypted and stored
4. No manual intervention required

If the refresh token is expired or invalid, you'll be prompted to re-authenticate:

```bash
ccswap oauth login work
```

## Mixed Profile Support

You can have both API key and OAuth2 profiles:

```
Available profiles:
  * default              # API key profile
    work                 # API key profile
    enterprise [OAuth2]  # OAuth2 profile
    personal             # API key profile
```

Switching between profile types works seamlessly:

```bash
ccswap use default        # Uses API key from profile
ccswap use enterprise     # Prompts for OAuth2 password, decrypts tokens
```

## Security Considerations

### Best Practices

1. **Strong Passwords:** Use a strong password for encrypting OAuth tokens
2. **HTTPS Only:** All OAuth2 endpoints must use HTTPS
3. **Secure Storage:** Token files have restrictive permissions (600 on Unix/macOS)
4. **Regular Rotation:** Consider running `ccswap oauth logout` then `ccswap oauth login` periodically to get fresh tokens

### What's Stored

| Location | Content | Encryption |
|----------|---------|------------|
| Profile JSON (`<name>.json`) | Client ID, client secret, endpoints | **No** (plain text) |
| Token file (`<name>_tokens.enc`) | Access token, refresh token | **Yes** (AES-256-CBC) |

### Why Client Secret in Plain Text?

Storing OAuth2 client credentials in the profile JSON is standard practice. These are not secret - they're meant to be distributed to client applications. The actual secrets (access tokens and refresh tokens) are encrypted.

## Troubleshooting OAuth2

### "Dependencies not found"

Install the required tools:
```bash
# Linux
sudo apt-get install curl jq openssl

# macOS
brew install curl jq openssl

# Windows (jq only)
choco install jq
```

### "Failed to decrypt tokens"

- Wrong password entered
- Token file corrupted
- Solution: Try again with correct password, or delete and re-authenticate

### "Token refresh failed"

- Refresh token expired or revoked
- OAuth2 provider issues
- Solution: Run `ccswap oauth login <profile>` to re-authenticate

### "Authorization timed out"

- Device code expired (usually 30 minutes)
- User didn't complete authorization in time
- Solution: Run `ccswap oauth login <profile>` again

### "Invalid OAuth2 configuration"

Check your profile JSON has all required fields:
- `auth_type`: "oauth2"
- `oauth2.client_id`
- `oauth2.device_code_endpoint`
- `oauth2.token_endpoint`

## Migration from API Key to OAuth2

To convert an existing API key profile to OAuth2:

1. **Backup your current profile:**
   ```bash
   cp ~/.claude/profiles/work.json ~/.claude/profiles/work.json.bak
   ```

2. **Edit the profile to add OAuth2 configuration:**
   ```bash
   # Add auth_type and oauth2 fields
   nano ~/.claude/profiles/work.json
   ```

   Change from:
   ```json
   {
     "env": {
       "ANTHROPIC_AUTH_TOKEN": "your-api-key",
       ...
     }
   }
   ```

   To:
   ```json
   {
     "auth_type": "oauth2",
     "oauth2": {
       "client_id": "your_client_id",
       "device_code_endpoint": "https://...",
       "token_endpoint": "https://...",
       "scopes": "openid profile email offline_access"
     },
     "env": {
       "ANTHROPIC_BASE_URL": "https://...",
       ...
     }
   }
   ```

3. **Authenticate:**
   ```bash
   ccswap oauth login work
   ```

4. **Use the profile:**
   ```bash
   ccswap use work
   ```

To revert back to API key authentication, simply remove the `auth_type` and `oauth2` fields from your profile JSON and restore the `ANTHROPIC_AUTH_TOKEN` in the `env` section.
