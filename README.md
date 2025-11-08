# ccswap
A lightweight, cross-platform command-line tool for managing multiple Claude Code configuration profiles.It allows users to easily switch between different sets of configurations, such as API keys, endpoints, and model mappings, using simple commands like ccswap use <profile>. The tool is designed to be simple and efficient, with no external dependencies, and it works by managing different versions of the settings.json file used by Claude Code. Built with ❤️ by JUAN MACKIE
-------------
# Installation Guide for ccswap

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

## File Structure After Installation

```
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
