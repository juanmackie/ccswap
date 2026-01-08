#!/bin/bash
# ccswap_oauth.sh - OAuth2 helper functions for ccswap (Unix/Linux/macOS)
# Version: 2.0.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check for required dependencies
check_dependencies() {
    local missing=0

    for cmd in curl jq openssl; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}Error: Required command '$cmd' not found${NC}"
            missing=1
        fi
    done

    if [ $missing -eq 1 ]; then
        echo ""
        echo "Please install missing dependencies:"
        echo "  Debian/Ubuntu: sudo apt-get install curl jq openssl"
        echo "  macOS: brew install curl jq openssl"
        echo "  RHEL/CentOS: sudo yum install curl jq openssl"
        return 1
    fi

    return 0
}

# Detect if a profile is OAuth2 type
detect_auth_type() {
    local profile_file="$1"

    if [ ! -f "$profile_file" ]; then
        echo "error"
        return 1
    fi

    # Check if profile has auth_type set to oauth2
    if grep -q '"auth_type"[[:space:]]*:[[:space:]]*"oauth2"' "$profile_file"; then
        echo "oauth2"
    elif grep -q '"auth_type"' "$profile_file"; then
        # Has auth_type but not oauth2
        echo "apikey"
    else
        # No auth_type field, default to apikey (backward compatible)
        echo "apikey"
    fi
}

# Encrypt token file using AES-256-CBC with PBKDF2
encrypt_tokens() {
    local input_file="$1"
    local output_file="$2"
    local password="$3"

    if [ -z "$password" ]; then
        echo "Error: Password is required for encryption" >&2
        return 1
    fi

    # Generate random salt (16 bytes = 32 hex chars)
    local salt=$(openssl rand -hex 16)

    # Derive key and IV using PBKDF2 (48 bytes = 32 key + 16 IV)
    local key_iv=$(echo -n "${password}" | openssl pbkdf2 -iter 100000 -salt "${salt}" -keylen 48 -hex 2>/dev/null)

    if [ -z "$key_iv" ]; then
        echo "Error: Failed to derive encryption key" >&2
        return 1
    fi

    local key=$(echo "${key_iv}" | cut -c 1-64)
    local iv=$(echo "${key_iv}" | cut -c 65-96)

    # Encrypt the data
    local temp_output=$(mktemp)
    if ! openssl enc -aes-256-cbc -in "${input_file}" -out "${temp_output}" \
        -K "${key}" -iv "${iv}" -pbkdf2 -iter 100000 2>/dev/null; then
        echo "Error: Encryption failed" >&2
        rm -f "$temp_output"
        return 1
    fi

    # Prepend salt to encrypted file
    echo -n "${salt}" > "${output_file}"
    cat "${temp_output}" >> "${output_file}"
    rm -f "$temp_output"

    # Set restrictive permissions (600 = user read/write only)
    chmod 600 "${output_file}" 2>/dev/null || true

    return 0
}

# Decrypt token file
decrypt_tokens() {
    local input_file="$1"
    local output_file="$2"
    local password="$3"

    if [ ! -f "$input_file" ]; then
        echo "Error: Token file not found" >&2
        return 1
    fi

    if [ -z "$password" ]; then
        echo "Error: Password is required for decryption" >&2
        return 1
    fi

    # Read the file
    local file_content
    file_content=$(cat "$input_file")

    # Extract salt (first 32 hex chars = 16 bytes) and encrypted data
    local salt="${file_content:0:32}"
    local encrypted_data="${file_content:32}"

    if [ ${#salt} -lt 32 ]; then
        echo "Error: Invalid token file format" >&2
        return 1
    fi

    # Derive key and IV using PBKDF2
    local key_iv=$(echo -n "${password}" | openssl pbkdf2 -iter 100000 -salt "${salt}" -keylen 48 -hex 2>/dev/null)

    if [ -z "$key_iv" ]; then
        echo "Error: Failed to derive decryption key" >&2
        return 1
    fi

    local key=$(echo "${key_iv}" | cut -c 1-64)
    local iv=$(echo "${key_iv}" | cut -c 65-96)

    # Decrypt the data
    echo -n "${encrypted_data}" | openssl enc -aes-256-cbc -d -out "${output_file}" \
        -K "${key}" -iv "${iv}" -pbkdf2 -iter 100000 2>/dev/null

    if [ $? -ne 0 ]; then
        echo "Error: Decryption failed (wrong password?)" >&2
        return 1
    fi

    return 0
}

# Check if token needs refresh
oauth_token_needs_refresh() {
    local tokens_file="$1"

    if [ ! -f "$tokens_file" ]; then
        return 1
    fi

    local expires_at=$(jq -r '.expires_at // 0' "$tokens_file" 2>/dev/null)

    if [ -z "$expires_at" ] || [ "$expires_at" = "null" ] || [ "$expires_at" = "0" ]; then
        return 1
    fi

    local current_time=$(date +%s)
    local buffer_seconds=300  # 5 minute buffer

    if [ $((current_time + buffer_seconds)) -ge "$expires_at" ]; then
        return 0  # Needs refresh
    fi

    return 1  # Valid
}

# OAuth Device Code Flow Login
oauth_device_code_login() {
    local profile_file="$1"
    local password="$2"
    local profile_name="$3"

    # Load OAuth config from profile
    local client_id=$(jq -r '.oauth2.client_id // empty' "$profile_file" 2>/dev/null)
    local client_secret=$(jq -r '.oauth2.client_secret // empty' "$profile_file" 2>/dev/null)
    local device_code_endpoint=$(jq -r '.oauth2.device_code_endpoint // empty' "$profile_file" 2>/dev/null)
    local token_endpoint=$(jq -r '.oauth2.token_endpoint // empty' "$profile_file" 2>/dev/null)
    local scopes=$(jq -r '.oauth2.scopes // "openid profile email offline_access"' "$profile_file" 2>/dev/null)

    # Validate OAuth config
    if [ -z "$client_id" ] || [ -z "$device_code_endpoint" ] || [ -z "$token_endpoint" ]; then
        echo -e "${RED}Error: Invalid OAuth2 configuration in profile${NC}"
        echo "Profile must have: oauth2.client_id, oauth2.device_code_endpoint, oauth2.token_endpoint"
        return 1
    fi

    # Step 1: Request device code
    echo -e "${CYAN}Initiating OAuth2 Device Code Flow...${NC}"
    echo ""

    local device_response=$(mktemp)
    local http_code=$(curl -s -w "%{http_code}" -o "$device_response" \
        --max-time 30 \
        -X POST \
        -u "${client_id}:${client_secret}" \
        -d "client_id=${client_id}" \
        -d "scope=${scopes}" \
        "${device_code_endpoint}" 2>/dev/null)

    if [ "$http_code" != "200" ]; then
        echo -e "${RED}Error: Failed to get device code (HTTP $http_code)${NC}"
        cat "$device_response" >&2
        rm -f "$device_response"
        return 1
    fi

    # Parse device code response
    local device_code=$(jq -r '.device_code // empty' "$device_response" 2>/dev/null)
    local user_code=$(jq -r '.user_code // empty' "$device_response" 2>/dev/null)
    local verification_uri=$(jq -r '.verification_uri // empty' "$device_response" 2>/dev/null)
    local verification_uri_complete=$(jq -r '.verification_uri_complete // .verification_uri // empty' "$device_response" 2>/dev/null)
    local expires_in=$(jq -r '.expires_in // 1800' "$device_response" 2>/dev/null)
    local interval=$(jq -r '.interval // 5' "$device_response" 2>/dev/null)

    rm -f "$device_response"

    if [ -z "$device_code" ] || [ -z "$user_code" ]; then
        echo -e "${RED}Error: Invalid device code response${NC}"
        return 1
    fi

    # Step 2: Display instructions to user
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}OAuth2 Authorization Required${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo ""
    echo -e "${YELLOW}Please complete the following steps:${NC}"
    echo ""
    echo -e "  1. ${CYAN}Visit this URL:${NC} ${verification_uri}"
    if [ -n "$verification_uri_complete" ] && [ "$verification_uri_complete" != "$verification_uri" ]; then
        echo -e "     ${CYAN}Or click:${NC} ${verification_uri_complete}"
    fi
    echo ""
    echo -e "  2. ${CYAN}Enter this code:${NC} ${GREEN}${user_code}${NC}"
    echo ""
    echo -e "${YELLOW}Note: This code expires in $((expires_in / 60)) minutes${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo ""
    echo -e "${CYAN}Waiting for you to complete authorization...${NC}"
    echo -e "${CYAN}(Press Ctrl+C to abort)${NC}"
    echo ""

    # Step 3: Poll for token
    local start_time=$(date +%s)
    local end_time=$((start_time + expires_in))
    local poll_interval=$interval

    while [ $(date +%s) -lt $end_time ]; do
        sleep $poll_interval

        local token_response=$(mktemp)
        local poll_http_code=$(curl -s -w "%{http_code}" -o "$token_response" \
            --max-time 30 \
            -X POST \
            -u "${client_id}:${client_secret}" \
            -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
            -d "device_code=${device_code}" \
            -d "client_id=${client_id}" \
            "${token_endpoint}" 2>/dev/null)

        if [ "$poll_http_code" = "200" ]; then
            # Success!
            echo ""
            echo -e "${GREEN}Authorization successful!${NC}"

            # Parse token response
            local access_token=$(jq -r '.access_token // empty' "$token_response" 2>/dev/null)
            local refresh_token=$(jq -r '.refresh_token // empty' "$token_response" 2>/dev/null)
            local token_expires_in=$(jq -r '.expires_in // 3600' "$token_response" 2>/dev/null)
            local token_type=$(jq -r '.token_type // "Bearer"' "$token_response" 2>/dev/null)
            local token_scope=$(jq -r '.scope // ""' "$token_response" 2>/dev/null)

            rm -f "$token_response"

            if [ -z "$access_token" ]; then
                echo -e "${RED}Error: No access token in response${NC}"
                return 1
            fi

            # Calculate expiration time
            local current_time=$(date +%s)
            local expires_at=$((current_time + token_expires_in))

            # Create token file
            local tokens_json=$(mktemp)
            cat > "$tokens_json" << EOF
{
  "access_token": "${access_token}",
  "refresh_token": "${refresh_token}",
  "expires_at": ${expires_at},
  "token_type": "${token_type}",
  "scope": "${token_scope}"
}
EOF

            # Get profile directory and token file path
            local profile_dir=$(dirname "$profile_file")
            local profile_basename=$(basename "$profile_file" .json)
            local token_file="${profile_dir}/${profile_basename}_tokens.enc"

            # Encrypt and save tokens
            if encrypt_tokens "$tokens_json" "$token_file" "$password"; then
                rm -f "$tokens_json"
                echo -e "${GREEN}OAuth tokens encrypted and saved to: ${token_file}${NC}"
                echo ""
                echo -e "${CYAN}Token expires in: $((token_expires_in / 60)) minutes${NC}"
                return 0
            else
                rm -f "$tokens_json"
                echo -e "${RED}Error: Failed to save OAuth tokens${NC}"
                return 1
            fi
        fi

        # Check for errors
        local error=$(jq -r '.error // empty' "$token_response" 2>/dev/null)
        rm -f "$token_response"

        case "$error" in
            "authorization_pending")
                # User hasn't authorized yet, continue polling
                echo -n "."
                ;;
            "slow_down")
                # Polling too fast, increase interval
                poll_interval=$((poll_interval * 2))
                echo -n "-"
                ;;
            "access_denied")
                echo ""
                echo -e "${RED}Error: Authorization was denied${NC}"
                echo "Please try again and approve the authorization"
                return 1
                ;;
            "expired_token")
                echo ""
                echo -e "${RED}Error: Device code has expired${NC}"
                echo "Please run 'ccswap oauth login ${profile_name}' to start a new authentication"
                return 1
                ;;
            ""|null)
                # No error field but not 200, likely network error
                echo -n "?"
                ;;
            *)
                echo ""
                echo -e "${RED}Error: OAuth error - ${error}${NC}"
                return 1
                ;;
        esac
    done

    echo ""
    echo -e "${RED}Error: Authorization timed out${NC}"
    echo "Please run 'ccswap oauth login ${profile_name}' to try again"
    return 1
}

# Token Refresh
oauth_token_refresh() {
    local profile_file="$1"
    local tokens_file="$2"
    local password="$3"

    # Load OAuth config from profile
    local client_id=$(jq -r '.oauth2.client_id // empty' "$profile_file" 2>/dev/null)
    local client_secret=$(jq -r '.oauth2.client_secret // empty' "$profile_file" 2>/dev/null)
    local token_endpoint=$(jq -r '.oauth2.token_endpoint // empty' "$profile_file" 2>/dev/null)
    local refresh_token=$(jq -r '.refresh_token // empty' "$tokens_file" 2>/dev/null)

    if [ -z "$client_id" ] || [ -z "$token_endpoint" ] || [ -z "$refresh_token" ]; then
        echo "Error: Missing OAuth configuration or refresh token" >&2
        return 1
    fi

    # Make refresh request
    local response=$(mktemp)
    local http_code=$(curl -s -w "%{http_code}" -o "$response" \
        --max-time 30 \
        -X POST \
        -u "${client_id}:${client_secret}" \
        -d "grant_type=refresh_token" \
        -d "refresh_token=${refresh_token}" \
        "${token_endpoint}" 2>/dev/null)

    if [ "$http_code" != "200" ]; then
        echo "Error: Token refresh failed (HTTP $http_code)" >&2
        cat "$response" >&2
        rm -f "$response"
        return 1
    fi

    # Check for errors
    local error=$(jq -r '.error // empty' "$response" 2>/dev/null)
    if [ -n "$error" ] && [ "$error" != "null" ]; then
        echo "Error: Token refresh failed - $error" >&2
        rm -f "$response"
        return 1
    fi

    # Update tokens file
    local current_time=$(date +%s)
    local expires_in=$(jq -r '.expires_in // 3600' "$response" 2>/dev/null)
    local expires_at=$((current_time + expires_in))
    local new_access_token=$(jq -r '.access_token // empty' "$response" 2>/dev/null)
    local new_refresh_token=$(jq -r '.refresh_token // .refresh_token // empty' "$response" 2>/dev/null)

    # Use new refresh token if provided, otherwise keep existing
    if [ -z "$new_refresh_token" ] || [ "$new_refresh_token" = "null" ]; then
        new_refresh_token="$refresh_token"
    fi

    local temp_tokens=$(mktemp)
    jq --arg access_token "$new_access_token" \
       --arg refresh_token "$new_refresh_token" \
       --argjson expires_at "$expires_at" \
       '.access_token = $access_token |
        .refresh_token = $refresh_token |
        .expires_at = $expires_at' \
       "$tokens_file" > "$temp_tokens" 2>/dev/null

    if [ $? -eq 0 ]; then
        mv "$temp_tokens" "$tokens_file"
        rm -f "$response"
        return 0
    else
        rm -f "$temp_tokens" "$response"
        echo "Error: Failed to update tokens" >&2
        return 1
    fi
}

# Display OAuth token status
oauth_display_status() {
    local tokens_file="$1"

    if [ ! -f "$tokens_file" ]; then
        echo "No OAuth tokens found"
        return 1
    fi

    local access_token=$(jq -r '.access_token // empty' "$tokens_file" 2>/dev/null)
    local expires_at=$(jq -r '.expires_at // 0' "$tokens_file" 2>/dev/null)
    local scope=$(jq -r '.scope // ""' "$tokens_file" 2>/dev/null)
    local token_type=$(jq -r '.token_type // "Bearer"' "$tokens_file" 2>/dev/null)

    if [ -z "$access_token" ]; then
        echo "Error: Invalid token file"
        return 1
    fi

    # Calculate time remaining
    local current_time=$(date +%s)
    local expires_in_seconds=$((expires_at - current_time))

    echo ""
    echo -e "${BLUE}OAuth2 Token Status${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo -e "Authentication Type: ${GREEN}OAuth2${NC}"
    echo -e "Token Type: ${token_type}"

    # Show truncated access token
    if [ ${#access_token} -gt 20 ]; then
        local token_start="${access_token:0:10}"
        local token_end="${access_token: -10}"
        echo -e "Access Token: ${token_start}...${token_end}"
    else
        echo -e "Access Token: ${access_token}"
    fi

    # Show expiration status
    if [ $expires_in_seconds -gt 0 ]; then
        local minutes=$((expires_in_seconds / 60))
        local seconds=$((expires_in_seconds % 60))
        echo -e "Status: ${GREEN}Active${NC}"
        echo -e "Expires: ${YELLOW}${minutes}m ${seconds}s${NC} from now"
    else
        echo -e "Status: ${RED}Expired${NC}"
        echo -e "Action: ${YELLOW}Token refresh required${NC}"
    fi

    if [ -n "$scope" ]; then
        echo -e "Scopes: ${scope}"
    fi

    echo -e "${BLUE}===========================================${NC}"
    echo ""

    return 0
}

# Export functions for use in main script
export -f check_dependencies
export -f detect_auth_type
export -f encrypt_tokens
export -f decrypt_tokens
export -f oauth_token_needs_refresh
export -f oauth_device_code_login
export -f oauth_token_refresh
export -f oauth_display_status
