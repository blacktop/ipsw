#!/usr/bin/env bash
#
# Debug helper to capture Apple authentication flow
# This script helps identify when and how Apple sends WebAuthn challenges

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/auth_debug.log"

echo "🔍 Apple Auth Flow Debugger"
echo "=========================="
echo ""
echo "This will run ipsw with verbose logging to capture the auth flow."
echo "Log will be saved to: $LOG_FILE"
echo ""
echo "Steps to test:"
echo "  1. Make sure you have an Apple ID with passkey registered"
echo "  2. Clear any saved credentials: rm -rf ~/.config/ipsw"
echo "  3. Run this script"
echo "  4. Enter your credentials when prompted"
echo "  5. Check $LOG_FILE for WebAuthn challenge data"
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."

# Clear old log
> "$LOG_FILE"

# Add debug helper to temporarily show all JSON responses
echo "Starting ipsw with debug logging..."
echo "====================================" >> "$LOG_FILE"
echo "Date: $(date)" >> "$LOG_FILE"
echo "====================================" >> "$LOG_FILE"

# Run ipsw with verbose output and capture everything
cd "$(git rev-parse --show-toplevel)" || exit 1

IPSW_DEBUG=1 go run ./cmd/ipsw download dev --os -v 2>&1 | tee -a "$LOG_FILE"

echo ""
echo "✅ Debug log saved to: $LOG_FILE"
echo ""
echo "Now analyze the log for:"
echo "  1. HTTP status codes (look for 412, 409, 200)"
echo "  2. 'publicKeyCredentialRequestOptions' field"
echo "  3. 'passkeyAuthentication' field"
echo "  4. 'authenticationType' field"
echo ""
echo "Search for WebAuthn data:"
echo "  grep -i 'webauthn\\|passkey\\|publicKey' $LOG_FILE"
echo ""
