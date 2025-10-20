#!/bin/bash
#
# Build the macOS passkey helper binary
# This script compiles the Swift code into a standalone executable

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/main.swift"
OUTPUT="$SCRIPT_DIR/passkey_helper"

echo "🔨 Building passkey_helper..."

# Check if Swift is available
if ! command -v swiftc &> /dev/null; then
    echo "❌ Error: swiftc not found. Please install Xcode Command Line Tools:"
    echo "   xcode-select --install"
    exit 1
fi

# Check macOS version
macos_version=$(sw_vers -productVersion | cut -d. -f1)
if [ "$macos_version" -lt 13 ]; then
    echo "⚠️  Warning: macOS 13+ recommended for full WebAuthn support"
fi

# Compile
swiftc -o "$OUTPUT" \
    -framework AuthenticationServices \
    -framework Foundation \
    -framework AppKit \
    "$SOURCE"

if [ $? -eq 0 ]; then
    chmod +x "$OUTPUT"
    echo "✅ Successfully built: $OUTPUT"
    echo ""
    echo "Test it with:"
    echo "  $OUTPUT '{\"challenge\":\"dGVzdA\",\"rpId\":\"apple.com\"}'"
else
    echo "❌ Build failed"
    exit 1
fi
