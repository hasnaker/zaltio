#!/bin/bash
# Zalt VS Code Extension Publish Script
# Usage: ./scripts/publish-vscode.sh

set -e

echo "🚀 Publishing Zalt VS Code Extension"
echo ""

cd packages/vscode-extension

# Check vsce
if ! command -v vsce &> /dev/null; then
  echo "Installing vsce..."
  npm install -g @vscode/vsce
fi

# Check ovsx for Open VSX (Cursor, etc.)
if ! command -v ovsx &> /dev/null; then
  echo "Installing ovsx..."
  npm install -g ovsx
fi

# Build
echo "📦 Building extension..."
npm run compile

# Package
echo "📦 Packaging..."
vsce package

# Get the vsix file
VSIX_FILE=$(ls *.vsix | head -1)

# Publish to VS Code Marketplace
echo ""
echo "📤 Publishing to VS Code Marketplace..."
echo "Run: vsce publish"
echo ""

# Publish to Open VSX (for Cursor)
echo "📤 Publishing to Open VSX..."
echo "Run: ovsx publish $VSIX_FILE -p YOUR_OPENVSX_TOKEN"
echo ""

echo "✅ Extension packaged: $VSIX_FILE"
echo ""
echo "Manual publish commands:"
echo "  VS Code:  vsce publish"
echo "  Open VSX: ovsx publish $VSIX_FILE -p YOUR_TOKEN"

cd ../..
