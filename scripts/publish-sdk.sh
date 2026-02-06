#!/bin/bash
# Zalt SDK Publish Script
# Usage: ./scripts/publish-sdk.sh [version]

set -e

VERSION=${1:-"1.0.0"}

echo "🚀 Publishing Zalt SDK packages v$VERSION"
echo ""

# Check npm login
if ! npm whoami &> /dev/null; then
  echo "❌ Not logged in to npm. Run: npm login"
  exit 1
fi

# Build all packages
echo "📦 Building packages..."
cd packages/core && npm run build && cd ../..
cd packages/react && npm run build && cd ../..
cd packages/next && npm run build && cd ../..
cd packages/mcp-server && npm run build && cd ../..

# Update versions
echo "📝 Updating versions to $VERSION..."
cd packages/core && npm version $VERSION --no-git-tag-version && cd ../..
cd packages/react && npm version $VERSION --no-git-tag-version && cd ../..
cd packages/next && npm version $VERSION --no-git-tag-version && cd ../..
cd packages/mcp-server && npm version $VERSION --no-git-tag-version && cd ../..

# Publish in order (core first, then dependents)
echo ""
echo "📤 Publishing @zalt/core..."
cd packages/core && npm publish --access public && cd ../..

echo "📤 Publishing @zalt/react..."
cd packages/react && npm publish --access public && cd ../..

echo "📤 Publishing @zalt/next..."
cd packages/next && npm publish --access public && cd ../..

echo "📤 Publishing @zalt/mcp-server..."
cd packages/mcp-server && npm publish --access public && cd ../..

echo ""
echo "✅ All packages published successfully!"
echo ""
echo "Install with:"
echo "  npm install @zalt/core @zalt/react @zalt/next"
echo ""
echo "For AI assistants:"
echo "  npm install -g @zalt/mcp-server"
