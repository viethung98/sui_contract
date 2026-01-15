#!/bin/bash

# Medical Vault Deployment Script
# This script deploys the Medical Vault smart contracts to Sui testnet

set -e

echo "🏥 Medical Vault Deployment Script"
echo "===================================="
echo ""

# Check if sui CLI is installed
if ! command -v sui &> /dev/null; then
    echo "❌ Error: Sui CLI is not installed"
    echo "Please install it from: https://docs.sui.io/build/install"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "❌ Error: jq is not installed"
    echo "Please install it: brew install jq (macOS) or apt-get install jq (Linux)"
    exit 1
fi

# Check active environment
ACTIVE_ENV=$(sui client active-env)
ACTIVE_ADDRESS=$(sui client active-address)
echo "📍 Active environment: $ACTIVE_ENV"
echo "👤 Active address: $ACTIVE_ADDRESS"
echo ""

# Build the project
echo "🔨 Building Move contracts..."
sui move build

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"
echo ""

# Deploy to network
echo "🚀 Deploying to $ACTIVE_ENV..."
echo "This may take a few moments..."
echo ""

DEPLOY_OUTPUT=$(sui client publish --gas-budget 100000000 --json)

if [ $? -ne 0 ]; then
    echo "❌ Deployment failed"
    exit 1
fi

# Create deployment directory with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEPLOY_DIR="../backend/deployment/$TIMESTAMP"
mkdir -p "$DEPLOY_DIR"

# Save full deployment output
echo $DEPLOY_OUTPUT | jq '.' > "$DEPLOY_DIR/deployment.json"
echo "💾 Full deployment saved to backend/deployment/$TIMESTAMP/"
echo ""

# Parse deployment output
PACKAGE_ID=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.type == "published") | .packageId')
DIGEST=$(echo $DEPLOY_OUTPUT | jq -r '.digest')

# Extract created objects
WHITELIST_REGISTRY=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.objectType | contains("WhitelistRegistry")) | .objectId' | head -n 1)
UPGRADE_CAP=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.objectType | contains("UpgradeCap")) | .objectId' | head -n 1)
PUBLISHER=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.objectType | contains("Publisher")) | .objectId' | head -n 1)

echo "✅ NEW Contract Deployed Successfully!"
echo ""
echo "📦 New Package ID: $PACKAGE_ID"
echo "🔐 Transaction: $DIGEST"
echo ""

if [ ! -z "$WHITELIST_REGISTRY" ] && [ "$WHITELIST_REGISTRY" != "null" ]; then
    echo "📋 WhitelistRegistry: $WHITELIST_REGISTRY"
fi
if [ ! -z "$UPGRADE_CAP" ] && [ "$UPGRADE_CAP" != "null" ]; then
    echo "🔧 UpgradeCap: $UPGRADE_CAP (save this for upgrades)"
fi
if [ ! -z "$PUBLISHER" ] && [ "$PUBLISHER" != "null" ]; then
    echo "📰 Publisher: $PUBLISHER"
fi
echo ""

# Display all created objects
echo "📋 All Created Objects:"
echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.type == "created") | "  - \(.objectType): \(.objectId)"'
echo ""

# Save package ID to versioned file
echo $PACKAGE_ID > .package_id_$TIMESTAMP
echo "💾 Package ID saved to .package_id_$TIMESTAMP"
echo ""

# Create environment file for backend
cat > ../backend/.env.deployment <<EOF
# Medical Vault Deployment Configuration
# Generated: $(date)
# Network: $ACTIVE_ENV
# Deployer: $ACTIVE_ADDRESS

SUI_NETWORK=$ACTIVE_ENV
SUI_PACKAGE_ID=$PACKAGE_ID
SUI_WHITELIST_REGISTRY=$WHITELIST_REGISTRY
SUI_UPGRADE_CAP=$UPGRADE_CAP
SUI_PUBLISHER=$PUBLISHER
DEPLOYMENT_DIGEST=$DIGEST
DEPLOYMENT_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

echo "✅ Backend environment file created: backend/.env.deployment"
echo ""

# Create environment file for frontend
cat > ../frontend/.env.local <<EOF
# Medical Vault Frontend Configuration
# Generated: $(date)
# Network: $ACTIVE_ENV

VITE_SUI_NETWORK=$ACTIVE_ENV
VITE_PACKAGE_ID=$PACKAGE_ID
VITE_WHITELIST_REGISTRY=$WHITELIST_REGISTRY
EOF

echo "✅ Frontend environment file created: frontend/.env.local"
echo ""

# Create deployment summary
cat > ../backend/deployment/deployment-summary.txt <<EOF
Medical Vault Deployment Summary
================================
Date: $(date)
Network: $ACTIVE_ENV
Deployer: $ACTIVE_ADDRESS

Core Contract:
  Package ID: $PACKAGE_ID
  Digest: $DIGEST

Shared Objects:
  WhitelistRegistry: $WHITELIST_REGISTRY

Admin Objects:
  UpgradeCap: $UPGRADE_CAP
  Publisher: $PUBLISHER

Explorer Links:
  Transaction: https://suiscan.xyz/$ACTIVE_ENV/tx/$DIGEST
  Package: https://suiscan.xyz/$ACTIVE_ENV/object/$PACKAGE_ID
EOF

if [ ! -z "$WHITELIST_REGISTRY" ] && [ "$WHITELIST_REGISTRY" != "null" ]; then
    echo "  Registry: https://suiscan.xyz/$ACTIVE_ENV/object/$WHITELIST_REGISTRY" >> ../backend/deployment/deployment-summary.txt
fi

cat >> ../backend/deployment/deployment-summary.txt <<EOF

Usage Examples:
  # Check whitelist registry
  sui client object $WHITELIST_REGISTRY

  # View package
  sui client object $PACKAGE_ID
EOF

echo "📄 Deployment summary saved to backend/deployment/deployment-summary.txt"
echo ""

echo "🎉 Deployment complete!"
echo ""
echo "🔗 Explorer links:"
echo "  📝 Transaction: https://suiscan.xyz/$ACTIVE_ENV/tx/$DIGEST"
echo "  📦 Package: https://suiscan.xyz/$ACTIVE_ENV/object/$PACKAGE_ID"

if [ ! -z "$WHITELIST_REGISTRY" ] && [ "$WHITELIST_REGISTRY" != "null" ]; then
    echo "  📋 Registry: https://suiscan.xyz/$ACTIVE_ENV/object/$WHITELIST_REGISTRY"
fi

echo ""
echo "📋 Next steps:"
echo "  1. Review backend/.env.deployment and merge with your .env file"
echo "  2. Update frontend environment with the new configuration"
echo "  3. Configure Walrus endpoints in your backend .env"
echo "  4. Set up Seal policies for encryption"
echo "  5. Restart your backend server to apply new package ID"
echo ""
