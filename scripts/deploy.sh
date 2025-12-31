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

# Check active environment
ACTIVE_ENV=$(sui client active-env)
echo "📍 Active environment: $ACTIVE_ENV"
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

# Deploy to testnet
echo "🚀 Deploying to $ACTIVE_ENV..."
echo "This may take a few moments..."
echo ""

DEPLOY_OUTPUT=$(sui client publish --gas-budget 100000000 --json)

if [ $? -ne 0 ]; then
    echo "❌ Deployment failed"
    exit 1
fi

# Parse deployment output
PACKAGE_ID=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.type == "published") | .packageId')

echo "✅ Deployment successful!"
echo ""
echo "📦 Package ID: $PACKAGE_ID"
echo ""

# Save package ID to file
echo $PACKAGE_ID > .package_id
echo "💾 Package ID saved to .package_id"
echo ""

# Display published objects
echo "📋 Published Objects:"
echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.type == "published") | "  - \(.packageId)"'
echo ""

# Create environment file for frontend
cat > frontend/.env.local <<EOF
NEXT_PUBLIC_SUI_NETWORK=$ACTIVE_ENV
NEXT_PUBLIC_PACKAGE_ID=$PACKAGE_ID
EOF

echo "✅ Frontend environment file created: frontend/.env.local"
echo ""

echo "🎉 Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Update your frontend with the package ID: $PACKAGE_ID"
echo "2. Configure Walrus endpoints in your .env file"
echo "3. Set up Seal policies"
echo ""
echo "To interact with the contract:"
echo "  sui client call --package $PACKAGE_ID --module folder --function create_folder ..."
echo ""
