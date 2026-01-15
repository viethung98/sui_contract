#!/bin/bash

# Medical Vault Smart Contract Deployment Tool
# Supports: Fresh deployment or Upgrade existing contract

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Medical Vault Contract Deployment${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

show_usage() {
    echo "Usage: $0 [deploy|upgrade] [options]"
    echo ""
    echo "Commands:"
    echo "  deploy              Deploy a new contract (fresh deployment)"
    echo "  upgrade             Upgrade an existing contract"
    echo ""
    echo "Options for 'upgrade':"
    echo "  --package-id ID     Existing package ID to upgrade"
    echo "  --upgrade-cap ID    UpgradeCap object ID"
    echo ""
    echo "Examples:"
    echo "  $0 deploy"
    echo "  $0 upgrade --package-id 0xabc... --upgrade-cap 0xdef..."
    echo ""
    exit 1
}

check_requirements() {
    # Check sui CLI
    if ! command -v sui &> /dev/null; then
        print_error "Sui CLI is not installed"
        echo "Install from: https://docs.sui.io/build/install"
        exit 1
    fi

    # Check jq
    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed"
        echo "Install: brew install jq (macOS) or apt-get install jq (Linux)"
        exit 1
    fi

    print_success "All requirements satisfied"
}

deploy_new_contract() {
    print_header
    echo "🚀 Mode: FRESH DEPLOYMENT"
    echo "   Creating a completely new contract"
    echo ""

    # Check environment
    ACTIVE_ENV=$(sui client active-env)
    ACTIVE_ADDRESS=$(sui client active-address)
    echo "📍 Network: $ACTIVE_ENV"
    echo "👤 Deployer: $ACTIVE_ADDRESS"
    echo ""

    # Confirmation
    read -p "Deploy new contract to $ACTIVE_ENV? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Deployment cancelled"
        exit 0
    fi
    echo ""

    # Build
    echo "🔨 Building Move contracts..."
    cd "$(dirname "$0")/.."
    sui move build

    if [ $? -ne 0 ]; then
        print_error "Build failed"
        exit 1
    fi
    print_success "Build successful"
    echo ""

    # Deploy
    echo "📦 Publishing new contract..."
    DEPLOY_OUTPUT=$(sui client publish --gas-budget 500000000 --json)

    if [ $? -ne 0 ]; then
        print_error "Deployment failed"
        exit 1
    fi

    # Parse results
    PACKAGE_ID=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.type == "published") | .packageId')
    DIGEST=$(echo $DEPLOY_OUTPUT | jq -r '.digest')
    WHITELIST_REGISTRY=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.objectType | contains("WhitelistRegistry")) | .objectId' | head -n 1)
    UPGRADE_CAP=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.objectType | contains("UpgradeCap")) | .objectId' | head -n 1)
    PUBLISHER=$(echo $DEPLOY_OUTPUT | jq -r '.objectChanges[] | select(.objectType | contains("Publisher")) | .objectId' | head -n 1)

    # Save deployment info
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    DEPLOY_DIR="deployment/$TIMESTAMP"
    mkdir -p "$DEPLOY_DIR"
    
    echo $DEPLOY_OUTPUT | jq '.' > "$DEPLOY_DIR/deployment.json"
    echo $PACKAGE_ID > "$DEPLOY_DIR/package_id.txt"

    # Create summary
    cat > "$DEPLOY_DIR/DEPLOYMENT_INFO.txt" << EOF
Medical Vault - Fresh Deployment
================================
Date: $(date)
Network: $ACTIVE_ENV
Deployer: $ACTIVE_ADDRESS

Core Information:
  Package ID: $PACKAGE_ID
  Transaction: $DIGEST

Important Objects:
  WhitelistRegistry: $WHITELIST_REGISTRY
  UpgradeCap: $UPGRADE_CAP
  Publisher: $PUBLISHER

⚠️  SAVE THE UPGRADE_CAP FOR FUTURE UPGRADES!

Explorer Links:
  Transaction: https://suiscan.xyz/$ACTIVE_ENV/tx/$DIGEST
  Package: https://suiscan.xyz/$ACTIVE_ENV/object/$PACKAGE_ID
  Registry: https://suiscan.xyz/$ACTIVE_ENV/object/$WHITELIST_REGISTRY

Environment Variables (add to your .env):
  SUI_PACKAGE_ID=$PACKAGE_ID
  SUI_WHITELIST_REGISTRY=$WHITELIST_REGISTRY
  SUI_UPGRADE_CAP=$UPGRADE_CAP
EOF

    # Display results
    echo ""
    print_success "NEW CONTRACT DEPLOYED!"
    echo ""
    echo "📦 Package ID: $PACKAGE_ID"
    echo "🔐 Transaction: $DIGEST"
    echo ""
    echo "📋 Important Objects:"
    echo "   WhitelistRegistry: $WHITELIST_REGISTRY"
    echo "   UpgradeCap: $UPGRADE_CAP"
    echo "   Publisher: $PUBLISHER"
    echo ""
    print_warning "Save UpgradeCap for future upgrades!"
    echo ""
    echo "📄 Deployment details saved to: $DEPLOY_DIR/"
    echo ""
    echo "🔗 Explorer: https://suiscan.xyz/$ACTIVE_ENV/tx/$DIGEST"
    echo ""
    
    # Create env files
    create_env_files "$PACKAGE_ID" "$WHITELIST_REGISTRY" "$UPGRADE_CAP" "$PUBLISHER" "$DIGEST" "$ACTIVE_ENV" "$ACTIVE_ADDRESS"
}

upgrade_existing_contract() {
    print_header
    echo "🔄 Mode: UPGRADE EXISTING CONTRACT"
    echo ""

    # Parse arguments
    PACKAGE_ID=""
    UPGRADE_CAP=""

    while [[ $# -gt 0 ]]; do
        case $1 in
            --package-id)
                PACKAGE_ID="$2"
                shift 2
                ;;
            --upgrade-cap)
                UPGRADE_CAP="$2"
                shift 2
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                ;;
        esac
    done

    # Validate arguments
    if [ -z "$PACKAGE_ID" ] || [ -z "$UPGRADE_CAP" ]; then
        print_error "Missing required arguments"
        echo ""
        echo "Required:"
        echo "  --package-id      The existing package ID"
        echo "  --upgrade-cap     The UpgradeCap object ID"
        echo ""
        show_usage
    fi

    # Check environment
    ACTIVE_ENV=$(sui client active-env)
    ACTIVE_ADDRESS=$(sui client active-address)
    echo "📍 Network: $ACTIVE_ENV"
    echo "👤 Upgrader: $ACTIVE_ADDRESS"
    echo ""
    echo "Upgrading:"
    echo "  Package: $PACKAGE_ID"
    echo "  Using UpgradeCap: $UPGRADE_CAP"
    echo ""

    # Confirmation
    read -p "Proceed with upgrade on $ACTIVE_ENV? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Upgrade cancelled"
        exit 0
    fi
    echo ""

    # Build
    echo "🔨 Building Move contracts..."
    cd "$(dirname "$0")/.."
    sui move build

    if [ $? -ne 0 ]; then
        print_error "Build failed"
        exit 1
    fi
    print_success "Build successful"
    echo ""

    # Upgrade
    echo "📦 Upgrading contract..."
    UPGRADE_OUTPUT=$(sui client upgrade --upgrade-capability $UPGRADE_CAP --gas-budget 500000000 --json)

    if [ $? -ne 0 ]; then
        print_error "Upgrade failed"
        exit 1
    fi

    # Parse results
    NEW_PACKAGE_ID=$(echo $UPGRADE_OUTPUT | jq -r '.objectChanges[] | select(.type == "published") | .packageId')
    DIGEST=$(echo $UPGRADE_OUTPUT | jq -r '.digest')

    # Save upgrade info
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    UPGRADE_DIR="deployment/upgrades/$TIMESTAMP"
    mkdir -p "$UPGRADE_DIR"
    
    echo $UPGRADE_OUTPUT | jq '.' > "$UPGRADE_DIR/upgrade.json"

    # Create summary
    cat > "$UPGRADE_DIR/UPGRADE_INFO.txt" << EOF
Medical Vault - Contract Upgrade
=================================
Date: $(date)
Network: $ACTIVE_ENV
Upgrader: $ACTIVE_ADDRESS

Upgrade Information:
  Old Package: $PACKAGE_ID
  New Package: $NEW_PACKAGE_ID
  Transaction: $DIGEST
  UpgradeCap Used: $UPGRADE_CAP

Explorer Links:
  Transaction: https://suiscan.xyz/$ACTIVE_ENV/tx/$DIGEST
  New Package: https://suiscan.xyz/$ACTIVE_ENV/object/$NEW_PACKAGE_ID

Environment Variables (update your .env):
  SUI_PACKAGE_ID=$NEW_PACKAGE_ID
  
Note: UpgradeCap and other shared objects remain the same
EOF

    # Display results
    echo ""
    print_success "CONTRACT UPGRADED!"
    echo ""
    echo "📦 Old Package: $PACKAGE_ID"
    echo "📦 New Package: $NEW_PACKAGE_ID"
    echo "🔐 Transaction: $DIGEST"
    echo ""
    print_warning "Update your .env with new Package ID: $NEW_PACKAGE_ID"
    echo ""
    echo "📄 Upgrade details saved to: $UPGRADE_DIR/"
    echo ""
    echo "🔗 Explorer: https://suiscan.xyz/$ACTIVE_ENV/tx/$DIGEST"
    echo ""

    # Update env files
    create_env_files "$NEW_PACKAGE_ID" "" "$UPGRADE_CAP" "" "$DIGEST" "$ACTIVE_ENV" "$ACTIVE_ADDRESS"
}

create_env_files() {
    local PKG_ID=$1
    local REGISTRY=$2
    local UPGRADE=$3
    local PUB=$4
    local DIGEST=$5
    local ENV=$6
    local ADDR=$7

    # Backend env
    cat > "../backend/.env.deployment" << EOF
# Medical Vault Deployment Configuration
# Generated: $(date)
# Network: $ENV
# Address: $ADDR

SUI_NETWORK=$ENV
SUI_PACKAGE_ID=$PKG_ID
EOF

    if [ -n "$REGISTRY" ] && [ "$REGISTRY" != "null" ]; then
        echo "SUI_WHITELIST_REGISTRY=$REGISTRY" >> "../backend/.env.deployment"
    fi
    if [ -n "$UPGRADE" ] && [ "$UPGRADE" != "null" ]; then
        echo "SUI_UPGRADE_CAP=$UPGRADE" >> "../backend/.env.deployment"
    fi
    if [ -n "$PUB" ] && [ "$PUB" != "null" ]; then
        echo "SUI_PUBLISHER=$PUB" >> "../backend/.env.deployment"
    fi
    
    echo "DEPLOYMENT_DIGEST=$DIGEST" >> "../backend/.env.deployment"
    echo "DEPLOYMENT_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "../backend/.env.deployment"

    print_success "Backend env created: backend/.env.deployment"

    # Frontend env
    cat > "../frontend/.env.local" << EOF
# Medical Vault Frontend Configuration
# Generated: $(date)
# Network: $ENV

VITE_SUI_NETWORK=$ENV
VITE_PACKAGE_ID=$PKG_ID
EOF

    if [ -n "$REGISTRY" ] && [ "$REGISTRY" != "null" ]; then
        echo "VITE_WHITELIST_REGISTRY=$REGISTRY" >> "../frontend/.env.local"
    fi

    print_success "Frontend env created: frontend/.env.local"
    echo ""
}

# Main script
if [ $# -eq 0 ]; then
    show_usage
fi

COMMAND=$1
shift

check_requirements

case $COMMAND in
    deploy)
        deploy_new_contract
        ;;
    upgrade)
        upgrade_existing_contract "$@"
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_usage
        ;;
esac

print_success "Done!"
echo ""
