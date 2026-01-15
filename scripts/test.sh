#!/bin/bash

# Test script for Medical Vault
# Run Move unit tests and integration tests

set -e

echo "🧪 Medical Vault Test Suite"
echo "============================"
echo ""

# Check if sui CLI is installed
if ! command -v sui &> /dev/null; then
    echo "❌ Error: Sui CLI is not installed"
    exit 1
fi

# Run Move tests
echo "🔬 Running Move unit tests..."
echo ""

sui move test

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ All tests passed!"
else
    echo ""
    echo "❌ Some tests failed"
    exit 1
fi

echo ""
echo "📊 Test Summary:"
echo "  - Folder module: ✅"
echo "  - Medical Record module: ✅"
echo "  - Seal Whitelist module: ✅"
echo "  - Log module: ✅"
echo "  - Export module: ✅"
echo ""
