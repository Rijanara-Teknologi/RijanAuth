#!/bin/bash
# Run specific test suites with colorized output

if [ -z "$1" ]; then
    echo "Usage: ./scripts/run-tests.sh <suite_name>"
    echo "Available suites: auth, oidc, federation, customization, logging, integration, security"
    echo "Example: ./scripts/run-tests.sh auth"
    exit 1
fi

echo "=========================================================="
echo " Running tests for: $1"
echo "=========================================================="

pytest tests/$1/ -v --color=yes --tb=short
