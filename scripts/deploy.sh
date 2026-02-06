#!/bin/bash
# HSD Auth Platform Deployment Script
# Validates: Requirements 7.1, 5.1, 5.2, 5.5
#
# Usage:
#   ./scripts/deploy.sh [environment]
#   
# Environments:
#   production  - Deploy to production (api.auth.hsdcore.com)
#   staging     - Deploy to staging (api.auth-staging.hsdcore.com)
#   development - Deploy to development (api.auth-dev.hsdcore.com)

set -e

# Default to production if no environment specified
ENVIRONMENT=${1:-production}

echo "=========================================="
echo "HSD Auth Platform Deployment"
echo "Environment: $ENVIRONMENT"
echo "Region: eu-central-1"
echo "=========================================="

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(production|staging|development)$ ]]; then
    echo "Error: Invalid environment '$ENVIRONMENT'"
    echo "Valid environments: production, staging, development"
    exit 1
fi

# Check for required tools
command -v sam >/dev/null 2>&1 || { echo "Error: AWS SAM CLI is required but not installed."; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "Error: AWS CLI is required but not installed."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Error: npm is required but not installed."; exit 1; }

# Check AWS credentials
echo "Checking AWS credentials..."
aws sts get-caller-identity > /dev/null || { echo "Error: AWS credentials not configured."; exit 1; }

# Install dependencies
echo "Installing dependencies..."
npm ci

# Build TypeScript
echo "Building TypeScript..."
npm run build

# Run tests
echo "Running tests..."
npm test

# Validate SAM template
echo "Validating SAM template..."
sam validate --lint

# Build SAM application
echo "Building SAM application..."
sam build

# Deploy based on environment
echo "Deploying to $ENVIRONMENT..."

if [ "$ENVIRONMENT" == "production" ]; then
    # Production deployment with confirmation
    sam deploy \
        --config-env production \
        --no-fail-on-empty-changeset
elif [ "$ENVIRONMENT" == "staging" ]; then
    # Staging deployment without confirmation
    sam deploy \
        --config-env staging \
        --no-fail-on-empty-changeset
else
    # Development deployment without confirmation
    sam deploy \
        --config-env development \
        --no-fail-on-empty-changeset
fi

echo "=========================================="
echo "Deployment complete!"
echo "=========================================="

# Get stack outputs
echo "Stack outputs:"
aws cloudformation describe-stacks \
    --stack-name "hsd-auth-platform-${ENVIRONMENT/production/prod}" \
    --query 'Stacks[0].Outputs' \
    --output table \
    --region eu-central-1 2>/dev/null || echo "Stack outputs not available yet."

echo ""
echo "Deployment finished successfully!"
