#!/bin/bash
# Setup OAuth credentials in AWS Secrets Manager
# Run this ONCE to store credentials securely

set -e

REGION="eu-central-1"
SECRET_NAME="zalt/oauth-credentials"

echo "Creating OAuth credentials secret in AWS Secrets Manager..."

# Create the secret with OAuth credentials
aws secretsmanager create-secret \
  --name "$SECRET_NAME" \
  --region "$REGION" \
  --description "Zalt OAuth credentials for Google and Apple Sign-In" \
  --secret-string '{
    "google": {
      "clientId": "YOUR_GOOGLE_CLIENT_ID",
      "clientSecret": "YOUR_GOOGLE_CLIENT_SECRET"
    },
    "apple": {
      "clientId": "clinisyn.com",
      "teamId": "YOUR_APPLE_TEAM_ID",
      "keyId": "YOUR_APPLE_KEY_ID",
      "privateKey": "YOUR_APPLE_PRIVATE_KEY"
    }
  }'

echo "✅ Secret created: $SECRET_NAME"
echo ""
echo "IMPORTANT: Update the secret with actual credentials:"
echo "  aws secretsmanager update-secret --secret-id $SECRET_NAME --secret-string '...'"
echo ""
echo "Or use AWS Console: https://eu-central-1.console.aws.amazon.com/secretsmanager"
