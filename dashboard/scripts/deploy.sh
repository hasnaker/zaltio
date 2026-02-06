#!/bin/bash
# Zalt Dashboard - Build and Deploy to EKS
# Usage: ./scripts/deploy.sh [tag]

set -e

# Configuration
AWS_REGION="eu-central-1"
AWS_ACCOUNT_ID="986906625644"
ECR_REPO="zalt-dashboard"
IMAGE_TAG="${1:-latest}"
FULL_IMAGE="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"

echo "🚀 Zalt Dashboard Deploy"
echo "========================"
echo "Image: ${FULL_IMAGE}"
echo ""

# Step 1: ECR Login
echo "📦 Logging into ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Step 2: Build
echo "🔨 Building Docker image..."
docker build -t ${ECR_REPO}:${IMAGE_TAG} \
  --build-arg NEXT_PUBLIC_ZALT_API_URL=https://api.zalt.io \
  --build-arg NEXT_PUBLIC_APP_URL=https://app.zalt.io \
  .

# Step 3: Tag
echo "🏷️  Tagging image..."
docker tag ${ECR_REPO}:${IMAGE_TAG} ${FULL_IMAGE}

# Step 4: Push
echo "⬆️  Pushing to ECR..."
docker push ${FULL_IMAGE}

# Step 5: Update K8s (if kubectl configured)
if command -v kubectl &> /dev/null; then
  echo "☸️  Updating Kubernetes deployment..."
  kubectl set image deployment/zalt-dashboard zalt-dashboard=${FULL_IMAGE} -n zalt --record || true
  kubectl rollout status deployment/zalt-dashboard -n zalt || true
fi

echo ""
echo "✅ Deploy complete!"
echo "   Image: ${FULL_IMAGE}"
echo ""
echo "📋 Next steps:"
echo "   1. ArgoCD will auto-sync if configured"
echo "   2. Or manually: kubectl apply -f k8s/"
