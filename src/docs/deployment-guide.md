# HSD Auth Platform - Deployment Guide

This guide covers deploying the HSD Auth Platform to AWS.

## Prerequisites

- AWS CLI v2 configured with appropriate credentials
- AWS SAM CLI installed
- Node.js 18+
- Docker (for local testing)

## AWS Account Setup

### 1. Create IAM User/Role

Create an IAM user or role with the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:*",
        "apigateway:*",
        "dynamodb:*",
        "secretsmanager:*",
        "cloudformation:*",
        "s3:*",
        "iam:*",
        "logs:*",
        "cloudwatch:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2. Configure AWS CLI

```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Default region: eu-central-1
# Default output format: json
```

## Infrastructure Setup

### 1. Create DynamoDB Tables

```bash
# Users table
aws dynamodb create-table \
  --table-name zalt-users \
  --attribute-definitions \
    AttributeName=PK,AttributeType=S \
    AttributeName=SK,AttributeType=S \
    AttributeName=email,AttributeType=S \
    AttributeName=realm_id,AttributeType=S \
  --key-schema \
    AttributeName=PK,KeyType=HASH \
    AttributeName=SK,KeyType=RANGE \
  --global-secondary-indexes \
    '[
      {
        "IndexName": "email-index",
        "KeySchema": [{"AttributeName": "email", "KeyType": "HASH"}],
        "Projection": {"ProjectionType": "ALL"}
      },
      {
        "IndexName": "realm-index",
        "KeySchema": [{"AttributeName": "realm_id", "KeyType": "HASH"}],
        "Projection": {"ProjectionType": "ALL"}
      }
    ]' \
  --billing-mode PAY_PER_REQUEST \
  --region eu-central-1

# Realms table
aws dynamodb create-table \
  --table-name zalt-realms \
  --attribute-definitions \
    AttributeName=id,AttributeType=S \
  --key-schema \
    AttributeName=id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region eu-central-1

# Sessions table with TTL
aws dynamodb create-table \
  --table-name zalt-sessions \
  --attribute-definitions \
    AttributeName=id,AttributeType=S \
    AttributeName=user_id,AttributeType=S \
  --key-schema \
    AttributeName=id,KeyType=HASH \
  --global-secondary-indexes \
    '[
      {
        "IndexName": "user-index",
        "KeySchema": [{"AttributeName": "user_id", "KeyType": "HASH"}],
        "Projection": {"ProjectionType": "ALL"}
      }
    ]' \
  --billing-mode PAY_PER_REQUEST \
  --region eu-central-1

# Enable TTL on sessions table
aws dynamodb update-time-to-live \
  --table-name zalt-sessions \
  --time-to-live-specification "Enabled=true, AttributeName=ttl" \
  --region eu-central-1
```

### 2. Create Secrets Manager Secret

```bash
# Generate JWT secrets
JWT_ACCESS_SECRET=$(openssl rand -base64 64)
JWT_REFRESH_SECRET=$(openssl rand -base64 64)

# Create secret
aws secretsmanager create-secret \
  --name zalt/jwt-secrets \
  --secret-string "{\"access_secret\":\"$JWT_ACCESS_SECRET\",\"refresh_secret\":\"$JWT_REFRESH_SECRET\"}" \
  --region eu-central-1
```

### 3. Create S3 Bucket for Deployment

```bash
aws s3 mb s3://zalt-deployment-artifacts --region eu-central-1
```

## Lambda Deployment

### Using SAM CLI

```bash
# Build
sam build

# Deploy (first time - guided)
sam deploy --guided

# Deploy (subsequent)
sam deploy
```

### SAM Configuration (samconfig.toml)

```toml
version = 0.1

[default.deploy.parameters]
stack_name = "zalt-platform"
region = "eu-central-1"
confirm_changeset = true
capabilities = "CAPABILITY_IAM"
s3_bucket = "zalt-deployment-artifacts"
s3_prefix = "zalt"
```

## API Gateway Configuration

### Custom Domain Setup

```bash
# Create ACM certificate (must be in us-east-1 for CloudFront)
aws acm request-certificate \
  --domain-name api.auth.hsdcore.com \
  --validation-method DNS \
  --region us-east-1

# After DNS validation, create custom domain
aws apigateway create-domain-name \
  --domain-name api.auth.hsdcore.com \
  --regional-certificate-arn arn:aws:acm:eu-central-1:xxx:certificate/xxx \
  --endpoint-configuration types=REGIONAL \
  --region eu-central-1

# Create base path mapping
aws apigateway create-base-path-mapping \
  --domain-name api.auth.hsdcore.com \
  --rest-api-id YOUR_API_ID \
  --stage prod \
  --region eu-central-1
```

### CORS Configuration

CORS is configured in the Lambda handlers. Allowed origins:
- `https://dashboard.auth.hsdcore.com`
- `https://portal.hsdcore.com`
- `https://chat.hsdcore.com`
- `https://tasks.hsdcore.com`
- `https://docs.hsdcore.com`
- `https://crm.hsdcore.com`

## Dashboard Deployment

### Build Dashboard

```bash
cd dashboard
npm run build
```

### Deploy to Vercel (Recommended)

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod
```

### Deploy to AWS (EKS/ECS)

```bash
# Build Docker image
docker build -t zalt-dashboard .

# Push to ECR
aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin YOUR_ACCOUNT.dkr.ecr.eu-central-1.amazonaws.com
docker tag zalt-dashboard:latest YOUR_ACCOUNT.dkr.ecr.eu-central-1.amazonaws.com/zalt-dashboard:latest
docker push YOUR_ACCOUNT.dkr.ecr.eu-central-1.amazonaws.com/zalt-dashboard:latest
```

## Environment Variables

### Lambda Functions

Set these in the SAM template or AWS Console:

```yaml
Environment:
  Variables:
    USERS_TABLE: zalt-users
    REALMS_TABLE: zalt-realms
    SESSIONS_TABLE: zalt-sessions
    JWT_SECRET_ARN: arn:aws:secretsmanager:eu-central-1:xxx:secret:zalt/jwt-secrets
    ALLOWED_ORIGINS: https://dashboard.auth.hsdcore.com,https://portal.hsdcore.com
```

### Dashboard

Create `.env.production`:

```bash
NEXT_PUBLIC_API_URL=https://api.auth.hsdcore.com
JWT_SECRET=your-dashboard-jwt-secret
```

## Monitoring Setup

### CloudWatch Alarms

```bash
# High error rate alarm
aws cloudwatch put-metric-alarm \
  --alarm-name zalt-high-error-rate \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:eu-central-1:xxx:hsd-alerts

# High latency alarm
aws cloudwatch put-metric-alarm \
  --alarm-name zalt-high-latency \
  --metric-name Duration \
  --namespace AWS/Lambda \
  --statistic Average \
  --period 300 \
  --threshold 1000 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:eu-central-1:xxx:hsd-alerts
```

### Enable X-Ray Tracing

```yaml
# In SAM template
Globals:
  Function:
    Tracing: Active
```

## Backup Configuration

### DynamoDB Point-in-Time Recovery

```bash
aws dynamodb update-continuous-backups \
  --table-name zalt-users \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true

aws dynamodb update-continuous-backups \
  --table-name zalt-realms \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true

aws dynamodb update-continuous-backups \
  --table-name zalt-sessions \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true
```

### Scheduled Backups

```bash
# Create backup plan
aws backup create-backup-plan \
  --backup-plan '{
    "BackupPlanName": "zalt-daily-backup",
    "Rules": [{
      "RuleName": "DailyBackup",
      "TargetBackupVaultName": "Default",
      "ScheduleExpression": "cron(0 5 ? * * *)",
      "StartWindowMinutes": 60,
      "CompletionWindowMinutes": 120,
      "Lifecycle": {
        "DeleteAfterDays": 30
      }
    }]
  }'
```

## Rollback Procedures

### Lambda Rollback

```bash
# List versions
aws lambda list-versions-by-function --function-name zalt-login

# Update alias to previous version
aws lambda update-alias \
  --function-name zalt-login \
  --name prod \
  --function-version 5
```

### Full Stack Rollback

```bash
# Rollback CloudFormation stack
aws cloudformation rollback-stack --stack-name zalt-platform
```

## Health Checks

### API Health Endpoint

```bash
curl https://api.auth.hsdcore.com/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "services": {
    "dynamodb": "healthy",
    "secrets_manager": "healthy"
  }
}
```

## Cost Optimization

### Estimated Monthly Costs

| Service | Estimated Cost |
|---------|---------------|
| Lambda | $5-15 |
| API Gateway | $10-20 |
| DynamoDB | $15-30 |
| Secrets Manager | $1 |
| CloudWatch | $5-10 |
| **Total** | **$36-76** |

### Cost Reduction Tips

1. Use DynamoDB on-demand pricing for variable workloads
2. Enable Lambda Provisioned Concurrency only for critical functions
3. Set appropriate CloudWatch log retention (14-30 days)
4. Use reserved capacity for predictable workloads
