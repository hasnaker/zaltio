# HSD Auth Platform - Architecture Guide

## System Overview

The HSD Auth Platform is a multi-tenant Authentication-as-a-Service system built on AWS serverless technologies.

## Architecture Diagram

```
                                    ┌─────────────────────────────────────┐
                                    │         Client Applications         │
                                    │  (Portal, Chat, Tasks, Docs, CRM)   │
                                    └─────────────────┬───────────────────┘
                                                      │
                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              AWS Cloud (eu-central-1)                           │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                           Route 53 DNS                                     │  │
│  │  auth.hsdcore.com → CloudFront                                            │  │
│  │  api.auth.hsdcore.com → API Gateway                                       │  │
│  │  dashboard.auth.hsdcore.com → CloudFront/Vercel                           │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                      │                                          │
│                    ┌─────────────────┼─────────────────┐                       │
│                    ▼                 ▼                 ▼                       │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐    │
│  │    CloudFront CDN   │  │    API Gateway      │  │   Dashboard (EKS)   │    │
│  │   (Static Assets)   │  │   (REST API)        │  │   (Next.js App)     │    │
│  └─────────────────────┘  └──────────┬──────────┘  └─────────────────────┘    │
│                                      │                                          │
│                                      ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                         Lambda Functions                                   │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │  │
│  │  │ Register │ │  Login   │ │ Refresh  │ │  Logout  │ │  Admin   │        │  │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘        │  │
│  │       │            │            │            │            │               │  │
│  └───────┼────────────┼────────────┼────────────┼────────────┼───────────────┘  │
│          │            │            │            │            │                  │
│          └────────────┴────────────┼────────────┴────────────┘                  │
│                                    ▼                                            │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                           Data Layer                                       │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │  │
│  │  │   DynamoDB      │  │   DynamoDB      │  │   DynamoDB      │            │  │
│  │  │   (Users)       │  │   (Realms)      │  │   (Sessions)    │            │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘            │  │
│  │                                                                            │  │
│  │  ┌─────────────────┐  ┌─────────────────┐                                 │  │
│  │  │ Secrets Manager │  │   CloudWatch    │                                 │  │
│  │  │  (JWT Keys)     │  │   (Logs/Metrics)│                                 │  │
│  │  └─────────────────┘  └─────────────────┘                                 │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Component Details

### API Gateway

**Purpose:** Entry point for all API requests

**Configuration:**
- Regional endpoint in eu-central-1
- Custom domain: api.auth.hsdcore.com
- Request validation enabled
- Usage plans for rate limiting
- API keys for client identification

**Endpoints:**
```
POST /auth/register     → auth-register Lambda
POST /auth/login        → auth-login Lambda
POST /auth/refresh      → auth-refresh Lambda
POST /auth/logout       → auth-logout Lambda
GET  /auth/me           → auth-profile Lambda
*    /admin/*           → auth-admin Lambda
*    /sso/*             → auth-sso Lambda
GET  /health            → auth-health Lambda
```

### Lambda Functions

| Function | Purpose | Memory | Timeout |
|----------|---------|--------|---------|
| auth-register | User registration | 256 MB | 10s |
| auth-login | User authentication | 256 MB | 10s |
| auth-refresh | Token refresh | 128 MB | 5s |
| auth-logout | Session termination | 128 MB | 5s |
| auth-admin | Admin operations | 512 MB | 30s |
| auth-sso | SSO handling | 256 MB | 15s |
| auth-health | Health checks | 128 MB | 5s |

**Shared Layers:**
- `zalt-common` - Shared utilities, models, services
- `zalt-deps` - Node.js dependencies

### DynamoDB Tables

#### Users Table (zalt-users)

```
Primary Key:
  PK: realm_id#user_id
  SK: USER#created_at

Global Secondary Indexes:
  email-index: email (HASH)
  realm-index: realm_id (HASH)

Attributes:
  - id: string
  - realm_id: string
  - email: string (encrypted)
  - password_hash: string
  - email_verified: boolean
  - status: string (active|suspended|pending)
  - profile: map
  - mfa_enabled: boolean
  - mfa_secret: string (encrypted)
  - created_at: string
  - updated_at: string
  - last_login: string
```

#### Realms Table (zalt-realms)

```
Primary Key:
  id: string (HASH)

Attributes:
  - id: string
  - name: string
  - domain: string
  - settings: map
    - password_policy: map
    - session_timeout: number
    - mfa_required: boolean
    - allowed_origins: list
  - auth_providers: list
  - created_at: string
  - updated_at: string
```

#### Sessions Table (zalt-sessions)

```
Primary Key:
  id: string (HASH)

Global Secondary Indexes:
  user-index: user_id (HASH)

Attributes:
  - id: string
  - user_id: string
  - realm_id: string
  - refresh_token_hash: string
  - ip_address: string
  - user_agent: string
  - created_at: string
  - expires_at: string
  - ttl: number (for auto-deletion)
```

### Dashboard (Next.js)

**Deployment Options:**
1. Vercel (recommended for simplicity)
2. AWS EKS (for full AWS integration)
3. AWS Amplify

**Features:**
- Realm management
- User management
- Session monitoring
- Analytics dashboard
- Admin role management
- Real-time notifications

## Data Flow

### Registration Flow

```
1. Client → API Gateway: POST /auth/register
2. API Gateway → Lambda (auth-register)
3. Lambda validates input
4. Lambda checks email uniqueness in DynamoDB
5. Lambda hashes password (bcrypt)
6. Lambda creates user in DynamoDB
7. Lambda generates JWT tokens
8. Lambda creates session in DynamoDB
9. Lambda → API Gateway: 201 Created
10. API Gateway → Client: User + Tokens
```

### Login Flow

```
1. Client → API Gateway: POST /auth/login
2. API Gateway → Lambda (auth-login)
3. Lambda validates input
4. Lambda fetches user from DynamoDB
5. Lambda verifies password
6. Lambda checks MFA if enabled
7. Lambda generates JWT tokens
8. Lambda creates session in DynamoDB
9. Lambda logs security event
10. Lambda → API Gateway: 200 OK
11. API Gateway → Client: User + Tokens
```

### Token Refresh Flow

```
1. Client → API Gateway: POST /auth/refresh
2. API Gateway → Lambda (auth-refresh)
3. Lambda validates refresh token
4. Lambda fetches session from DynamoDB
5. Lambda verifies session is valid
6. Lambda generates new tokens
7. Lambda updates session (token rotation)
8. Lambda → API Gateway: 200 OK
9. API Gateway → Client: New Tokens
```

## Multi-Tenancy

### Realm Isolation

Each realm (tenant) has:
- Isolated user data (partition key includes realm_id)
- Custom authentication settings
- Separate password policies
- Independent session management
- Custom allowed origins

### Data Partitioning

```
Users Table Partition Strategy:
  PK = realm_id#user_id
  
  Example:
  - realm-portal#user-001
  - realm-chat#user-001
  - realm-tasks#user-002
```

This ensures:
- No cross-realm data access
- Efficient queries within a realm
- Scalable per-realm operations

## Scalability

### Lambda Scaling

- Automatic scaling based on requests
- Provisioned concurrency for critical functions
- Reserved concurrency to prevent noisy neighbors

### DynamoDB Scaling

- On-demand capacity mode
- Auto-scaling for provisioned mode
- Global tables for multi-region (future)

### API Gateway Scaling

- Automatic scaling
- Regional deployment
- Edge-optimized for global access (future)

## High Availability

### Current Setup (Single Region)

- Lambda: Multi-AZ by default
- DynamoDB: Multi-AZ replication
- API Gateway: Regional with multiple AZs

### Future: Multi-Region

```
┌─────────────────┐     ┌─────────────────┐
│  eu-central-1   │     │   us-east-1     │
│  (Primary)      │────▶│   (Secondary)   │
│                 │     │                 │
│  - Lambda       │     │  - Lambda       │
│  - DynamoDB     │     │  - DynamoDB     │
│  - API Gateway  │     │  - API Gateway  │
└─────────────────┘     └─────────────────┘
         │                       │
         └───────────┬───────────┘
                     ▼
              Route 53 (Latency-based routing)
```

## Monitoring & Observability

### Metrics

- Lambda: Invocations, Duration, Errors, Throttles
- API Gateway: Requests, Latency, 4xx/5xx errors
- DynamoDB: Read/Write capacity, Throttles

### Logging

- Structured JSON logs
- Correlation IDs for request tracing
- Log levels: ERROR, WARN, INFO, DEBUG

### Alerting

- CloudWatch Alarms for critical metrics
- SNS notifications to Slack/Email
- PagerDuty integration for on-call

## Cost Optimization

### Current Architecture Costs

| Component | Monthly Cost |
|-----------|-------------|
| Lambda | $5-15 |
| API Gateway | $10-20 |
| DynamoDB | $15-30 |
| Secrets Manager | $1 |
| CloudWatch | $5-10 |
| **Total** | **$36-76** |

### Optimization Strategies

1. **Lambda:** Use ARM64 (Graviton2) for 20% cost reduction
2. **DynamoDB:** Use on-demand for variable workloads
3. **CloudWatch:** Set appropriate log retention
4. **API Gateway:** Use caching for read-heavy endpoints
