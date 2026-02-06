# Zalt

Modern Authentication-as-a-Service platform. Simple, secure, and scalable authentication for your applications.

## Overview

Zalt provides:
- 🔐 Multi-tenant authentication with realm isolation
- 🚀 Serverless architecture on AWS (Lambda, DynamoDB, API Gateway)
- 📊 Administrative dashboard for user and realm management
- 📦 Official SDKs for JavaScript/TypeScript and Python
- 🔒 Enterprise-grade security with encryption, MFA, and audit logging
- 🌍 GDPR compliant data handling

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                            Zalt                                 │
├─────────────────────────────────────────────────────────────────┤
│  Clients                                                        │
│  ├── Your web & mobile applications                             │
│  └── Third-party integrations                                   │
├─────────────────────────────────────────────────────────────────┤
│  API Layer                                                      │
│  ├── API Gateway (api.zalt.io)                                  │
│  ├── REST endpoints for auth operations                         │
│  └── Rate limiting & CORS                                       │
├─────────────────────────────────────────────────────────────────┤
│  Lambda Functions                                               │
│  ├── auth-register    - User registration                       │
│  ├── auth-login       - User authentication                     │
│  ├── auth-refresh     - Token refresh                           │
│  ├── auth-logout      - Session termination                     │
│  ├── auth-admin       - Administrative operations               │
│  └── auth-sso         - Single Sign-On                          │
├─────────────────────────────────────────────────────────────────┤
│  Data Layer                                                     │
│  ├── DynamoDB (zalt-users, zalt-realms, zalt-sessions)          │
│  └── Secrets Manager (JWT keys)                                 │
├─────────────────────────────────────────────────────────────────┤
│  Dashboard (app.zalt.io)                                        │
│  └── Next.js admin interface                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Domain Structure

| Domain | Purpose |
|--------|---------|
| `zalt.io` | Landing page / Marketing |
| `app.zalt.io` | Dashboard |
| `api.zalt.io` | API endpoints |
| `docs.zalt.io` | Documentation |

## Quick Start

### Prerequisites

- Node.js 18+
- AWS CLI configured
- Python 3.9+ (for Python SDK development)

### Installation

```bash
# Clone the repository
git clone https://github.com/zalt-io/zalt.git
cd zalt

# Install dependencies
npm install

# Install dashboard dependencies
cd dashboard && npm install && cd ..

# Set up environment variables
cp .env.example .env
```

### Development

```bash
# Run tests
npm test

# Run dashboard in development mode
cd dashboard && npm run dev

# Build for production
npm run build
```

### Deployment

```bash
# Deploy to AWS
./scripts/deploy.sh
```

## Project Structure

```
zalt/
├── src/
│   ├── config/          # Configuration files
│   ├── docs/            # Technical documentation
│   ├── handlers/        # Lambda function handlers
│   ├── middleware/      # Security & CORS middleware
│   ├── models/          # Data models
│   ├── repositories/    # Database access layer
│   ├── sdk/             # JavaScript/TypeScript SDK
│   │   └── python/      # Python SDK
│   ├── services/        # Business logic services
│   └── utils/           # Utility functions
├── dashboard/           # Next.js admin dashboard
├── scripts/             # Deployment scripts
├── template.yaml        # SAM template
└── .kiro/specs/         # Feature specifications
```

## Documentation

### Getting Started
| Document | Description |
|----------|-------------|
| [API Reference](src/docs/api-reference.md) | REST API endpoints |
| [OpenAPI Specification](src/docs/openapi.yaml) | OpenAPI 3.0 spec |
| [SDK Guide - JavaScript](src/sdk/README.md) | JavaScript/TypeScript SDK |
| [SDK Guide - Python](src/sdk/python/README.md) | Python SDK |
| [SDK Integration Guide](src/docs/sdk-integration-guide.md) | SDK usage examples |

### Administration
| Document | Description |
|----------|-------------|
| [Dashboard Guide](dashboard/README.md) | Admin dashboard usage |
| [Realm Management](src/docs/realm-management-guide.md) | Realm configuration |
| [Architecture Guide](src/docs/architecture-guide.md) | System architecture |

### Operations
| Document | Description |
|----------|-------------|
| [Deployment Guide](src/docs/deployment-guide.md) | AWS deployment |
| [Security Guide](src/docs/security-guide.md) | Security best practices |
| [SSO Integration](src/docs/sso-integration-guide.md) | Single Sign-On setup |
| [Disaster Recovery](src/docs/disaster-recovery-procedures.md) | DR procedures |
| [Troubleshooting](src/docs/troubleshooting-guide.md) | Common issues & solutions |
| [Migration Guide](src/docs/migration-guide.md) | Migrating from other systems |

### Development
| Document | Description |
|----------|-------------|
| [Contributing](CONTRIBUTING.md) | Contribution guidelines |
| [Changelog](CHANGELOG.md) | Version history |

## AWS Resources

| Resource | Name | Region |
|----------|------|--------|
| API Gateway | `zalt-api` | eu-central-1 |
| DynamoDB | `zalt-users` | eu-central-1 |
| DynamoDB | `zalt-realms` | eu-central-1 |
| DynamoDB | `zalt-sessions` | eu-central-1 |
| Secrets Manager | `zalt/jwt-secrets` | eu-central-1 |

## Environment Variables

```bash
# AWS Configuration
AWS_REGION=eu-central-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# API Configuration
API_GATEWAY_URL=https://api.zalt.io
JWT_SECRET_ARN=arn:aws:secretsmanager:eu-central-1:xxx:secret:zalt/jwt-secrets

# Dashboard Configuration
NEXT_PUBLIC_API_URL=https://api.zalt.io
```

## SDK Installation

### JavaScript/TypeScript

```bash
npm install @zalt/auth-sdk
```

```typescript
import { ZaltAuth } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  realmId: 'your-realm-id',
  baseUrl: 'https://api.zalt.io'
});

// Login
const session = await auth.login({
  email: 'user@example.com',
  password: 'password'
});
```

### Python

```bash
pip install zalt-auth
```

```python
from zalt_auth import ZaltAuth

auth = ZaltAuth(
    realm_id='your-realm-id',
    base_url='https://api.zalt.io'
)

# Login
session = auth.login(
    email='user@example.com',
    password='password'
)
```

## Contributing

1. Create a feature branch from `main`
2. Make your changes
3. Run tests: `npm test`
4. Submit a pull request

## License

MIT License - Zalt

---

Built with ❤️ by the Zalt team
