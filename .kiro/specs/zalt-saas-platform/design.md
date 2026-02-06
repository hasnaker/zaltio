# Design Document: Zalt SaaS Platform

## Overview

Zalt.io'yu Clerk benzeri self-service SaaS platformuna dönüştürme. Müşteri gelir, register olur, SDK kurar, kullanır.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        zalt.io (Dashboard)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Signup  │  │  Login   │  │ Dashboard │  │   Docs   │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────────┘        │
│       │             │             │                              │
│       └─────────────┴─────────────┘                              │
│                     │                                            │
└─────────────────────┼────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     api.zalt.io (Backend)                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Platform APIs (Customer)                 │   │
│  │  POST /platform/register  - Customer signup               │   │
│  │  POST /platform/login     - Customer login                │   │
│  │  GET  /platform/me        - Customer profile              │   │
│  │  GET  /platform/api-keys  - List API keys                 │   │
│  │  POST /platform/api-keys  - Create API key                │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  End-User APIs (SDK calls)                │   │
│  │  POST /register  - End-user signup (with API key)         │   │
│  │  POST /login     - End-user login (with API key)          │   │
│  │  GET  /me        - End-user profile                       │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                        DynamoDB Tables                           │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐    │
│  │ zalt-      │  │ zalt-      │  │ zalt-      │    │
│  │ customers      │  │ api-keys       │  │ users          │    │
│  └────────────────┘  └────────────────┘  └────────────────┘    │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐    │
│  │ zalt-      │  │ zalt-      │  │ zalt-      │    │
│  │ realms         │  │ sessions       │  │ usage          │    │
│  └────────────────┘  └────────────────┘  └────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Data Models

### Customer (Platform User)

```typescript
interface Customer {
  PK: `CUSTOMER#${string}`;           // CUSTOMER#cust_abc123
  SK: 'PROFILE';
  customer_id: string;                 // cust_abc123
  email: string;
  password_hash: string;               // Argon2id
  company_name: string;
  plan: 'free' | 'pro' | 'enterprise';
  stripe_customer_id?: string;
  default_realm_id: string;
  created_at: string;
  updated_at: string;
}

// GSI: email-index
// PK: email, SK: customer_id
```

### API Key

```typescript
interface ApiKey {
  PK: `APIKEY#${string}`;             // APIKEY#key_xyz789
  SK: `CUSTOMER#${string}`;           // CUSTOMER#cust_abc123
  key_id: string;                      // key_xyz789
  customer_id: string;
  realm_id?: string;                   // null = all realms
  type: 'publishable' | 'secret';
  key_prefix: string;                  // pk_live_abc... (first 20 chars)
  key_hash?: string;                   // Only for secret keys
  name: string;
  status: 'active' | 'revoked';
  last_used_at?: string;
  created_at: string;
}

// GSI: customer-keys-index
// PK: customer_id, SK: key_id

// GSI: key-lookup-index  
// PK: key_prefix, SK: key_id
```

### Usage Record

```typescript
interface UsageRecord {
  PK: `CUSTOMER#${string}`;           // CUSTOMER#cust_abc123
  SK: `USAGE#${string}`;              // USAGE#2026-01
  customer_id: string;
  month: string;                       // 2026-01
  mau: number;
  api_calls: number;
  realms_count: number;
  updated_at: string;
}
```

## API Key Format

```
Publishable Key: pk_live_<realm_id>_<random_24_chars>
Secret Key:      sk_live_<realm_id>_<random_24_chars>

Example:
pk_live_clinisyn_a1b2c3d4e5f6g7h8i9j0k1l2
sk_live_clinisyn_m3n4o5p6q7r8s9t0u1v2w3x4
```

## Components

### 1. Platform Handler (Lambda)

```typescript
// src/handlers/platform-handler.ts

export async function handler(event: APIGatewayProxyEvent) {
  const path = event.path;
  const method = event.httpMethod;

  // Customer Registration
  if (path === '/platform/register' && method === 'POST') {
    return registerCustomer(event);
  }

  // Customer Login
  if (path === '/platform/login' && method === 'POST') {
    return loginCustomer(event);
  }

  // Customer Profile (requires auth)
  if (path === '/platform/me' && method === 'GET') {
    return getCustomerProfile(event);
  }

  // API Keys CRUD
  if (path === '/platform/api-keys') {
    if (method === 'GET') return listApiKeys(event);
    if (method === 'POST') return createApiKey(event);
  }

  if (path.match(/\/platform\/api-keys\/[\w-]+/) && method === 'DELETE') {
    return revokeApiKey(event);
  }
}
```

### 2. Customer Registration Flow

```typescript
async function registerCustomer(event) {
  const { email, password, company_name } = JSON.parse(event.body);

  // 1. Check if email exists
  const existing = await findCustomerByEmail(email);
  if (existing) throw new Error('Email already registered');

  // 2. Create customer
  const customer_id = `cust_${generateId()}`;
  const password_hash = await hashPassword(password);

  // 3. Create default realm
  const realm_id = slugify(company_name);
  await createRealm({
    realm_id,
    customer_id,
    name: company_name,
    mfa_policy: 'optional'
  });

  // 4. Generate API keys
  const publishableKey = generateApiKey('publishable', realm_id);
  const secretKey = generateApiKey('secret', realm_id);

  await saveApiKey({
    key_id: `key_${generateId()}`,
    customer_id,
    realm_id,
    type: 'publishable',
    key_prefix: publishableKey.substring(0, 24),
    name: 'Default Publishable Key'
  });

  await saveApiKey({
    key_id: `key_${generateId()}`,
    customer_id,
    realm_id,
    type: 'secret',
    key_prefix: secretKey.substring(0, 24),
    key_hash: await hashApiKey(secretKey),
    name: 'Default Secret Key'
  });

  // 5. Save customer
  await saveCustomer({
    customer_id,
    email,
    password_hash,
    company_name,
    plan: 'free',
    default_realm_id: realm_id
  });

  // 6. Return with keys (only time secret is shown)
  return {
    customer_id,
    email,
    company_name,
    realm_id,
    publishable_key: publishableKey,
    secret_key: secretKey  // Only shown once!
  };
}
```

### 3. API Key Validation Middleware

```typescript
// For SDK requests - validate publishable key
async function validatePublishableKey(event) {
  const apiKey = event.headers['x-zalt-publishable-key'];
  if (!apiKey?.startsWith('pk_live_')) {
    throw new Error('Invalid publishable key');
  }

  const keyPrefix = apiKey.substring(0, 24);
  const keyRecord = await findApiKeyByPrefix(keyPrefix);
  
  if (!keyRecord || keyRecord.status !== 'active') {
    throw new Error('Invalid or revoked API key');
  }

  // Update last_used_at
  await updateApiKeyLastUsed(keyRecord.key_id);

  return {
    customer_id: keyRecord.customer_id,
    realm_id: keyRecord.realm_id
  };
}

// For backend requests - validate secret key
async function validateSecretKey(event) {
  const apiKey = event.headers['x-zalt-secret-key'];
  if (!apiKey?.startsWith('sk_live_')) {
    throw new Error('Invalid secret key');
  }

  const keyPrefix = apiKey.substring(0, 24);
  const keyRecord = await findApiKeyByPrefix(keyPrefix);
  
  if (!keyRecord || keyRecord.status !== 'active') {
    throw new Error('Invalid or revoked API key');
  }

  // Verify hash
  const isValid = await verifyApiKeyHash(apiKey, keyRecord.key_hash);
  if (!isValid) {
    throw new Error('Invalid API key');
  }

  return {
    customer_id: keyRecord.customer_id,
    realm_id: keyRecord.realm_id
  };
}
```

### 4. SDK Integration

```typescript
// @zalt.io/core - ZaltClient

export class ZaltClient {
  private publishableKey: string;
  private baseUrl = 'https://api.zalt.io';

  constructor(config: { publishableKey: string }) {
    this.publishableKey = config.publishableKey;
  }

  private async request(path: string, options: RequestInit = {}) {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'x-zalt-publishable-key': this.publishableKey,
        ...options.headers
      }
    });
    return response.json();
  }

  async login(email: string, password: string) {
    return this.request('/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
  }

  async register(email: string, password: string) {
    return this.request('/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
  }

  async getUser(accessToken: string) {
    return this.request('/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
  }
}
```

## Correctness Properties

### Property 1: Customer Email Uniqueness
*For any* email address, there SHALL be at most one customer account.
**Validates: Requirements 1.2**

### Property 2: API Key Uniqueness
*For any* API key prefix, there SHALL be exactly one key record.
**Validates: Requirements 4.2**

### Property 3: Realm Isolation
*For any* end-user, they SHALL only exist in one realm and cannot access other realms.
**Validates: Requirements 3.1, 6.1**

### Property 4: API Key Validation
*For any* SDK request with publishable key, the system SHALL validate the key and extract realm_id.
**Validates: Requirements 5.2**

## Error Handling

| Error | HTTP | Message |
|-------|------|---------|
| EMAIL_EXISTS | 409 | Email already registered |
| INVALID_CREDENTIALS | 401 | Invalid email or password |
| INVALID_API_KEY | 401 | Invalid or revoked API key |
| PLAN_LIMIT_EXCEEDED | 403 | Plan limit exceeded |
| REALM_NOT_FOUND | 404 | Realm not found |

## Testing Strategy

### Unit Tests
- Customer registration logic
- API key generation and validation
- Password hashing

### Integration Tests
- Full registration flow
- SDK → Backend communication
- API key CRUD

### E2E Tests
- Customer signup → onboarding → SDK integration
- End-user login via SDK
