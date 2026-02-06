# Auth Endpoints Deployment - Design Document

## Overview

Bu doküman, mevcut handler'ların AWS'ye deploy edilmesi için gerekli infrastructure değişikliklerini tanımlar.

**Kritik:** Kod YAZILMIŞ, sadece deployment eksik!

---

## ARCHITECTURE

### Mevcut Lambda Yapısı

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MEVCUT LAMBDA FUNCTIONS                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ zalt-register│  │  zalt-login  │  │ zalt-refresh │  │  zalt-logout │   │
│  │   /register  │  │    /login    │  │   /refresh   │  │   /logout    │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                      │
│  │  zalt-admin  │  │   zalt-sso   │  │ zalt-health  │                      │
│  │  /v1/admin/* │  │   /oauth/*   │  │   /health/*  │                      │
│  └──────────────┘  └──────────────┘  └──────────────┘                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Yeni Lambda Yapısı (Eklenecek)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         YENİ LAMBDA FUNCTIONS                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                           zalt-mfa                                    │  │
│  │  POST /v1/auth/mfa/setup         → mfaSetupHandler                   │  │
│  │  POST /v1/auth/mfa/verify        → mfaVerifyHandler                  │  │
│  │  POST /v1/auth/mfa/disable       → mfaDisableHandler                 │  │
│  │  POST /v1/auth/mfa/login/verify  → mfaLoginVerifyHandler             │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                      zalt-password-reset                              │  │
│  │  POST /v1/auth/password-reset/request  → requestPasswordResetHandler │  │
│  │  POST /v1/auth/password-reset/confirm  → confirmPasswordResetHandler │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                      zalt-verify-email                                │  │
│  │  POST /v1/auth/verify-email/send    → sendVerificationCodeHandler    │  │
│  │  POST /v1/auth/verify-email/confirm → confirmVerificationHandler     │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                         zalt-webauthn                                 │  │
│  │  POST /v1/auth/webauthn/register/options     → registerOptions       │  │
│  │  POST /v1/auth/webauthn/register/verify      → registerVerify        │  │
│  │  POST /v1/auth/webauthn/authenticate/options → authenticateOptions   │  │
│  │  POST /v1/auth/webauthn/authenticate/verify  → authenticateVerify    │  │
│  │  GET  /v1/auth/webauthn/credentials          → listCredentials       │  │
│  │  DELETE /v1/auth/webauthn/credentials/{id}   → deleteCredential      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## LAMBDA FUNCTION SPECIFICATIONS

### 1. zalt-mfa Lambda

```yaml
FunctionName: zalt-mfa
Handler: mfa-handler.handler
CodeUri: src/handlers/
MemorySize: 256
Timeout: 30
AutoPublishAlias: live
ProvisionedConcurrencyConfig:
  ProvisionedConcurrentExecutions: 3

Policies:
  - DynamoDB: zalt-users (GetItem, PutItem, UpdateItem, Query)
  - DynamoDB: zalt-sessions (GetItem, PutItem, UpdateItem, Query, Scan)
  - DynamoDB: zalt-realms (GetItem)
  - SecretsManager: zalt/jwt-secrets (GetSecretValue)
  - KMS: fa16a08f-aa50-4113-af73-155a31d13d49 (Sign, Verify, GetPublicKey)

Events:
  - POST /v1/auth/mfa/setup
  - POST /v1/auth/mfa/verify
  - POST /v1/auth/mfa/disable
  - POST /v1/auth/mfa/login/verify
```

### 2. zalt-password-reset Lambda

```yaml
FunctionName: zalt-password-reset
Handler: password-reset-handler.handler
CodeUri: src/handlers/
MemorySize: 512  # Argon2id için yüksek memory
Timeout: 30
AutoPublishAlias: live
ProvisionedConcurrencyConfig:
  ProvisionedConcurrentExecutions: 3

Policies:
  - DynamoDB: zalt-users (GetItem, PutItem, UpdateItem, Query)
  - DynamoDB: zalt-sessions (DeleteItem, Query, Scan)
  - DynamoDB: zalt-realms (GetItem)
  - SES: SendEmail, SendRawEmail
  - SecretsManager: zalt/jwt-secrets (GetSecretValue)

Events:
  - POST /v1/auth/password-reset/request
  - POST /v1/auth/password-reset/confirm
```

### 3. zalt-verify-email Lambda

```yaml
FunctionName: zalt-verify-email
Handler: verify-email-handler.handler
CodeUri: src/handlers/
MemorySize: 256
Timeout: 30
AutoPublishAlias: live
ProvisionedConcurrencyConfig:
  ProvisionedConcurrentExecutions: 3

Policies:
  - DynamoDB: zalt-users (GetItem, UpdateItem, Query)
  - DynamoDB: zalt-realms (GetItem)
  - SES: SendEmail, SendRawEmail
  - SecretsManager: zalt/jwt-secrets (GetSecretValue)
  - KMS: fa16a08f-aa50-4113-af73-155a31d13d49 (Verify, GetPublicKey)

Events:
  - POST /v1/auth/verify-email/send
  - POST /v1/auth/verify-email/confirm
```

### 4. zalt-webauthn Lambda

```yaml
FunctionName: zalt-webauthn
Handler: webauthn-handler.handler
CodeUri: src/handlers/
MemorySize: 256
Timeout: 30
AutoPublishAlias: live
ProvisionedConcurrencyConfig:
  ProvisionedConcurrentExecutions: 3

Policies:
  - DynamoDB: zalt-users (GetItem, PutItem, UpdateItem, Query)
  - DynamoDB: zalt-sessions (GetItem, PutItem, UpdateItem, Query)
  - DynamoDB: zalt-realms (GetItem)
  - SecretsManager: zalt/jwt-secrets (GetSecretValue)
  - KMS: fa16a08f-aa50-4113-af73-155a31d13d49 (Sign, Verify, GetPublicKey)

Events:
  - POST /v1/auth/webauthn/register/options
  - POST /v1/auth/webauthn/register/verify
  - POST /v1/auth/webauthn/authenticate/options
  - POST /v1/auth/webauthn/authenticate/verify
  - GET /v1/auth/webauthn/credentials
  - DELETE /v1/auth/webauthn/credentials/{id}
```

---

## WAF CONFIGURATION UPDATE

### Mevcut AllowKnownPaths Rule

```yaml
# Mevcut izin verilen path'ler:
- /login
- /register
- /refresh
- /logout
- /v1/admin/
- /oauth/
- /.well-known/
```

### Güncellenmiş AllowKnownPaths Rule

```yaml
# Eklenecek path'ler:
- /v1/auth/mfa/
- /v1/auth/password-reset/
- /v1/auth/verify-email/
- /v1/auth/webauthn/
```

---

## HANDLER ROUTING DESIGN

### mfa-handler.ts Router

```typescript
// src/handlers/mfa-handler.ts
export const handler = async (event: APIGatewayProxyEvent) => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'POST' && path === '/v1/auth/mfa/setup') {
    return mfaSetupHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/verify') {
    return mfaVerifyHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/disable') {
    return mfaDisableHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/login/verify') {
    return mfaLoginVerifyHandler(event);
  }

  return { statusCode: 404, body: '404 page not found' };
};
```

### password-reset-handler.ts Router

```typescript
// src/handlers/password-reset-handler.ts
export const handler = async (event: APIGatewayProxyEvent) => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'POST' && path === '/v1/auth/password-reset/request') {
    return requestPasswordResetHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/password-reset/confirm') {
    return confirmPasswordResetHandler(event);
  }

  return { statusCode: 404, body: '404 page not found' };
};
```

### verify-email-handler.ts Router

```typescript
// src/handlers/verify-email-handler.ts
export const handler = async (event: APIGatewayProxyEvent) => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'POST' && path === '/v1/auth/verify-email/send') {
    return sendVerificationCodeHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/verify-email/confirm') {
    return confirmVerificationHandler(event);
  }

  return { statusCode: 404, body: '404 page not found' };
};
```

### webauthn-handler.ts Router

```typescript
// src/handlers/webauthn-handler.ts
export const handler = async (event: APIGatewayProxyEvent) => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'POST' && path === '/v1/auth/webauthn/register/options') {
    return webauthnRegisterOptionsHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/webauthn/register/verify') {
    return webauthnRegisterVerifyHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/webauthn/authenticate/options') {
    return webauthnAuthenticateOptionsHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/webauthn/authenticate/verify') {
    return webauthnAuthenticateVerifyHandler(event);
  }
  if (method === 'GET' && path === '/v1/auth/webauthn/credentials') {
    return webauthnListCredentialsHandler(event);
  }
  if (method === 'DELETE' && path.startsWith('/v1/auth/webauthn/credentials/')) {
    return webauthnDeleteCredentialHandler(event);
  }

  return { statusCode: 404, body: '404 page not found' };
};
```

---

## ESBUILD CONFIGURATION

Her Lambda için esbuild metadata:

```yaml
Metadata:
  BuildMethod: esbuild
  BuildProperties:
    Minify: true
    Target: "es2022"
    Sourcemap: false
    EntryPoints:
      - <handler-file>.ts
    External:
      - "@aws-sdk/*"
      - "argon2"
      - "mock-aws-s3"
      - "aws-sdk"
      - "nock"
```

---

## RATE LIMITING (WAF)

### Yeni Rate Limit Rules

```yaml
# MFA Verify Rate Limit (5/min/IP)
- Name: RateLimitMFAVerify
  Priority: 7
  Statement:
    RateBasedStatement:
      Limit: 100  # WAF minimum
      AggregateKeyType: IP
      ScopeDownStatement:
        ByteMatchStatement:
          SearchString: /v1/auth/mfa/
          FieldToMatch:
            UriPath: {}
          PositionalConstraint: STARTS_WITH

# Password Reset Rate Limit (3/hour/IP)
- Name: RateLimitPasswordReset
  Priority: 8
  Statement:
    RateBasedStatement:
      Limit: 100
      AggregateKeyType: IP
      ScopeDownStatement:
        ByteMatchStatement:
          SearchString: /v1/auth/password-reset/
          FieldToMatch:
            UriPath: {}
          PositionalConstraint: STARTS_WITH
```

---

## SDK LOCAL BUILD

### Build Steps

```bash
# 1. SDK dizinine git
cd src/sdk

# 2. Dependencies install
npm install

# 3. TypeScript build
npm run build

# 4. Local link oluştur
npm link

# 5. Test project'te kullan
cd /path/to/test-project
npm link @zalt/auth-sdk
```

### SDK Package.json

```json
{
  "name": "@zalt/auth-sdk",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": ["dist"],
  "scripts": {
    "build": "tsc",
    "prepublishOnly": "npm run build"
  }
}
```

---

## DEPLOYMENT SEQUENCE

```
1. Handler router dosyalarını oluştur/güncelle
   ├── mfa-handler.ts (router ekle)
   ├── password-reset-handler.ts (router ekle)
   ├── verify-email-handler.ts (router ekle)
   └── webauthn-handler.ts (router ekle)

2. template.yaml güncelle
   ├── 4 yeni Lambda function ekle
   ├── API Gateway events ekle
   └── WAF AllowKnownPaths güncelle

3. SAM Build
   └── sam build

4. SAM Deploy
   └── sam deploy --guided (veya MCP ile)

5. Test
   ├── curl ile endpoint'leri test et
   └── E2E testleri çalıştır

6. SDK Build
   ├── cd src/sdk
   ├── npm run build
   └── npm link
```

