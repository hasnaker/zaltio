# Design Document

## Overview

Bu tasarım, Zalt.io Auth Platform Lambda fonksiyonlarının AWS'e düzgün deploy edilmesi için gerekli değişiklikleri tanımlar. Ana sorun SAM build'in TypeScript output'unu Lambda'ya yüklerken handler path'lerinin bozulması.

## Architecture

```
src/handlers/
├── login.handler.ts      → exports { handler }
├── register.handler.ts   → exports { handler }
├── refresh.handler.ts    → exports { handler }
├── logout.handler.ts     → exports { handler }
├── sso.handler.ts        → exports { handler }
├── admin.handler.ts      → exports { handler } (router)
└── health.handler.ts     → exports { healthHandler, livenessHandler, readinessHandler }

dist/handlers/
├── login.handler.js
├── register.handler.js
├── refresh.handler.js
├── logout.handler.js
├── sso.handler.js
├── admin.handler.js
└── health.handler.js
```

## Components and Interfaces

### Admin Handler Router

```typescript
// src/handlers/admin.handler.ts
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const path = event.path;
  const method = event.httpMethod;

  // Realm routes
  if (path === '/admin/realms' && method === 'GET') return listRealmsHandler(event);
  if (path === '/admin/realms' && method === 'POST') return createRealmHandler(event);
  if (path.match(/^\/admin\/realms\/[\w-]+$/) && method === 'GET') return getRealmHandler(event);
  if (path.match(/^\/admin\/realms\/[\w-]+$/) && method === 'PATCH') return updateRealmHandler(event);
  if (path.match(/^\/admin\/realms\/[\w-]+$/) && method === 'DELETE') return deleteRealmHandler(event);

  // User routes
  if (path === '/admin/users' && method === 'GET') return listUsersHandler(event);
  if (path.match(/^\/admin\/users\/[\w-]+$/) && method === 'GET') return getUserHandler(event);
  if (path.match(/^\/admin\/users\/[\w-]+\/suspend$/) && method === 'POST') return suspendUserHandler(event);
  if (path.match(/^\/admin\/users\/[\w-]+\/activate$/) && method === 'POST') return activateUserHandler(event);
  if (path.match(/^\/admin\/users\/[\w-]+\/unlock$/) && method === 'POST') return unlockUserHandler(event);
  if (path.match(/^\/admin\/users\/[\w-]+\/reset-password$/) && method === 'POST') return adminResetPasswordHandler(event);
  if (path.match(/^\/admin\/users\/[\w-]+\/reset-mfa$/) && method === 'POST') return resetMFAHandler(event);
  if (path.match(/^\/admin\/users\/[\w-]+$/) && method === 'DELETE') return deleteUserHandler(event);

  // Session routes
  if (path.match(/^\/admin\/users\/[\w-]+\/sessions$/) && method === 'GET') return listUserSessionsHandler(event);
  if (path.match(/^\/admin\/users\/[\w-]+\/sessions$/) && method === 'DELETE') return revokeAllSessionsHandler(event);
  if (path.match(/^\/admin\/sessions\/[\w-]+$/) && method === 'DELETE') return revokeSessionHandler(event);

  return { statusCode: 404, body: JSON.stringify({ error: 'Not found' }) };
}
```

### template.yaml Handler Paths

```yaml
LoginFunction:
  Handler: dist/handlers/login.handler.handler

RegisterFunction:
  Handler: dist/handlers/register.handler.handler

RefreshFunction:
  Handler: dist/handlers/refresh.handler.handler

LogoutFunction:
  Handler: dist/handlers/logout.handler.handler

SSOFunction:
  Handler: dist/handlers/sso.handler.handler

AdminFunction:
  Handler: dist/handlers/admin.handler.handler

HealthFunction:
  Handler: dist/handlers/health.handler.healthHandler
```

### AWS Config - Table Separation

```typescript
// src/config/aws.config.ts
export const AWS_CONFIG = {
  dynamodb: {
    // Core tables - health check validates these
    tables: {
      users: 'zalt-users',
      realms: 'zalt-realms',
      sessions: 'zalt-sessions'
    },
    // Extended tables - optional, not validated by health check
    extendedTables: {
      tokens: 'zalt-tokens',
      documents: 'zalt-documents',
      audit: 'zalt-audit',
      devices: 'zalt-devices',
      mfa: 'zalt-mfa',
      webauthn: 'zalt-webauthn'
    }
  }
};
```

## Data Models

No new data models required.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system.*

### Property 1: Handler Resolution

*For any* Lambda function in the template, the handler path SHALL resolve to an exported function in the compiled JavaScript.

**Validates: Requirements 1.4, 3.2-3.8**

### Property 2: Admin Router Coverage

*For any* admin API endpoint defined in template.yaml, the admin handler router SHALL have a matching route.

**Validates: Requirements 4.2, 4.3**

### Property 3: Health Check Independence

*For any* health check execution, the result SHALL only depend on core tables (users, realms, sessions).

**Validates: Requirements 5.1, 5.3**

## Error Handling

- Handler not found: Lambda returns "Cannot find module" error → Fix handler path
- Route not found in admin: Return 404 with clear error message
- Table not found in health check: Only fail if core table, ignore extended tables

## Testing Strategy

### Unit Tests
- Admin router correctly routes each endpoint
- Health service only checks core tables

### Integration Tests
- SAM build produces correct output structure
- Lambda invocation resolves handler correctly
- Admin endpoints return expected responses
