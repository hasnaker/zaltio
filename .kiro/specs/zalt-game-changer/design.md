# Design Document

## Overview

Zalt Game-Changer Features - Clerk'in ötesine geçen, enterprise-grade authentication ve authorization özellikleri. Bu tasarım, Machine Authentication, Reverification, Session Tasks, Billing, ve AI Security özelliklerinin teknik implementasyonunu tanımlar.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Zalt Game-Changer Layer                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Machine   │  │ Reverifi-   │  │  Session    │              │
│  │    Auth     │  │  cation     │  │   Tasks     │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Billing   │  │  Waitlist   │  │ Imperson-   │              │
│  │ Integration │  │    Mode     │  │   ation     │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  Invitation │  │  Webhook    │  │   Session   │              │
│  │   System    │  │   System    │  │   Handler   │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │  AI Risk    │  │ Compromised │                               │
│  │ Assessment  │  │  Password   │                               │
│  └─────────────┘  └─────────────┘                               │
├─────────────────────────────────────────────────────────────────┤
│                     Existing Zalt Core                           │
│  (Auth, Multi-Tenant, RBAC, MFA, WebAuthn, Social Login)        │
└─────────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. Machine Authentication Service

```typescript
// src/services/machine-auth.service.ts
interface Machine {
  id: string;                    // machine_xxx
  realmId: string;
  name: string;
  description?: string;
  clientId: string;              // Public identifier
  clientSecretHash: string;      // Argon2id hashed
  scopes: string[];              // ['read:users', 'write:sessions']
  allowedTargets: string[];      // Other machine IDs that can be called
  status: 'active' | 'disabled';
  createdAt: string;
  lastUsedAt?: string;
}

interface M2MToken {
  machine_id: string;
  scopes: string[];
  target_machines: string[];
  iat: number;
  exp: number;
  iss: string;
  type: 'm2m';
}

class MachineAuthService {
  createMachine(realmId: string, config: CreateMachineInput): Promise<Machine>;
  authenticateMachine(clientId: string, clientSecret: string): Promise<M2MToken>;
  validateM2MToken(token: string): Promise<M2MToken>;
  rotateCredentials(machineId: string): Promise<{ clientId: string; clientSecret: string }>;
  listMachines(realmId: string): Promise<Machine[]>;
  deleteMachine(machineId: string): Promise<void>;
}
```

### 2. API Key Service

```typescript
// src/services/api-key.service.ts
interface APIKey {
  id: string;                    // key_xxx
  userId: string;
  realmId: string;
  tenantId?: string;
  name: string;
  keyPrefix: string;             // zalt_key_xxx... (first 12 chars)
  keyHash: string;               // SHA-256 hash of full key
  scopes: string[];
  expiresAt?: string;
  lastUsedAt?: string;
  createdAt: string;
  status: 'active' | 'revoked';
}

class APIKeyService {
  createKey(userId: string, config: CreateKeyInput): Promise<{ key: APIKey; fullKey: string }>;
  validateKey(fullKey: string): Promise<{ key: APIKey; user: User }>;
  listKeys(userId: string): Promise<APIKey[]>;
  revokeKey(keyId: string): Promise<void>;
}
```

### 3. Reverification Service

```typescript
// src/services/reverification.service.ts
interface ReverificationConfig {
  level: 'password' | 'mfa' | 'webauthn';
  validityMinutes: number;       // Default: 10
}

interface SessionReverification {
  sessionId: string;
  level: string;
  verifiedAt: string;
  expiresAt: string;
}

class ReverificationService {
  requireReverification(sessionId: string, level: string): Promise<void>;
  checkReverification(sessionId: string, requiredLevel: string): Promise<boolean>;
  completeReverification(sessionId: string, level: string, proof: string): Promise<void>;
  getRequiredLevel(endpoint: string): ReverificationConfig | null;
}
```

### 4. Session Tasks Service

```typescript
// src/services/session-tasks.service.ts
type TaskType = 'choose_organization' | 'setup_mfa' | 'reset_password' | 'accept_terms' | 'custom';

interface SessionTask {
  id: string;
  sessionId: string;
  userId: string;
  type: TaskType;
  status: 'pending' | 'completed' | 'skipped';
  metadata?: Record<string, any>;
  createdAt: string;
  completedAt?: string;
}

class SessionTasksService {
  createTask(sessionId: string, type: TaskType, metadata?: any): Promise<SessionTask>;
  getPendingTasks(sessionId: string): Promise<SessionTask[]>;
  completeTask(taskId: string): Promise<void>;
  hasBlockingTasks(sessionId: string): Promise<boolean>;
  forcePasswordReset(userId: string, revokeAllSessions?: boolean): Promise<void>;
  forcePasswordResetAll(realmId: string): Promise<number>;
}
```

### 5. Waitlist Service

```typescript
// src/services/waitlist.service.ts
interface WaitlistEntry {
  id: string;
  realmId: string;
  email: string;
  metadata?: Record<string, any>;
  status: 'pending' | 'approved' | 'rejected';
  position: number;
  referralCode?: string;
  createdAt: string;
  approvedAt?: string;
}

class WaitlistService {
  join(realmId: string, email: string, metadata?: any): Promise<WaitlistEntry>;
  approve(entryId: string): Promise<void>;
  reject(entryId: string): Promise<void>;
  bulkApprove(entryIds: string[]): Promise<void>;
  getPosition(entryId: string): Promise<number>;
  listEntries(realmId: string, status?: string): Promise<WaitlistEntry[]>;
  isWaitlistMode(realmId: string): Promise<boolean>;
}
```

### 6. Impersonation Service

```typescript
// src/services/impersonation.service.ts
interface ImpersonationSession {
  id: string;
  adminId: string;
  targetUserId: string;
  reason: string;
  restrictions: string[];        // ['no_password_change', 'no_delete']
  startedAt: string;
  expiresAt: string;
  endedAt?: string;
}

class ImpersonationService {
  startImpersonation(adminId: string, targetUserId: string, reason: string): Promise<ImpersonationSession>;
  endImpersonation(sessionId: string): Promise<void>;
  isImpersonating(sessionId: string): Promise<ImpersonationSession | null>;
  getRestrictions(sessionId: string): Promise<string[]>;
}
```

### 7. Billing Service

```typescript
// src/services/billing.service.ts
interface BillingPlan {
  id: string;
  realmId: string;
  name: string;
  type: 'per_user' | 'per_org' | 'flat_rate' | 'usage_based';
  priceMonthly: number;
  priceYearly: number;
  features: string[];
  limits: Record<string, number>;
  stripePriceId?: string;
}

interface Subscription {
  id: string;
  tenantId: string;
  planId: string;
  stripeSubscriptionId: string;
  status: 'active' | 'past_due' | 'canceled' | 'trialing';
  currentPeriodEnd: string;
}

class BillingService {
  createPlan(realmId: string, config: CreatePlanInput): Promise<BillingPlan>;
  subscribe(tenantId: string, planId: string, paymentMethodId: string): Promise<Subscription>;
  cancelSubscription(subscriptionId: string): Promise<void>;
  checkEntitlement(tenantId: string, feature: string): Promise<boolean>;
  getUsage(tenantId: string): Promise<UsageMetrics>;
  handleStripeWebhook(event: Stripe.Event): Promise<void>;
}
```

### 8. Invitation Service

```typescript
// src/services/invitation.service.ts
interface Invitation {
  id: string;
  tenantId: string;
  email: string;
  role: string;
  permissions?: string[];
  invitedBy: string;
  token: string;
  status: 'pending' | 'accepted' | 'expired' | 'revoked';
  expiresAt: string;
  createdAt: string;
  acceptedAt?: string;
}

class InvitationService {
  create(tenantId: string, email: string, role: string, invitedBy: string): Promise<Invitation>;
  accept(token: string, userId?: string, newUserData?: CreateUserInput): Promise<void>;
  revoke(invitationId: string): Promise<void>;
  list(tenantId: string): Promise<Invitation[]>;
  resend(invitationId: string): Promise<void>;
}
```

### 9. Webhook Service

```typescript
// src/services/webhook.service.ts
interface WebhookConfig {
  id: string;
  realmId: string;
  url: string;
  secret: string;
  events: string[];
  status: 'active' | 'disabled';
  createdAt: string;
}

interface WebhookDelivery {
  id: string;
  webhookId: string;
  eventType: string;
  payload: any;
  status: 'pending' | 'success' | 'failed';
  attempts: number;
  responseCode?: number;
  responseTime?: number;
  error?: string;
  createdAt: string;
}

class WebhookService {
  create(realmId: string, url: string, events: string[]): Promise<WebhookConfig>;
  dispatch(realmId: string, eventType: string, data: any): Promise<void>;
  test(webhookId: string): Promise<WebhookDelivery>;
  getDeliveryLogs(webhookId: string, limit?: number): Promise<WebhookDelivery[]>;
  rotateSecret(webhookId: string): Promise<string>;
  verifySignature(payload: string, signature: string, secret: string): boolean;
}
```

### 10. AI Risk Assessment Service

```typescript
// src/services/ai-risk.service.ts
interface RiskAssessment {
  score: number;                 // 0-100
  factors: RiskFactor[];
  recommendation: 'allow' | 'mfa_required' | 'block';
  assessedAt: string;
}

interface RiskFactor {
  type: 'ip_reputation' | 'geo_velocity' | 'device_trust' | 'behavior_anomaly';
  score: number;
  details: string;
}

class AIRiskService {
  assessLoginRisk(context: LoginContext): Promise<RiskAssessment>;
  updateUserBehaviorProfile(userId: string, event: BehaviorEvent): Promise<void>;
  detectImpossibleTravel(userId: string, currentLocation: GeoLocation): Promise<boolean>;
  checkIPReputation(ip: string): Promise<number>;
  getDeviceTrustScore(fingerprint: string, userId: string): Promise<number>;
}
```

## Data Models

### DynamoDB Tables

```yaml
# zalt-machines
pk: REALM#{realmId}#MACHINE#{machineId}
sk: MACHINE
GSI: client-id-index (clientId -> machineId)

# zalt-api-keys
pk: USER#{userId}#KEY#{keyId}
sk: KEY
GSI: key-hash-index (keyHash -> keyId)

# zalt-invitations
pk: TENANT#{tenantId}#INVITATION#{invitationId}
sk: INVITATION
GSI: token-index (token -> invitationId)
GSI: email-index (email -> invitations)

# zalt-webhooks
pk: REALM#{realmId}#WEBHOOK#{webhookId}
sk: WEBHOOK

# zalt-webhook-deliveries
pk: WEBHOOK#{webhookId}#DELIVERY#{deliveryId}
sk: DELIVERY#{timestamp}

# zalt-waitlist
pk: REALM#{realmId}#WAITLIST#{entryId}
sk: WAITLIST
GSI: email-index (email -> entryId)

# zalt-billing-plans
pk: REALM#{realmId}#PLAN#{planId}
sk: PLAN

# zalt-subscriptions
pk: TENANT#{tenantId}#SUBSCRIPTION#{subscriptionId}
sk: SUBSCRIPTION
GSI: stripe-index (stripeSubscriptionId -> subscriptionId)

# zalt-session-tasks
pk: SESSION#{sessionId}#TASK#{taskId}
sk: TASK

# zalt-impersonation
pk: ADMIN#{adminId}#IMPERSONATION#{sessionId}
sk: IMPERSONATION
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system.*

### Property 1: M2M Token Scope Enforcement
*For any* M2M token and any API call, the call SHALL succeed only if the token's scopes include the required scope for that endpoint.
**Validates: Requirements 1.4, 1.7**

### Property 2: API Key User Context Preservation
*For any* API key and any request, the request SHALL execute with the exact same permissions as if the user made the request directly.
**Validates: Requirements 2.7, 2.8**

### Property 3: Reverification Expiry
*For any* reverification completion, the reverification status SHALL expire after the configured validity period.
**Validates: Requirements 3.4, 3.5**

### Property 4: Session Task Blocking
*For any* session with pending blocking tasks, all API calls (except task completion) SHALL return 403.
**Validates: Requirements 4.2**

### Property 5: Invitation Token Single Use
*For any* invitation token, acceptance SHALL succeed exactly once and subsequent attempts SHALL fail.
**Validates: Requirements 11.3, 11.4**

### Property 6: Webhook Signature Validity
*For any* webhook delivery, the HMAC-SHA256 signature SHALL be verifiable using the webhook secret.
**Validates: Requirements 12.3, 12.4**

### Property 7: Impersonation Restrictions
*For any* impersonation session, restricted actions (password change, account delete) SHALL be blocked.
**Validates: Requirements 6.8**

### Property 8: Risk Score Consistency
*For any* login context, repeated risk assessments within 1 minute SHALL return scores within ±5 points.
**Validates: Requirements 10.1, 10.2**

### Property 9: Compromised Password Detection
*For any* password in HaveIBeenPwned database, registration/password change SHALL be rejected.
**Validates: Requirements 8.1, 8.2**

### Property 10: Billing Entitlement Enforcement
*For any* feature check, access SHALL be granted only if the tenant's active plan includes that feature.
**Validates: Requirements 7.6**

## Error Handling

| Error Code | HTTP | Description |
|------------|------|-------------|
| REVERIFICATION_REQUIRED | 403 | Endpoint requires step-up authentication |
| SESSION_TASK_PENDING | 403 | User has pending session tasks |
| M2M_SCOPE_INSUFFICIENT | 403 | M2M token lacks required scope |
| API_KEY_INVALID | 401 | API key not found or revoked |
| API_KEY_EXPIRED | 401 | API key has expired |
| INVITATION_EXPIRED | 400 | Invitation token has expired |
| INVITATION_ALREADY_USED | 400 | Invitation already accepted |
| WAITLIST_MODE_ACTIVE | 403 | Registration blocked, waitlist mode |
| IMPERSONATION_RESTRICTED | 403 | Action not allowed during impersonation |
| RISK_SCORE_TOO_HIGH | 403 | Login blocked due to high risk |
| PASSWORD_COMPROMISED | 400 | Password found in breach database |
| PLAN_LIMIT_EXCEEDED | 403 | Feature/usage limit exceeded |
| WEBHOOK_DELIVERY_FAILED | 500 | Webhook delivery failed after retries |

## Testing Strategy

### Unit Tests
- Service method tests with mocked dependencies
- Input validation tests
- Error handling tests

### Property-Based Tests (fast-check)
- M2M scope enforcement
- API key permission inheritance
- Reverification expiry timing
- Session task blocking
- Webhook signature verification
- Risk score consistency

### Integration Tests
- Full flow tests: M2M auth → API call → response
- Invitation flow: create → email → accept → membership
- Billing flow: subscribe → entitlement check → usage tracking
- Webhook flow: event → dispatch → delivery → retry

### Security Tests
- M2M credential rotation
- API key hash collision resistance
- Webhook signature tampering detection
- Impersonation restriction bypass attempts
