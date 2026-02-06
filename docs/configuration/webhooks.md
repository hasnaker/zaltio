# Webhooks

Receive real-time notifications when events occur in your Zalt.io realm.

## Overview

Webhooks allow your application to receive HTTP POST requests when specific events happen, enabling:
- Real-time user synchronization
- Custom analytics and logging
- Workflow automation
- Third-party integrations

## Data Model

### DynamoDB Schema

#### Webhooks Table

```yaml
Table: zalt-webhooks
Primary Key:
  pk: REALM#{realmId}#WEBHOOK#{webhookId}
  sk: WEBHOOK

GSI: realm-index
  Partition Key: realm_id
  Purpose: List all webhooks for a realm

Fields:
  - id: string              # webhook_xxx format
  - realm_id: string        # Realm this webhook belongs to
  - url: string             # Webhook endpoint URL (HTTPS required)
  - secret: string          # HMAC-SHA256 signing secret (64 hex chars)
  - events: string[]        # Events to subscribe to
  - status: string          # active | inactive | deleted
  - description: string     # Optional description
  - created_at: string      # ISO 8601 timestamp
  - updated_at: string      # ISO 8601 timestamp
  - last_triggered_at: string # Last successful delivery
  - metadata: object        # Additional metadata
```

#### Webhook Deliveries Table

```yaml
Table: zalt-webhook-deliveries
Primary Key:
  pk: WEBHOOK#{webhookId}#DELIVERY#{deliveryId}
  sk: DELIVERY#{timestamp}

GSI: webhook-index
  Partition Key: webhook_id
  Purpose: List all deliveries for a webhook

Fields:
  - id: string              # del_xxx format
  - webhook_id: string      # Parent webhook ID
  - event_type: string      # Event type that triggered delivery
  - payload: object         # The payload that was/will be sent
  - status: string          # pending | success | failed | retrying
  - attempts: number        # Number of delivery attempts
  - max_attempts: number    # Maximum retry attempts (default: 5)
  - response_code: number   # HTTP response code from endpoint
  - response_time_ms: number # Response time in milliseconds
  - error: string           # Error message if failed
  - next_retry_at: string   # Next retry timestamp (ISO 8601)
  - created_at: string      # ISO 8601 timestamp
  - updated_at: string      # ISO 8601 timestamp
  - completed_at: string    # Completion timestamp (ISO 8601)
  - metadata: object        # Additional metadata (response headers, etc.)
```

### Delivery Status Types

| Status | Description |
|--------|-------------|
| `pending` | Waiting to be delivered |
| `success` | Successfully delivered (2xx response) |
| `failed` | Delivery failed after all retries |
| `retrying` | Waiting for next retry attempt |

### Webhook Status Types

| Status | Description |
|--------|-------------|
| `active` | Webhook is enabled and will receive events |
| `inactive` | Webhook is disabled, no events will be sent |
| `deleted` | Webhook is soft-deleted |

### Security Features

- **Secret Generation**: 32 bytes (64 hex characters) cryptographically secure
- **Signature Algorithm**: HMAC-SHA256
- **Timestamp Tolerance**: 5 minutes (replay attack protection)
- **URL Validation**: HTTPS required, SSRF protection
- **Timing-Safe Comparison**: Prevents timing attacks on signature verification

## Setting Up Webhooks

### Create a Webhook Endpoint

```bash
curl -X POST https://api.zalt.io/v1/admin/realms/your-realm/webhooks \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://yourapp.com/webhooks/zalt",
    "events": ["user.created", "user.login", "session.created"],
    "secret": "your-webhook-secret"
  }'
```

### Webhook Payload

All webhooks follow this structure:

```json
{
  "id": "evt_abc123",
  "type": "user.created",
  "created_at": "2026-01-16T12:00:00Z",
  "realm_id": "your-realm-id",
  "data": {
    // Event-specific data
  }
}
```

### Verifying Signatures

All webhooks include signature headers for verification:

```
x-zalt-signature: <hmac-sha256-hex>
x-zalt-timestamp: <unix-timestamp>
x-zalt-delivery-id: <delivery-id>
```

**Verification (Node.js):**

```typescript
import crypto from 'crypto';

const SIGNATURE_TIMESTAMP_TOLERANCE = 300; // 5 minutes

function verifyWebhookSignature(
  payload: string,
  signature: string,
  timestamp: number,
  secret: string
): boolean {
  // Check timestamp is within tolerance (replay protection)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > SIGNATURE_TIMESTAMP_TOLERANCE) {
    return false;
  }
  
  // Calculate expected signature
  const signedPayload = `${timestamp}.${payload}`;
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');
  
  // Use timing-safe comparison
  try {
    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');
    
    if (sigBuffer.length !== expectedBuffer.length) {
      return false;
    }
    
    return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    return false;
  }
}

// Express middleware
app.post('/webhooks/zalt', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['x-zalt-signature'] as string;
  const timestamp = parseInt(req.headers['x-zalt-timestamp'] as string, 10);
  const deliveryId = req.headers['x-zalt-delivery-id'] as string;
  
  if (!verifyWebhookSignature(req.body.toString(), signature, timestamp, WEBHOOK_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  
  const event = JSON.parse(req.body);
  
  // Use idempotency_key for deduplication
  if (await isEventProcessed(event.idempotency_key)) {
    return res.status(200).send('Already processed');
  }
  
  // Process event...
  await processEvent(event);
  await markEventProcessed(event.idempotency_key);
  
  res.status(200).send('OK');
});
```

**Using Zalt SDK:**

```typescript
import { verifyWebhookSignature } from '@zalt/auth-sdk';

// Automatic verification
const isValid = verifyWebhookSignature(payload, signature, timestamp, secret);
```

## Available Events

### Supported Event Types

| Category | Events |
|----------|--------|
| **User** | `user.created`, `user.updated`, `user.deleted` |
| **Session** | `session.created`, `session.revoked` |
| **Tenant** | `tenant.created`, `tenant.updated`, `tenant.deleted` |
| **Member** | `member.invited`, `member.joined`, `member.removed` |
| **MFA** | `mfa.enabled`, `mfa.disabled` |
| **Billing** | `billing.subscription.created`, `billing.subscription.updated`, `billing.subscription.canceled`, `billing.payment.succeeded`, `billing.payment.failed` |
| **Security** | `security.high_risk_login` |

### User Events

| Event | Description |
|-------|-------------|
| `user.created` | New user registered |
| `user.updated` | User profile updated |
| `user.deleted` | User account deleted |
| `user.email_verified` | Email verification completed |
| `user.password_changed` | Password updated |
| `user.locked` | Account locked (failed attempts) |
| `user.unlocked` | Account unlocked |

**Example: user.created**
```json
{
  "id": "evt_abc123",
  "type": "user.created",
  "created_at": "2026-01-16T12:00:00Z",
  "data": {
    "user": {
      "id": "usr_xyz789",
      "email": "user@example.com",
      "email_verified": false,
      "profile": {
        "first_name": "John",
        "last_name": "Doe"
      },
      "created_at": "2026-01-16T12:00:00Z"
    }
  }
}
```

### Session Events

| Event | Description |
|-------|-------------|
| `session.created` | User logged in |
| `session.ended` | User logged out |
| `session.revoked` | Session forcefully terminated |
| `session.expired` | Session timed out |

**Example: session.created**
```json
{
  "id": "evt_def456",
  "type": "session.created",
  "created_at": "2026-01-16T12:00:00Z",
  "data": {
    "session": {
      "id": "ses_abc123",
      "user_id": "usr_xyz789",
      "device": {
        "type": "desktop",
        "browser": "Chrome 120",
        "os": "macOS 14"
      },
      "ip_address": "203.0.113.1",
      "location": {
        "city": "Istanbul",
        "country": "Turkey"
      }
    }
  }
}
```

**Example: session.revoked**

Triggered when a session is revoked. Includes the reason for revocation.

```json
{
  "id": "evt_rev789",
  "type": "session.revoked",
  "created_at": "2026-01-16T14:30:00Z",
  "idempotency_key": "idem_xxx",
  "data": {
    "session_id": "ses_abc123",
    "user_id": "usr_xyz789",
    "realm_id": "realm_clinisyn",
    "reason": "logout"
  }
}
```

**Session Revocation Reasons:**

| Reason | Description |
|--------|-------------|
| `logout` | User manually logged out or revoked the session |
| `force_logout` | User revoked all sessions (except current) |
| `impossible_travel` | Session auto-revoked due to impossible travel detection |
| `session_limit_exceeded` | Oldest session revoked when concurrent session limit exceeded |
| `password_change` | All sessions revoked after password change |
| `security` | Session revoked due to security incident |
| `expired` | Session expired due to inactivity or timeout |

**Use Cases:**
- Sync session state with your application
- Trigger cleanup workflows when sessions end
- Monitor for suspicious session terminations
- Alert on impossible travel detections
- Track session limit enforcement

### MFA Events

| Event | Description |
|-------|-------------|
| `mfa.enabled` | User enabled MFA |
| `mfa.disabled` | User disabled MFA |
| `mfa.verified` | MFA verification successful |
| `mfa.failed` | MFA verification failed |
| `mfa.backup_used` | Backup code used |

### Security Events

| Event | Description |
|-------|-------------|
| `security.high_risk_login` | High-risk login detected by AI risk assessment |
| `security.login_failed` | Failed login attempt |
| `security.suspicious_activity` | Unusual activity detected |
| `security.password_breach` | Password found in breach |
| `security.new_device` | Login from new device |
| `security.impossible_travel` | Login from impossible location |

**Example: security.high_risk_login**
```json
{
  "id": "evt_risk123",
  "type": "security.high_risk_login",
  "created_at": "2026-01-16T12:00:00Z",
  "idempotency_key": "idem_xxx",
  "data": {
    "user_id": "usr_xyz789",
    "realm_id": "realm_abc",
    "email": "user@example.com",
    "risk_score": 85,
    "risk_level": "high",
    "risk_factors": [
      {
        "type": "new_device",
        "severity": "medium",
        "score": 40,
        "description": "Login from new/unrecognized device"
      },
      {
        "type": "vpn_detected",
        "severity": "medium",
        "score": 30,
        "description": "VPN connection detected"
      },
      {
        "type": "unusual_time",
        "severity": "low",
        "score": 15,
        "description": "Login at unusual hour"
      }
    ],
    "recommendation": "mfa_required",
    "ip_address": "203.0.113.1",
    "location": {
      "city": "Istanbul",
      "country": "Turkey",
      "country_code": "TR"
    },
    "device": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
      "is_new_device": true
    },
    "action_taken": "mfa_required",
    "assessment_id": "risk_1705406400_abc123",
    "timestamp": "2026-01-16T12:00:00Z"
  }
}
```

**Risk Score Thresholds:**
| Score Range | Risk Level | Action Taken |
|-------------|------------|--------------|
| 0-25 | Low | Allowed |
| 26-50 | Medium | Allowed |
| 51-70 | Medium-High | Allowed |
| 71-90 | High | MFA Required |
| 91-100 | Critical | Blocked |

**Example: security.suspicious_activity**
```json
{
  "id": "evt_sec789",
  "type": "security.suspicious_activity",
  "created_at": "2026-01-16T12:00:00Z",
  "data": {
    "user_id": "usr_xyz789",
    "activity_type": "impossible_travel",
    "details": {
      "previous_location": "Istanbul, Turkey",
      "current_location": "New York, USA",
      "time_difference_minutes": 30
    },
    "action_taken": "session_blocked"
  }
}
```

### Admin Events

| Event | Description |
|-------|-------------|
| `admin.user_suspended` | Admin suspended user |
| `admin.user_activated` | Admin activated user |
| `admin.mfa_reset` | Admin reset user's MFA |
| `admin.sessions_revoked` | Admin revoked all sessions |

## Webhook Configuration

### Limits

| Limit | Value |
|-------|-------|
| Max webhooks per realm | 10 |
| Max events per webhook | 50 |
| Signature timestamp tolerance | 5 minutes |
| Secret length | 64 hex characters (32 bytes) |

### Retry Policy

Failed webhooks are retried with exponential backoff:

| Attempt | Delay |
|---------|-------|
| 1 | Immediate |
| 2 | 1 minute |
| 3 | 5 minutes |
| 4 | 30 minutes |
| 5 | 2 hours |
| 6 | 8 hours |

After 6 failed attempts, the webhook is marked as failed.

### Timeout

Webhooks must respond within 30 seconds. Return a 2xx status code to acknowledge receipt.

### Managing Webhooks

```bash
# List webhooks
curl https://api.zalt.io/v1/admin/realms/your-realm/webhooks \
  -H "Authorization: Bearer <admin_token>"

# Update webhook
curl -X PATCH https://api.zalt.io/v1/admin/realms/your-realm/webhooks/whk_123 \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"events": ["user.created", "user.deleted"]}'

# Delete webhook
curl -X DELETE https://api.zalt.io/v1/admin/realms/your-realm/webhooks/whk_123 \
  -H "Authorization: Bearer <admin_token>"

# View webhook logs
curl https://api.zalt.io/v1/admin/realms/your-realm/webhooks/whk_123/logs \
  -H "Authorization: Bearer <admin_token>"
```

### Testing Webhooks

```bash
# Send test event
curl -X POST https://api.zalt.io/v1/admin/realms/your-realm/webhooks/whk_123/test \
  -H "Authorization: Bearer <admin_token>" \
  -d '{"event_type": "user.created"}'
```

## Best Practices

1. **Always verify signatures** - Prevent spoofed requests
2. **Respond quickly** - Process asynchronously if needed
3. **Handle duplicates** - Use idempotency_key for deduplication
4. **Monitor failures** - Set up alerts for failed webhooks
5. **Use HTTPS** - Webhook URLs must use HTTPS
6. **Check timestamps** - Reject requests outside 5-minute tolerance

## Repository API

The webhook repository provides the following operations:

### Webhook Operations

#### Create Operations

```typescript
import { createWebhook } from './repositories/webhook.repository';

const result = await createWebhook({
  realm_id: 'realm_xxx',
  url: 'https://example.com/webhook',
  events: ['user.created', 'user.deleted'],
  description: 'User sync webhook',
  created_by: 'user_xxx'
});

// result.webhook - Webhook response (without secret)
// result.secret - Raw secret (only returned once!)
```

#### Read Operations

```typescript
import { 
  getWebhookById, 
  listWebhooksByRealm, 
  getWebhooksForEvent 
} from './repositories/webhook.repository';

// Get single webhook
const webhook = await getWebhookById('realm_xxx', 'webhook_xxx');

// List all webhooks for a realm
const { webhooks, nextCursor } = await listWebhooksByRealm('realm_xxx', {
  status: 'active',
  limit: 50
});

// Get webhooks subscribed to specific event
const activeWebhooks = await getWebhooksForEvent('realm_xxx', 'user.created');
```

#### Update Operations

```typescript
import { 
  updateWebhook, 
  updateWebhookStatus, 
  rotateWebhookSecret 
} from './repositories/webhook.repository';

// Update webhook configuration
await updateWebhook('realm_xxx', 'webhook_xxx', {
  url: 'https://new-url.com/webhook',
  events: ['user.created'],
  status: 'inactive'
});

// Rotate secret (returns new secret)
const { webhook, secret } = await rotateWebhookSecret('realm_xxx', 'webhook_xxx');
```

#### Delete Operations

```typescript
import { deleteWebhook, hardDeleteWebhook } from './repositories/webhook.repository';

// Soft delete (marks as deleted)
await deleteWebhook('realm_xxx', 'webhook_xxx');

// Hard delete (permanent)
await hardDeleteWebhook('realm_xxx', 'webhook_xxx');
```

### Webhook Delivery Operations

#### Create Delivery

```typescript
import { createWebhookDelivery } from './repositories/webhook-delivery.repository';

const delivery = await createWebhookDelivery({
  webhook_id: 'webhook_xxx',
  event_type: 'user.created',
  payload: {
    id: 'evt_xxx',
    type: 'user.created',
    timestamp: new Date().toISOString(),
    idempotency_key: 'idem_xxx',
    data: { user_id: 'user_xxx' }
  },
  metadata: {
    realm_id: 'realm_xxx',
    target_url: 'https://example.com/webhook'
  }
});
```

#### Read Deliveries

```typescript
import { 
  getWebhookDeliveryById,
  listWebhookDeliveries,
  getPendingDeliveries,
  getRecentDeliveries,
  getDeliveryStats
} from './repositories/webhook-delivery.repository';

// Get single delivery
const delivery = await getWebhookDeliveryById('webhook_xxx', 'del_xxx');

// List deliveries with filtering
const { deliveries, nextCursor } = await listWebhookDeliveries('webhook_xxx', {
  status: 'failed',
  limit: 50,
  startDate: '2026-01-01T00:00:00Z',
  endDate: '2026-01-31T23:59:59Z'
});

// Get pending deliveries ready for retry
const pending = await getPendingDeliveries('webhook_xxx', 10);

// Get last 100 deliveries
const recent = await getRecentDeliveries('webhook_xxx', 100);

// Get delivery statistics
const stats = await getDeliveryStats('webhook_xxx');
// stats: { total, pending, success, failed, retrying, averageResponseTime, successRate }
```

#### Record Delivery Attempts

```typescript
import { 
  recordDeliveryAttempt,
  markDeliverySuccess,
  markDeliveryFailed
} from './repositories/webhook-delivery.repository';

// Record a delivery attempt with full details
await recordDeliveryAttempt('webhook_xxx', 'del_xxx', {
  success: true,
  response_code: 200,
  response_time_ms: 150,
  response_body: '{"status": "ok"}',
  response_headers: { 'content-type': 'application/json' }
});

// Quick success marking
await markDeliverySuccess('webhook_xxx', 'del_xxx', 200, 150);

// Quick failure marking
await markDeliveryFailed('webhook_xxx', 'del_xxx', 'Connection timeout', 504);
```

#### Delete Deliveries

```typescript
import { 
  deleteWebhookDelivery,
  deleteAllWebhookDeliveries,
  deleteOldDeliveries
} from './repositories/webhook-delivery.repository';

// Delete single delivery
await deleteWebhookDelivery('webhook_xxx', 'del_xxx');

// Delete all deliveries for a webhook
const count = await deleteAllWebhookDeliveries('webhook_xxx');

// Delete deliveries older than 30 days
const deleted = await deleteOldDeliveries('webhook_xxx', '2025-12-25T00:00:00Z');
```

## Model Utilities

### Webhook Utilities

```typescript
import {
  generateWebhookId,
  generateWebhookSecret,
  createWebhookSignature,
  verifyWebhookSignature,
  createWebhookPayload,
  createSignatureHeaders,
  isValidWebhookUrl,
  isValidWebhookEvent
} from './models/webhook.model';

// Generate IDs and secrets
const webhookId = generateWebhookId();     // webhook_xxx
const secret = generateWebhookSecret();     // 64 hex chars

// Create and verify signatures
const signature = createWebhookSignature(payload, timestamp, secret);
const isValid = verifyWebhookSignature(payload, signature, timestamp, secret);

// Create webhook payload
const payload = createWebhookPayload('user.created', { user_id: 'xxx' });

// Create signature headers for delivery
const headers = createSignatureHeaders(JSON.stringify(payload), secret, deliveryId);

// Validation
isValidWebhookUrl('https://example.com/hook');  // true
isValidWebhookUrl('http://example.com/hook');   // false (HTTP not allowed)
isValidWebhookEvent('user.created');            // true
```

### Webhook Delivery Utilities

```typescript
import {
  generateDeliveryId,
  calculateRetryDelay,
  calculateNextRetryAt,
  shouldRetry,
  isDeliveryComplete,
  isReadyForRetry,
  determineDeliveryStatus,
  isSuccessStatusCode,
  isRetryableStatusCode,
  truncateResponseBody,
  sanitizeErrorMessage,
  toWebhookDeliveryResponse,
  createWebhookDeliveryFromInput,
  isValidDeliveryStatus,
  getStatusDescription,
  calculateDeliveryStats,
  DEFAULT_MAX_ATTEMPTS,
  RETRY_DELAYS_SECONDS
} from './models/webhook-delivery.model';

// Generate delivery ID
const deliveryId = generateDeliveryId();  // del_xxx

// Calculate retry delays (exponential backoff)
calculateRetryDelay(1);  // 1 second
calculateRetryDelay(2);  // 5 seconds
calculateRetryDelay(3);  // 30 seconds
calculateRetryDelay(4);  // 300 seconds (5 minutes)
calculateRetryDelay(5);  // null (max attempts reached)

// Calculate next retry timestamp
const nextRetry = calculateNextRetryAt(2);  // ISO 8601 timestamp

// Check delivery status
shouldRetry(delivery);        // true if should retry
isDeliveryComplete(delivery); // true if success or final failure
isReadyForRetry(delivery);    // true if ready for next attempt

// Determine status based on result
const status = determineDeliveryStatus(
  { success: false, error: 'timeout' },
  currentAttempts,
  maxAttempts
);  // 'retrying' or 'failed'

// HTTP status code helpers
isSuccessStatusCode(200);     // true (2xx)
isRetryableStatusCode(503);   // true (5xx, 408, 429)

// Sanitize response data
const truncated = truncateResponseBody(longBody);  // Max 1024 chars
const safeError = sanitizeErrorMessage(error);     // No stack traces

// Calculate statistics
const stats = calculateDeliveryStats(deliveries);
// { total, pending, success, failed, retrying, averageResponseTime, successRate }
```
