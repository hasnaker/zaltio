/**
 * Webhook Model - Webhook Configuration and Delivery for Zalt.io
 * 
 * Webhooks allow customers to receive real-time notifications of auth events.
 * The webhook includes URL, signing secret, and event filtering.
 * 
 * DynamoDB Schema:
 * - Table: zalt-webhooks
 * - pk: REALM#{realmId}#WEBHOOK#{webhookId}
 * - sk: WEBHOOK
 * - GSI: realm-index (realmId -> webhooks)
 * 
 * Security Requirements:
 * - Secret must be cryptographically secure (32 bytes, hex encoded)
 * - Payload must be signed with HMAC-SHA256
 * - Audit logging for all operations
 * 
 * Validates: Requirements 12.1 (Webhook System)
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'crypto';

/**
 * Webhook status types
 */
export type WebhookStatus = 'active' | 'inactive' | 'deleted';

/**
 * Supported webhook event types
 */
export type WebhookEventType =
  // User events
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  // Session events
  | 'session.created'
  | 'session.revoked'
  // Tenant events
  | 'tenant.created'
  | 'tenant.updated'
  | 'tenant.deleted'
  // Member events
  | 'member.invited'
  | 'member.joined'
  | 'member.removed'
  // MFA events
  | 'mfa.enabled'
  | 'mfa.disabled'
  // Billing events
  | 'billing.subscription.created'
  | 'billing.subscription.updated'
  | 'billing.subscription.canceled'
  | 'billing.payment.succeeded'
  | 'billing.payment.failed'
  // Security events (Task 15.6 - Requirement 10.9)
  | 'security.high_risk_login';

/**
 * All supported webhook events
 */
export const WEBHOOK_EVENTS: WebhookEventType[] = [
  'user.created',
  'user.updated',
  'user.deleted',
  'session.created',
  'session.revoked',
  'tenant.created',
  'tenant.updated',
  'tenant.deleted',
  'member.invited',
  'member.joined',
  'member.removed',
  'mfa.enabled',
  'mfa.disabled',
  'billing.subscription.created',
  'billing.subscription.updated',
  'billing.subscription.canceled',
  'billing.payment.succeeded',
  'billing.payment.failed',
  // Security events (Task 15.6 - Requirement 10.9)
  'security.high_risk_login'
];

/**
 * Webhook entity
 */
export interface Webhook {
  id: string;                    // webhook_xxx format
  realm_id: string;              // Realm this webhook belongs to
  url: string;                   // Webhook endpoint URL (HTTPS required)
  secret: string;                // HMAC-SHA256 signing secret (hex encoded)
  events: WebhookEventType[];    // Events to subscribe to
  status: WebhookStatus;         // Current status
  description?: string;          // Optional description
  created_at: string;            // Creation timestamp
  updated_at?: string;           // Last update timestamp
  last_triggered_at?: string;    // Last successful delivery
  metadata?: WebhookMetadata;    // Additional metadata
}

/**
 * Webhook metadata for additional context
 */
export interface WebhookMetadata {
  created_by?: string;           // User who created the webhook
  failure_count?: number;        // Consecutive failure count
  last_failure_at?: string;      // Last failure timestamp
  last_failure_reason?: string;  // Last failure reason
  total_deliveries?: number;     // Total delivery attempts
  successful_deliveries?: number; // Successful deliveries
}

/**
 * Input for creating a webhook
 */
export interface CreateWebhookInput {
  realm_id: string;
  url: string;
  events: WebhookEventType[];
  description?: string;
  created_by?: string;
}

/**
 * Input for updating a webhook
 */
export interface UpdateWebhookInput {
  url?: string;
  events?: WebhookEventType[];
  status?: WebhookStatus;
  description?: string;
}

/**
 * Webhook response (API response format)
 */
export interface WebhookResponse {
  id: string;
  realm_id: string;
  url: string;
  events: WebhookEventType[];
  status: WebhookStatus;
  description?: string;
  created_at: string;
  updated_at?: string;
  last_triggered_at?: string;
  metadata?: Omit<WebhookMetadata, 'created_by'>;
}

/**
 * Webhook with secret (returned only on creation or rotation)
 */
export interface WebhookWithSecret {
  webhook: WebhookResponse;
  secret: string;                // Raw secret - only returned once
}

/**
 * Webhook payload structure
 */
export interface WebhookPayload {
  id: string;                    // Unique delivery ID
  type: WebhookEventType;        // Event type
  timestamp: string;             // ISO 8601 timestamp
  idempotency_key: string;       // For deduplication
  data: Record<string, unknown>; // Event-specific data
}

/**
 * Webhook signature header format
 */
export interface WebhookSignatureHeaders {
  'x-zalt-signature': string;    // HMAC-SHA256 signature
  'x-zalt-timestamp': string;    // Unix timestamp
  'x-zalt-delivery-id': string;  // Delivery ID
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Webhook ID prefix
 */
export const WEBHOOK_ID_PREFIX = 'webhook_';

/**
 * Secret length in bytes (32 bytes = 64 hex chars)
 */
export const WEBHOOK_SECRET_BYTES = 32;

/**
 * Maximum events per webhook
 */
export const MAX_EVENTS_PER_WEBHOOK = 50;

/**
 * Maximum webhooks per realm
 */
export const MAX_WEBHOOKS_PER_REALM = 10;

/**
 * Signature timestamp tolerance in seconds (5 minutes)
 */
export const SIGNATURE_TIMESTAMP_TOLERANCE = 300;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate unique webhook ID
 */
export function generateWebhookId(): string {
  return `${WEBHOOK_ID_PREFIX}${randomBytes(12).toString('hex')}`;
}

/**
 * Generate cryptographically secure webhook secret
 * Returns 64 character hex string (32 bytes)
 */
export function generateWebhookSecret(): string {
  return randomBytes(WEBHOOK_SECRET_BYTES).toString('hex');
}

/**
 * Generate unique delivery ID
 */
export function generateDeliveryId(): string {
  return `del_${randomBytes(16).toString('hex')}`;
}

/**
 * Generate idempotency key for webhook payload
 */
export function generateIdempotencyKey(): string {
  return `idem_${randomBytes(16).toString('hex')}`;
}

/**
 * Create HMAC-SHA256 signature for webhook payload
 * 
 * @param payload - The webhook payload as string
 * @param timestamp - Unix timestamp
 * @param secret - The webhook secret
 * @returns The HMAC-SHA256 signature
 */
export function createWebhookSignature(
  payload: string,
  timestamp: number,
  secret: string
): string {
  const signedPayload = `${timestamp}.${payload}`;
  return createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');
}

/**
 * Verify webhook signature
 * Uses timing-safe comparison to prevent timing attacks
 * 
 * @param payload - The webhook payload as string
 * @param signature - The signature to verify
 * @param timestamp - Unix timestamp from header
 * @param secret - The webhook secret
 * @returns True if signature is valid
 */
export function verifyWebhookSignature(
  payload: string,
  signature: string,
  timestamp: number,
  secret: string
): boolean {
  // Check timestamp is within tolerance
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > SIGNATURE_TIMESTAMP_TOLERANCE) {
    return false;
  }
  
  // Calculate expected signature
  const expectedSignature = createWebhookSignature(payload, timestamp, secret);
  
  // Use timing-safe comparison
  try {
    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');
    
    if (sigBuffer.length !== expectedBuffer.length) {
      return false;
    }
    
    return timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    return false;
  }
}

/**
 * Validate webhook URL
 * Must be HTTPS and valid URL format
 */
export function isValidWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Validate webhook event type
 */
export function isValidWebhookEvent(event: string): event is WebhookEventType {
  return WEBHOOK_EVENTS.includes(event as WebhookEventType);
}

/**
 * Validate webhook status
 */
export function isValidWebhookStatus(status: string): status is WebhookStatus {
  return ['active', 'inactive', 'deleted'].includes(status);
}

/**
 * Check if event matches webhook subscription
 * Supports wildcard matching (e.g., 'user.*' matches 'user.created')
 */
export function eventMatchesSubscription(
  event: WebhookEventType,
  subscriptions: WebhookEventType[]
): boolean {
  return subscriptions.some(sub => {
    if (sub === event) return true;
    // Support wildcard matching
    if (sub.endsWith('.*')) {
      const prefix = sub.slice(0, -2);
      return event.startsWith(prefix + '.');
    }
    return false;
  });
}

/**
 * Convert Webhook to API response format (excludes sensitive data)
 */
export function toWebhookResponse(webhook: Webhook): WebhookResponse {
  const { created_by, ...safeMetadata } = webhook.metadata || {};
  
  return {
    id: webhook.id,
    realm_id: webhook.realm_id,
    url: webhook.url,
    events: webhook.events,
    status: webhook.status,
    description: webhook.description,
    created_at: webhook.created_at,
    updated_at: webhook.updated_at,
    last_triggered_at: webhook.last_triggered_at,
    metadata: Object.keys(safeMetadata).length > 0 ? safeMetadata : undefined
  };
}

/**
 * Create webhook payload
 */
export function createWebhookPayload(
  eventType: WebhookEventType,
  data: Record<string, unknown>
): WebhookPayload {
  return {
    id: generateDeliveryId(),
    type: eventType,
    timestamp: new Date().toISOString(),
    idempotency_key: generateIdempotencyKey(),
    data
  };
}

/**
 * Create webhook signature headers
 */
export function createSignatureHeaders(
  payload: string,
  secret: string,
  deliveryId: string
): WebhookSignatureHeaders {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = createWebhookSignature(payload, timestamp, secret);
  
  return {
    'x-zalt-signature': signature,
    'x-zalt-timestamp': timestamp.toString(),
    'x-zalt-delivery-id': deliveryId
  };
}

/**
 * Mask webhook URL for display (hide path and query params)
 */
export function maskWebhookUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}/***`;
  } catch {
    return '***';
  }
}
