/**
 * Tediyat Webhook Service
 * HMAC-SHA256 signing with timestamp for replay protection
 * 
 * Validates: Requirements 22.1-22.4
 * Property 25: Webhook Signature Verification
 */

import crypto from 'crypto';

export type WebhookEventType =
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'tenant.created'
  | 'tenant.updated'
  | 'tenant.deleted'
  | 'member.added'
  | 'member.removed'
  | 'member.role_changed'
  | 'session.created'
  | 'session.terminated';

export interface WebhookEvent {
  id: string;
  type: WebhookEventType;
  timestamp: string;
  data: Record<string, unknown>;
  tenant_id?: string;
}

export interface WebhookDelivery {
  event: WebhookEvent;
  signature: string;
  timestamp: number;
}

export interface WebhookConfig {
  url: string;
  secret: string;
  events: WebhookEventType[];
  enabled: boolean;
}

const SIGNATURE_VERSION = 'v1';
const TIMESTAMP_TOLERANCE_SECONDS = 300; // 5 minutes

/**
 * Generate webhook signature using HMAC-SHA256
 */
export function generateSignature(
  payload: string,
  secret: string,
  timestamp: number
): string {
  const signedPayload = `${timestamp}.${payload}`;
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(signedPayload);
  return `${SIGNATURE_VERSION}=${hmac.digest('hex')}`;
}

/**
 * Verify webhook signature
 */
export function verifySignature(
  payload: string,
  signature: string,
  secret: string,
  timestamp: number
): boolean {
  // Check timestamp is within tolerance (replay protection)
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > TIMESTAMP_TOLERANCE_SECONDS) {
    return false;
  }

  const expectedSignature = generateSignature(payload, secret, timestamp);
  
  // Check length first (timingSafeEqual requires same length)
  if (signature.length !== expectedSignature.length) {
    return false;
  }
  
  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

/**
 * Create webhook event
 */
export function createWebhookEvent(
  type: WebhookEventType,
  data: Record<string, unknown>,
  tenantId?: string
): WebhookEvent {
  return {
    id: `evt_${crypto.randomBytes(16).toString('hex')}`,
    type,
    timestamp: new Date().toISOString(),
    data,
    ...(tenantId && { tenant_id: tenantId }),
  };
}

/**
 * Prepare webhook delivery with signature
 */
export function prepareWebhookDelivery(
  event: WebhookEvent,
  secret: string
): WebhookDelivery {
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = JSON.stringify(event);
  const signature = generateSignature(payload, secret, timestamp);

  return {
    event,
    signature,
    timestamp,
  };
}

/**
 * Format webhook headers for HTTP request
 */
export function formatWebhookHeaders(delivery: WebhookDelivery): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'X-Webhook-Signature': delivery.signature,
    'X-Webhook-Timestamp': delivery.timestamp.toString(),
    'X-Webhook-Id': delivery.event.id,
  };
}

/**
 * Send webhook (async, fire-and-forget with retry logic)
 */
export async function sendWebhook(
  config: WebhookConfig,
  event: WebhookEvent,
  maxRetries: number = 3
): Promise<{ success: boolean; statusCode?: number; error?: string }> {
  if (!config.enabled) {
    return { success: false, error: 'Webhook disabled' };
  }

  if (!config.events.includes(event.type)) {
    return { success: false, error: 'Event type not subscribed' };
  }

  const delivery = prepareWebhookDelivery(event, config.secret);
  const headers = formatWebhookHeaders(delivery);
  const body = JSON.stringify(delivery.event);

  let lastError: string | undefined;
  let lastStatusCode: number | undefined;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await fetch(config.url, {
        method: 'POST',
        headers,
        body,
        signal: AbortSignal.timeout(10000), // 10 second timeout
      });

      lastStatusCode = response.status;

      if (response.ok) {
        return { success: true, statusCode: response.status };
      }

      // Don't retry on 4xx errors (client errors)
      if (response.status >= 400 && response.status < 500) {
        return { success: false, statusCode: response.status, error: `Client error: ${response.status}` };
      }

      lastError = `Server error: ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : 'Unknown error';
    }

    // Exponential backoff before retry
    if (attempt < maxRetries - 1) {
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
    }
  }

  return { success: false, statusCode: lastStatusCode, error: lastError };
}

/**
 * Parse and verify incoming webhook (for receiving webhooks)
 */
export function parseIncomingWebhook(
  body: string,
  signature: string,
  timestamp: string,
  secret: string
): { valid: boolean; event?: WebhookEvent; error?: string } {
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts)) {
    return { valid: false, error: 'Invalid timestamp' };
  }

  if (!verifySignature(body, signature, secret, ts)) {
    return { valid: false, error: 'Invalid signature or expired timestamp' };
  }

  try {
    const event = JSON.parse(body) as WebhookEvent;
    return { valid: true, event };
  } catch {
    return { valid: false, error: 'Invalid JSON payload' };
  }
}
