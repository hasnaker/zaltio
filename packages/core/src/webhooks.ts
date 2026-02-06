/**
 * Webhook Signature Verification for Zalt.io SDK
 * 
 * Provides utilities for verifying webhook signatures in your application.
 * Use this to ensure webhook payloads are authentic and haven't been tampered with.
 * 
 * Security:
 * - HMAC-SHA256 signatures
 * - Timing-safe comparison to prevent timing attacks
 * - Timestamp validation to prevent replay attacks
 * 
 * Validates: Requirement 12.10
 * 
 * @example
 * ```typescript
 * import { verifyWebhookSignature, WebhookVerificationError } from '@zalt/core';
 * 
 * // In your webhook handler
 * app.post('/webhooks/zalt', (req, res) => {
 *   const signature = req.headers['zalt-signature'];
 *   const payload = req.body; // raw body string
 *   
 *   try {
 *     const isValid = verifyWebhookSignature(payload, signature, process.env.WEBHOOK_SECRET);
 *     if (!isValid) {
 *       return res.status(401).json({ error: 'Invalid signature' });
 *     }
 *     // Process webhook...
 *   } catch (error) {
 *     if (error instanceof WebhookVerificationError) {
 *       return res.status(401).json({ error: error.message });
 *     }
 *     throw error;
 *   }
 * });
 * ```
 */

import { createHmac, timingSafeEqual } from 'crypto';

// ============================================================================
// Configuration
// ============================================================================

/**
 * Default timestamp tolerance in seconds (5 minutes)
 * Webhooks older than this will be rejected to prevent replay attacks
 */
export const DEFAULT_TIMESTAMP_TOLERANCE = 300;

// ============================================================================
// Types
// ============================================================================

/**
 * Options for webhook signature verification
 */
export interface WebhookVerifyOptions {
  /**
   * Maximum age of webhook in seconds (default: 300 = 5 minutes)
   * Set to 0 to disable timestamp validation
   */
  timestampTolerance?: number;
  
  /**
   * Current timestamp for testing purposes
   * Defaults to current time
   */
  currentTimestamp?: number;
}

/**
 * Parsed webhook signature components
 */
export interface ParsedSignature {
  timestamp: number;
  signature: string;
}

/**
 * Webhook payload structure
 */
export interface WebhookPayload {
  id: string;
  type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

// ============================================================================
// Errors
// ============================================================================

/**
 * Error codes for webhook verification failures
 */
export enum WebhookVerificationErrorCode {
  INVALID_SIGNATURE_FORMAT = 'INVALID_SIGNATURE_FORMAT',
  SIGNATURE_MISMATCH = 'SIGNATURE_MISMATCH',
  TIMESTAMP_EXPIRED = 'TIMESTAMP_EXPIRED',
  MISSING_SIGNATURE = 'MISSING_SIGNATURE',
  MISSING_SECRET = 'MISSING_SECRET',
  INVALID_PAYLOAD = 'INVALID_PAYLOAD'
}

/**
 * Error thrown when webhook verification fails
 */
export class WebhookVerificationError extends Error {
  constructor(
    public code: WebhookVerificationErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'WebhookVerificationError';
  }
}

// ============================================================================
// Main Functions
// ============================================================================

/**
 * Verify a webhook signature
 * 
 * Validates that the webhook payload was sent by Zalt.io and hasn't been
 * tampered with. Also validates the timestamp to prevent replay attacks.
 * 
 * @param payload - The raw webhook payload (string or object)
 * @param signature - The signature from the 'zalt-signature' header
 * @param secret - Your webhook signing secret (starts with 'whsec_')
 * @param options - Optional verification options
 * @returns true if signature is valid
 * @throws WebhookVerificationError if verification fails
 * 
 * @example
 * ```typescript
 * const isValid = verifyWebhookSignature(
 *   req.body,
 *   req.headers['zalt-signature'],
 *   process.env.WEBHOOK_SECRET
 * );
 * ```
 */
export function verifyWebhookSignature(
  payload: string | object,
  signature: string | undefined | null,
  secret: string | undefined | null,
  options: WebhookVerifyOptions = {}
): boolean {
  // Validate inputs
  if (!signature) {
    throw new WebhookVerificationError(
      WebhookVerificationErrorCode.MISSING_SIGNATURE,
      'Missing webhook signature header'
    );
  }

  if (!secret) {
    throw new WebhookVerificationError(
      WebhookVerificationErrorCode.MISSING_SECRET,
      'Missing webhook secret'
    );
  }

  // Convert payload to string if needed
  const payloadString = typeof payload === 'string' 
    ? payload 
    : JSON.stringify(payload);

  if (!payloadString) {
    throw new WebhookVerificationError(
      WebhookVerificationErrorCode.INVALID_PAYLOAD,
      'Invalid webhook payload'
    );
  }

  // Parse signature header
  const parsed = parseSignatureHeader(signature);

  // Validate timestamp
  const {
    timestampTolerance = DEFAULT_TIMESTAMP_TOLERANCE,
    currentTimestamp = Math.floor(Date.now() / 1000)
  } = options;

  if (timestampTolerance > 0) {
    const age = currentTimestamp - parsed.timestamp;
    if (age > timestampTolerance) {
      throw new WebhookVerificationError(
        WebhookVerificationErrorCode.TIMESTAMP_EXPIRED,
        `Webhook timestamp too old (${age}s > ${timestampTolerance}s tolerance)`
      );
    }
    // Also check for future timestamps (clock skew)
    if (age < -timestampTolerance) {
      throw new WebhookVerificationError(
        WebhookVerificationErrorCode.TIMESTAMP_EXPIRED,
        'Webhook timestamp is in the future'
      );
    }
  }

  // Compute expected signature
  const signedPayload = `${parsed.timestamp}.${payloadString}`;
  const expectedSignature = computeSignature(signedPayload, secret);

  // Timing-safe comparison
  const isValid = safeCompare(parsed.signature, expectedSignature);

  if (!isValid) {
    throw new WebhookVerificationError(
      WebhookVerificationErrorCode.SIGNATURE_MISMATCH,
      'Webhook signature does not match'
    );
  }

  return true;
}

/**
 * Parse the signature header into components
 * 
 * Signature format: t=timestamp,v1=signature
 * 
 * @param header - The signature header value
 * @returns Parsed timestamp and signature
 */
export function parseSignatureHeader(header: string): ParsedSignature {
  const parts = header.split(',');
  let timestamp: number | undefined;
  let signature: string | undefined;

  for (const part of parts) {
    const [key, value] = part.split('=');
    if (key === 't') {
      timestamp = parseInt(value, 10);
    } else if (key === 'v1') {
      signature = value;
    }
  }

  // Handle simple signature format (just hex string)
  if (!timestamp && !signature && header.length === 64 && /^[a-f0-9]+$/i.test(header)) {
    throw new WebhookVerificationError(
      WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT,
      'Invalid signature format. Expected: t=timestamp,v1=signature'
    );
  }

  if (timestamp === undefined || isNaN(timestamp)) {
    throw new WebhookVerificationError(
      WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT,
      'Missing or invalid timestamp in signature header'
    );
  }

  if (!signature) {
    throw new WebhookVerificationError(
      WebhookVerificationErrorCode.INVALID_SIGNATURE_FORMAT,
      'Missing signature value in signature header'
    );
  }

  return { timestamp, signature };
}

/**
 * Compute HMAC-SHA256 signature
 * 
 * @param payload - The payload to sign
 * @param secret - The signing secret
 * @returns Hex-encoded signature
 */
export function computeSignature(payload: string, secret: string): string {
  return createHmac('sha256', secret)
    .update(payload, 'utf8')
    .digest('hex');
}

/**
 * Timing-safe string comparison
 * 
 * Prevents timing attacks by ensuring comparison takes constant time
 * regardless of where strings differ.
 * 
 * @param a - First string
 * @param b - Second string
 * @returns true if strings are equal
 */
export function safeCompare(a: string, b: string): boolean {
  try {
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');

    if (bufA.length !== bufB.length) {
      return false;
    }

    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Construct a webhook event from raw payload
 * 
 * Parses and validates the webhook payload structure.
 * 
 * @param payload - Raw payload string or object
 * @returns Parsed webhook payload
 */
export function constructWebhookEvent(payload: string | object): WebhookPayload {
  const data = typeof payload === 'string' ? JSON.parse(payload) : payload;

  if (!data.id || !data.type || !data.timestamp || !data.data) {
    throw new WebhookVerificationError(
      WebhookVerificationErrorCode.INVALID_PAYLOAD,
      'Invalid webhook payload structure'
    );
  }

  return data as WebhookPayload;
}

/**
 * Create a signature for testing purposes
 * 
 * Useful for testing webhook handlers in development.
 * 
 * @param payload - The payload to sign
 * @param secret - The signing secret
 * @param timestamp - Optional timestamp (defaults to current time)
 * @returns Formatted signature header value
 */
export function createTestSignature(
  payload: string | object,
  secret: string,
  timestamp?: number
): string {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const payloadString = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const signedPayload = `${ts}.${payloadString}`;
  const signature = computeSignature(signedPayload, secret);
  return `t=${ts},v1=${signature}`;
}
