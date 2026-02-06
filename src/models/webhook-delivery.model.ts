/**
 * WebhookDelivery Model - Webhook Delivery Tracking for Zalt.io
 * 
 * Tracks all webhook delivery attempts including status, retries, and responses.
 * Used for debugging, monitoring, and retry logic.
 * 
 * DynamoDB Schema:
 * - Table: zalt-webhook-deliveries
 * - pk: WEBHOOK#{webhookId}#DELIVERY#{deliveryId}
 * - sk: DELIVERY#{timestamp}
 * - GSI: webhook-index (webhookId -> deliveries)
 * 
 * Security Requirements:
 * - Payload must be stored securely
 * - Error messages must not leak sensitive information
 * - Audit logging for all delivery attempts
 * 
 * Validates: Requirements 12.7 (Webhook Delivery Logs)
 */

import { randomBytes } from 'crypto';

/**
 * Delivery status types
 */
export type DeliveryStatus = 'pending' | 'success' | 'failed' | 'retrying';

/**
 * WebhookDelivery entity
 */
export interface WebhookDelivery {
  id: string;                    // del_xxx format
  webhook_id: string;            // Parent webhook ID
  event_type: string;            // Event type that triggered delivery
  payload: WebhookDeliveryPayload; // The payload that was/will be sent
  status: DeliveryStatus;        // Current delivery status
  attempts: number;              // Number of delivery attempts
  max_attempts: number;          // Maximum retry attempts
  response_code?: number;        // HTTP response code from endpoint
  response_time_ms?: number;     // Response time in milliseconds
  error?: string;                // Error message if failed
  next_retry_at?: string;        // Next retry timestamp (ISO 8601)
  created_at: string;            // Creation timestamp (ISO 8601)
  updated_at?: string;           // Last update timestamp (ISO 8601)
  completed_at?: string;         // Completion timestamp (ISO 8601)
  metadata?: WebhookDeliveryMetadata; // Additional metadata
}

/**
 * Webhook delivery payload structure
 */
export interface WebhookDeliveryPayload {
  id: string;                    // Unique event ID
  type: string;                  // Event type
  timestamp: string;             // ISO 8601 timestamp
  idempotency_key: string;       // For deduplication
  data: Record<string, unknown>; // Event-specific data
}

/**
 * Webhook delivery metadata
 */
export interface WebhookDeliveryMetadata {
  realm_id?: string;             // Realm ID for context
  target_url?: string;           // Target webhook URL
  request_headers?: Record<string, string>; // Request headers sent
  response_headers?: Record<string, string>; // Response headers received
  response_body?: string;        // Response body (truncated)
  ip_address?: string;           // IP address of the endpoint
  user_agent?: string;           // User agent used for request
}

/**
 * Input for creating a webhook delivery
 */
export interface CreateWebhookDeliveryInput {
  webhook_id: string;
  event_type: string;
  payload: WebhookDeliveryPayload;
  metadata?: Partial<WebhookDeliveryMetadata>;
}

/**
 * Input for updating a webhook delivery
 */
export interface UpdateWebhookDeliveryInput {
  status?: DeliveryStatus;
  attempts?: number;
  response_code?: number;
  response_time_ms?: number;
  error?: string;
  next_retry_at?: string;
  completed_at?: string;
  metadata?: Partial<WebhookDeliveryMetadata>;
}

/**
 * Webhook delivery response (API response format)
 */
export interface WebhookDeliveryResponse {
  id: string;
  webhook_id: string;
  event_type: string;
  status: DeliveryStatus;
  attempts: number;
  max_attempts: number;
  response_code?: number;
  response_time_ms?: number;
  error?: string;
  next_retry_at?: string;
  created_at: string;
  updated_at?: string;
  completed_at?: string;
}

/**
 * Delivery attempt result
 */
export interface DeliveryAttemptResult {
  success: boolean;
  response_code?: number;
  response_time_ms?: number;
  error?: string;
  response_body?: string;
  response_headers?: Record<string, string>;
}

/**
 * Retry schedule configuration
 */
export interface RetrySchedule {
  attempt: number;
  delay_seconds: number;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Delivery ID prefix
 */
export const DELIVERY_ID_PREFIX = 'del_';

/**
 * Default maximum retry attempts
 */
export const DEFAULT_MAX_ATTEMPTS = 5;

/**
 * Retry delays in seconds (exponential backoff)
 * Attempt 1: 1s, Attempt 2: 5s, Attempt 3: 30s, Attempt 4: 300s (5m)
 */
export const RETRY_DELAYS_SECONDS: RetrySchedule[] = [
  { attempt: 1, delay_seconds: 1 },
  { attempt: 2, delay_seconds: 5 },
  { attempt: 3, delay_seconds: 30 },
  { attempt: 4, delay_seconds: 300 }  // 5 minutes
];

/**
 * Maximum response body length to store (prevent large payloads)
 */
export const MAX_RESPONSE_BODY_LENGTH = 1024;

/**
 * Delivery timeout in milliseconds
 */
export const DELIVERY_TIMEOUT_MS = 30000; // 30 seconds

/**
 * Maximum deliveries to return in a single query
 */
export const MAX_DELIVERIES_PER_QUERY = 100;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate unique delivery ID
 */
export function generateDeliveryId(): string {
  return `${DELIVERY_ID_PREFIX}${randomBytes(16).toString('hex')}`;
}

/**
 * Calculate next retry delay based on attempt number
 * Uses exponential backoff strategy
 * 
 * @param attempt - Current attempt number (1-based)
 * @returns Delay in seconds, or null if max attempts reached
 */
export function calculateRetryDelay(attempt: number): number | null {
  const schedule = RETRY_DELAYS_SECONDS.find(s => s.attempt === attempt);
  if (schedule) {
    return schedule.delay_seconds;
  }
  
  // If attempt exceeds defined schedule, return null (no more retries)
  if (attempt > RETRY_DELAYS_SECONDS.length) {
    return null;
  }
  
  // Fallback: exponential backoff
  return Math.min(Math.pow(2, attempt) * 5, 3600); // Max 1 hour
}

/**
 * Calculate next retry timestamp
 * 
 * @param attempt - Current attempt number (1-based)
 * @returns ISO 8601 timestamp for next retry, or null if no more retries
 */
export function calculateNextRetryAt(attempt: number): string | null {
  const delaySeconds = calculateRetryDelay(attempt);
  if (delaySeconds === null) {
    return null;
  }
  
  const nextRetry = new Date(Date.now() + delaySeconds * 1000);
  return nextRetry.toISOString();
}

/**
 * Check if delivery should be retried
 * 
 * @param delivery - The webhook delivery
 * @returns True if delivery should be retried
 */
export function shouldRetry(delivery: WebhookDelivery): boolean {
  // Don't retry successful deliveries
  if (delivery.status === 'success') {
    return false;
  }
  
  // Don't retry if max attempts reached
  if (delivery.attempts >= delivery.max_attempts) {
    return false;
  }
  
  // Don't retry if already marked as failed (final)
  if (delivery.status === 'failed' && delivery.attempts >= delivery.max_attempts) {
    return false;
  }
  
  return true;
}

/**
 * Check if delivery is complete (success or final failure)
 * 
 * @param delivery - The webhook delivery
 * @returns True if delivery is complete
 */
export function isDeliveryComplete(delivery: WebhookDelivery): boolean {
  return delivery.status === 'success' || 
         (delivery.status === 'failed' && delivery.attempts >= delivery.max_attempts);
}

/**
 * Check if delivery is ready for retry
 * 
 * @param delivery - The webhook delivery
 * @returns True if delivery is ready for retry
 */
export function isReadyForRetry(delivery: WebhookDelivery): boolean {
  if (delivery.status !== 'retrying') {
    return false;
  }
  
  if (!delivery.next_retry_at) {
    return true;
  }
  
  const nextRetryTime = new Date(delivery.next_retry_at).getTime();
  return Date.now() >= nextRetryTime;
}

/**
 * Determine delivery status based on attempt result
 * 
 * @param result - The delivery attempt result
 * @param currentAttempts - Current number of attempts
 * @param maxAttempts - Maximum allowed attempts
 * @returns The new delivery status
 */
export function determineDeliveryStatus(
  result: DeliveryAttemptResult,
  currentAttempts: number,
  maxAttempts: number
): DeliveryStatus {
  if (result.success) {
    return 'success';
  }
  
  // Check if we should retry
  if (currentAttempts < maxAttempts) {
    return 'retrying';
  }
  
  return 'failed';
}

/**
 * Check if HTTP status code indicates success
 * 
 * @param statusCode - HTTP status code
 * @returns True if status code indicates success (2xx)
 */
export function isSuccessStatusCode(statusCode: number): boolean {
  return statusCode >= 200 && statusCode < 300;
}

/**
 * Check if HTTP status code indicates a retryable error
 * 
 * @param statusCode - HTTP status code
 * @returns True if error is retryable
 */
export function isRetryableStatusCode(statusCode: number): boolean {
  // Retry on server errors (5xx) and some client errors
  const retryableCodes = [
    408, // Request Timeout
    429, // Too Many Requests
    500, // Internal Server Error
    502, // Bad Gateway
    503, // Service Unavailable
    504  // Gateway Timeout
  ];
  
  return retryableCodes.includes(statusCode) || statusCode >= 500;
}

/**
 * Truncate response body to maximum length
 * 
 * @param body - Response body
 * @returns Truncated body
 */
export function truncateResponseBody(body: string): string {
  if (body.length <= MAX_RESPONSE_BODY_LENGTH) {
    return body;
  }
  
  return body.substring(0, MAX_RESPONSE_BODY_LENGTH) + '... [truncated]';
}

/**
 * Sanitize error message (remove sensitive information)
 * 
 * @param error - Error message or Error object
 * @returns Sanitized error message
 */
export function sanitizeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    // Remove stack traces and sensitive paths
    return error.message.replace(/at .+/g, '').trim();
  }
  
  if (typeof error === 'string') {
    return error.substring(0, 500);
  }
  
  return 'Unknown error';
}

/**
 * Convert WebhookDelivery to API response format
 * Excludes sensitive data like full payload
 */
export function toWebhookDeliveryResponse(delivery: WebhookDelivery): WebhookDeliveryResponse {
  return {
    id: delivery.id,
    webhook_id: delivery.webhook_id,
    event_type: delivery.event_type,
    status: delivery.status,
    attempts: delivery.attempts,
    max_attempts: delivery.max_attempts,
    response_code: delivery.response_code,
    response_time_ms: delivery.response_time_ms,
    error: delivery.error,
    next_retry_at: delivery.next_retry_at,
    created_at: delivery.created_at,
    updated_at: delivery.updated_at,
    completed_at: delivery.completed_at
  };
}

/**
 * Create a new webhook delivery from input
 */
export function createWebhookDeliveryFromInput(
  input: CreateWebhookDeliveryInput
): WebhookDelivery {
  const now = new Date().toISOString();
  
  return {
    id: generateDeliveryId(),
    webhook_id: input.webhook_id,
    event_type: input.event_type,
    payload: input.payload,
    status: 'pending',
    attempts: 0,
    max_attempts: DEFAULT_MAX_ATTEMPTS,
    created_at: now,
    metadata: input.metadata as WebhookDeliveryMetadata
  };
}

/**
 * Validate delivery status
 */
export function isValidDeliveryStatus(status: string): status is DeliveryStatus {
  return ['pending', 'success', 'failed', 'retrying'].includes(status);
}

/**
 * Get human-readable status description
 */
export function getStatusDescription(status: DeliveryStatus): string {
  const descriptions: Record<DeliveryStatus, string> = {
    pending: 'Waiting to be delivered',
    success: 'Successfully delivered',
    failed: 'Delivery failed after all retries',
    retrying: 'Waiting for retry'
  };
  
  return descriptions[status];
}

/**
 * Calculate delivery statistics from a list of deliveries
 */
export function calculateDeliveryStats(deliveries: WebhookDelivery[]): {
  total: number;
  pending: number;
  success: number;
  failed: number;
  retrying: number;
  averageResponseTime: number | null;
  successRate: number;
} {
  const stats = {
    total: deliveries.length,
    pending: 0,
    success: 0,
    failed: 0,
    retrying: 0,
    averageResponseTime: null as number | null,
    successRate: 0
  };
  
  let totalResponseTime = 0;
  let responseTimeCount = 0;
  
  for (const delivery of deliveries) {
    stats[delivery.status]++;
    
    if (delivery.response_time_ms !== undefined) {
      totalResponseTime += delivery.response_time_ms;
      responseTimeCount++;
    }
  }
  
  if (responseTimeCount > 0) {
    stats.averageResponseTime = Math.round(totalResponseTime / responseTimeCount);
  }
  
  const completed = stats.success + stats.failed;
  if (completed > 0) {
    stats.successRate = Math.round((stats.success / completed) * 100);
  }
  
  return stats;
}
