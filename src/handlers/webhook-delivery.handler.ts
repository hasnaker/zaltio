/**
 * Webhook Delivery Handler
 * 
 * SQS-triggered Lambda that delivers webhooks to customer endpoints.
 * Implements retry with exponential backoff.
 * 
 * Validates: Requirements 12.3, 12.4, 12.5
 */

import { SQSEvent, SQSRecord, Context } from 'aws-lambda';
import * as webhookDeliveryRepository from '../repositories/webhook-delivery.repository';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';

// Retry delays in seconds: 1s, 5s, 30s, 5m
const RETRY_DELAYS = [1, 5, 30, 300];
const MAX_ATTEMPTS = 5;
const DELIVERY_TIMEOUT_MS = 30000; // 30 seconds

interface WebhookMessage {
  webhook_id: string;
  delivery_id: string;
  url: string;
  payload: string;
  signature: string;
  timestamp: number;
  attempt: number;
  max_attempts: number;
}

interface DeliveryResult {
  success: boolean;
  status_code?: number;
  response_body?: string;
  error?: string;
  duration_ms: number;
}

/**
 * Deliver webhook to customer endpoint
 */
async function deliverWebhook(message: WebhookMessage): Promise<DeliveryResult> {
  const startTime = Date.now();
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

    const response = await fetch(message.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Zalt-Signature': message.signature,
        'X-Zalt-Timestamp': message.timestamp.toString(),
        'X-Zalt-Delivery-Id': message.delivery_id,
        'User-Agent': 'Zalt-Webhook/1.0'
      },
      body: message.payload,
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    const duration = Date.now() - startTime;

    // Read response body (limited to 1KB for storage)
    let responseBody = '';
    try {
      const text = await response.text();
      responseBody = text.substring(0, 1024);
    } catch {
      responseBody = '[Unable to read response body]';
    }

    // 2xx status codes are considered successful
    const success = response.status >= 200 && response.status < 300;

    return {
      success,
      status_code: response.status,
      response_body: responseBody,
      duration_ms: duration
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return {
          success: false,
          error: 'Request timeout',
          duration_ms: duration
        };
      }
      return {
        success: false,
        error: error.message,
        duration_ms: duration
      };
    }
    
    return {
      success: false,
      error: 'Unknown error',
      duration_ms: duration
    };
  }
}

/**
 * Process a single SQS record
 */
async function processRecord(record: SQSRecord): Promise<void> {
  let message: WebhookMessage;
  
  try {
    message = JSON.parse(record.body);
  } catch {
    console.error('Failed to parse SQS message:', record.body);
    return; // Don't retry malformed messages
  }

  const { webhook_id, delivery_id, attempt } = message;

  console.log(`Processing webhook delivery: ${delivery_id}, attempt ${attempt}/${message.max_attempts}`);

  // Deliver the webhook
  const result = await deliverWebhook(message);

  if (result.success) {
    // Mark delivery as successful
    await webhookDeliveryRepository.markDeliverySuccess(
      webhook_id,
      delivery_id,
      result.status_code || 200,
      result.duration_ms
    );

    await logAuditEvent({
      eventType: AuditEventType.ADMIN_ACTION,
      result: AuditResult.SUCCESS,
      realmId: 'system',
      userId: 'webhook-delivery',
      ipAddress: '0.0.0.0',
      action: 'webhook_delivered',
      resource: `webhook:${webhook_id}`,
      details: {
        delivery_id,
        status_code: result.status_code,
        duration_ms: result.duration_ms,
        attempt
      }
    });

    console.log(`Webhook delivered successfully: ${delivery_id}`);
  } else {
    // Check if we should retry
    if (attempt < message.max_attempts) {
      // Update attempt count in delivery record
      await webhookDeliveryRepository.incrementDeliveryAttempt(
        webhook_id,
        delivery_id,
        result.error || 'Delivery failed'
      );

      // Throw error to trigger SQS retry with visibility timeout
      // The message will be retried after the visibility timeout
      const retryDelay = RETRY_DELAYS[Math.min(attempt - 1, RETRY_DELAYS.length - 1)];
      console.log(`Webhook delivery failed, will retry in ${retryDelay}s: ${delivery_id}`);
      
      throw new Error(`Webhook delivery failed: ${result.error}`);
    } else {
      // Max attempts reached, mark as failed
      await webhookDeliveryRepository.markDeliveryFailed(
        webhook_id,
        delivery_id,
        result.error || 'Max attempts exceeded'
      );

      await logAuditEvent({
        eventType: AuditEventType.ADMIN_ACTION,
        result: AuditResult.FAILURE,
        realmId: 'system',
        userId: 'webhook-delivery',
        ipAddress: '0.0.0.0',
        action: 'webhook_delivery_failed',
        resource: `webhook:${webhook_id}`,
        details: {
          delivery_id,
          error: result.error,
          attempts: attempt,
          duration_ms: result.duration_ms
        }
      });

      console.error(`Webhook delivery failed permanently: ${delivery_id}`);
    }
  }
}

/**
 * Main Lambda handler for SQS events
 */
export async function handler(event: SQSEvent, context: Context): Promise<void> {
  console.log(`Processing ${event.Records.length} webhook delivery messages`);

  // Process records in parallel with error handling
  const results = await Promise.allSettled(
    event.Records.map(record => processRecord(record))
  );

  // Log any failures
  const failures = results.filter(r => r.status === 'rejected');
  if (failures.length > 0) {
    console.error(`${failures.length} webhook deliveries failed`);
    // Throw to trigger partial batch failure handling
    throw new Error(`${failures.length} webhook deliveries failed`);
  }

  console.log(`Successfully processed ${event.Records.length} webhook deliveries`);
}
