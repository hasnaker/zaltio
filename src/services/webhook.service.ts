/**
 * Webhook Service - Webhook Management and Delivery for Zalt.io
 * 
 * Handles the complete webhook lifecycle:
 * - Creating webhooks with signing secrets
 * - Dispatching webhook events to SQS for async delivery
 * - Testing webhooks with test events
 * - Managing delivery logs
 * - Rotating webhook secrets
 * - Verifying webhook signatures
 * 
 * Security Requirements:
 * - HMAC-SHA256 signatures for all payloads
 * - Timing-safe signature comparison
 * - Secure secret generation (32 bytes)
 * - Audit logging for all operations
 * 
 * Validates: Requirements 12.1, 12.3, 12.6, 12.9
 */

import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import {
  Webhook,
  WebhookResponse,
  WebhookWithSecret,
  WebhookEventType,
  WebhookPayload,
  CreateWebhookInput,
  UpdateWebhookInput,
  createWebhookPayload,
  createWebhookSignature,
  verifyWebhookSignature as verifySignatureHelper,
  toWebhookResponse,
  isValidWebhookUrl,
  isValidWebhookEvent,
  eventMatchesSubscription,
  generateWebhookSecret,
  SIGNATURE_TIMESTAMP_TOLERANCE
} from '../models/webhook.model';
import {
  WebhookDelivery,
  WebhookDeliveryResponse,
  CreateWebhookDeliveryInput,
  toWebhookDeliveryResponse,
  DEFAULT_MAX_ATTEMPTS
} from '../models/webhook-delivery.model';
import * as webhookRepository from '../repositories/webhook.repository';
import * as webhookDeliveryRepository from '../repositories/webhook-delivery.repository';
import { logAuditEvent, AuditEventType, AuditResult } from './audit.service';
import { timingSafeEqual, createHmac } from 'crypto';

// ============================================================================
// Configuration
// ============================================================================

const SQS_QUEUE_URL = process.env.WEBHOOK_QUEUE_URL || 'https://sqs.eu-central-1.amazonaws.com/123456789/zalt-webhook-queue';
const sqsClient = new SQSClient({ region: process.env.AWS_REGION || 'eu-central-1' });

// ============================================================================
// Types
// ============================================================================

/**
 * Input for creating a webhook via the service
 */
export interface CreateWebhookServiceInput {
  realm_id: string;
  url: string;
  events: WebhookEventType[];
  description?: string;
  created_by?: string;
}

/**
 * Input for dispatching a webhook event
 */
export interface DispatchWebhookInput {
  realm_id: string;
  event_type: WebhookEventType;
  data: Record<string, unknown>;
}

/**
 * Input for testing a webhook
 */
export interface TestWebhookInput {
  webhook_id: string;
  realm_id: string;
  tested_by?: string;
}

/**
 * Input for getting delivery logs
 */
export interface GetDeliveryLogsInput {
  webhook_id: string;
  realm_id: string;
  limit?: number;
  cursor?: string;
}

/**
 * Input for rotating webhook secret
 */
export interface RotateSecretInput {
  webhook_id: string;
  realm_id: string;
  rotated_by?: string;
}

/**
 * Result of dispatching webhooks
 */
export interface DispatchResult {
  webhooks_triggered: number;
  delivery_ids: string[];
}

/**
 * Service error codes
 */
export enum WebhookErrorCode {
  INVALID_URL = 'INVALID_URL',
  INVALID_EVENT = 'INVALID_EVENT',
  WEBHOOK_NOT_FOUND = 'WEBHOOK_NOT_FOUND',
  WEBHOOK_DISABLED = 'WEBHOOK_DISABLED',
  MAX_WEBHOOKS_EXCEEDED = 'MAX_WEBHOOKS_EXCEEDED',
  DISPATCH_FAILED = 'DISPATCH_FAILED',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  SIGNATURE_EXPIRED = 'SIGNATURE_EXPIRED'
}

/**
 * Service error class
 */
export class WebhookServiceError extends Error {
  constructor(
    public code: WebhookErrorCode,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'WebhookServiceError';
  }
}

// ============================================================================
// Webhook Service Class
// ============================================================================

/**
 * Webhook Service
 * Handles all webhook-related business logic
 */
export class WebhookService {
  private sqsClient: SQSClient;
  private queueUrl: string;

  constructor(sqsClientInstance?: SQSClient, queueUrl?: string) {
    this.sqsClient = sqsClientInstance || sqsClient;
    this.queueUrl = queueUrl || SQS_QUEUE_URL;
  }

  /**
   * Create a new webhook
   * 
   * Security:
   * - Validates URL (must be HTTPS)
   * - Validates event types
   * - Generates cryptographically secure signing secret
   * - Audit logs the operation
   * 
   * Validates: Requirement 12.1
   */
  async create(input: CreateWebhookServiceInput): Promise<WebhookWithSecret> {
    // Validate URL
    if (!isValidWebhookUrl(input.url)) {
      throw new WebhookServiceError(
        WebhookErrorCode.INVALID_URL,
        'Invalid webhook URL. Must be HTTPS.'
      );
    }

    // Validate events
    for (const event of input.events) {
      if (!isValidWebhookEvent(event)) {
        throw new WebhookServiceError(
          WebhookErrorCode.INVALID_EVENT,
          `Invalid webhook event: ${event}`
        );
      }
    }

    // Create webhook in repository
    const createInput: CreateWebhookInput = {
      realm_id: input.realm_id,
      url: input.url,
      events: input.events,
      description: input.description,
      created_by: input.created_by
    };

    try {
      const result = await webhookRepository.createWebhook(createInput);

      // Audit log
      await this.logAuditEvent(input.realm_id, input.created_by, 'webhook_created', {
        webhook_id: result.webhook.id,
        url: input.url,
        events: input.events
      });

      return result;
    } catch (error) {
      if (error instanceof Error && error.message.includes('Maximum webhooks')) {
        throw new WebhookServiceError(
          WebhookErrorCode.MAX_WEBHOOKS_EXCEEDED,
          error.message
        );
      }
      throw error;
    }
  }

  /**
   * Dispatch webhook event to all subscribed webhooks
   * 
   * Queues webhook delivery via SQS for async processing.
   * Creates delivery records for tracking.
   * 
   * Validates: Requirement 12.3
   */
  async dispatch(input: DispatchWebhookInput): Promise<DispatchResult> {
    // Get all active webhooks for this realm that subscribe to this event
    const webhooks = await webhookRepository.getWebhooksForEvent(
      input.realm_id,
      input.event_type
    );

    if (webhooks.length === 0) {
      return { webhooks_triggered: 0, delivery_ids: [] };
    }

    const deliveryIds: string[] = [];

    // Create delivery records and queue messages for each webhook
    for (const webhook of webhooks) {
      try {
        // Check if webhook subscribes to this event
        if (!eventMatchesSubscription(input.event_type, webhook.events)) {
          continue;
        }

        // Create webhook payload
        const payload = createWebhookPayload(input.event_type, input.data);

        // Create delivery record
        const deliveryInput: CreateWebhookDeliveryInput = {
          webhook_id: webhook.id,
          event_type: input.event_type,
          payload,
          metadata: {
            realm_id: input.realm_id,
            target_url: webhook.url
          }
        };

        const delivery = await webhookDeliveryRepository.createWebhookDelivery(deliveryInput);
        deliveryIds.push(delivery.id);

        // Queue for async delivery via SQS
        await this.queueDelivery(webhook, delivery, payload);
      } catch (error) {
        // Log error but continue with other webhooks
        console.error(`Failed to dispatch webhook ${webhook.id}:`, error);
      }
    }

    return {
      webhooks_triggered: deliveryIds.length,
      delivery_ids: deliveryIds
    };
  }

  /**
   * Test a webhook by sending a test event
   * 
   * Sends a test event to verify webhook configuration.
   * 
   * Validates: Requirement 12.6
   */
  async test(input: TestWebhookInput): Promise<WebhookDeliveryResponse> {
    // Get webhook
    const webhook = await webhookRepository.getWebhookById(input.realm_id, input.webhook_id);
    
    if (!webhook) {
      throw new WebhookServiceError(
        WebhookErrorCode.WEBHOOK_NOT_FOUND,
        'Webhook not found'
      );
    }

    if (webhook.status !== 'active') {
      throw new WebhookServiceError(
        WebhookErrorCode.WEBHOOK_DISABLED,
        'Webhook is not active'
      );
    }

    // Create test payload
    const testPayload = createWebhookPayload('user.created' as WebhookEventType, {
      test: true,
      message: 'This is a test webhook delivery from Zalt.io',
      timestamp: new Date().toISOString()
    });

    // Create delivery record
    const deliveryInput: CreateWebhookDeliveryInput = {
      webhook_id: webhook.id,
      event_type: 'test',
      payload: testPayload,
      metadata: {
        realm_id: input.realm_id,
        target_url: webhook.url
      }
    };

    const delivery = await webhookDeliveryRepository.createWebhookDelivery(deliveryInput);

    // Queue for delivery
    await this.queueDelivery(webhook, delivery, testPayload);

    // Audit log
    await this.logAuditEvent(input.realm_id, input.tested_by, 'webhook_tested', {
      webhook_id: input.webhook_id,
      delivery_id: delivery.id
    });

    return toWebhookDeliveryResponse(delivery);
  }

  /**
   * Get delivery logs for a webhook
   * 
   * Returns the delivery history with status and response details.
   * 
   * Validates: Requirement 12.7
   */
  async getDeliveryLogs(input: GetDeliveryLogsInput): Promise<{
    deliveries: WebhookDeliveryResponse[];
    next_cursor?: string;
  }> {
    // Verify webhook exists
    const webhook = await webhookRepository.getWebhookById(input.realm_id, input.webhook_id);
    
    if (!webhook) {
      throw new WebhookServiceError(
        WebhookErrorCode.WEBHOOK_NOT_FOUND,
        'Webhook not found'
      );
    }

    const result = await webhookDeliveryRepository.listWebhookDeliveries(
      input.webhook_id,
      {
        limit: input.limit || 100,
        cursor: input.cursor
      }
    );

    return {
      deliveries: result.deliveries,
      next_cursor: result.nextCursor
    };
  }

  /**
   * Rotate webhook signing secret
   * 
   * Generates a new signing secret. The old secret is immediately invalidated.
   * 
   * Validates: Requirement 12.9
   */
  async rotateSecret(input: RotateSecretInput): Promise<WebhookWithSecret> {
    // Verify webhook exists
    const webhook = await webhookRepository.getWebhookById(input.realm_id, input.webhook_id);
    
    if (!webhook) {
      throw new WebhookServiceError(
        WebhookErrorCode.WEBHOOK_NOT_FOUND,
        'Webhook not found'
      );
    }

    // Rotate secret in repository
    const result = await webhookRepository.rotateWebhookSecret(input.realm_id, input.webhook_id);
    
    if (!result) {
      throw new WebhookServiceError(
        WebhookErrorCode.WEBHOOK_NOT_FOUND,
        'Failed to rotate webhook secret'
      );
    }

    // Audit log
    await this.logAuditEvent(input.realm_id, input.rotated_by, 'webhook_secret_rotated', {
      webhook_id: input.webhook_id
    });

    return result;
  }

  /**
   * Verify webhook signature
   * 
   * Verifies HMAC-SHA256 signature using timing-safe comparison.
   * 
   * Security:
   * - Uses timing-safe comparison to prevent timing attacks
   * - Validates timestamp to prevent replay attacks
   * 
   * Validates: Requirement 12.3
   */
  verifySignature(payload: string, signature: string, secret: string): boolean {
    // Parse signature header format: t=timestamp,v1=signature
    const parts = signature.split(',');
    let timestamp: number | undefined;
    let sig: string | undefined;

    for (const part of parts) {
      const [key, value] = part.split('=');
      if (key === 't') {
        timestamp = parseInt(value, 10);
      } else if (key === 'v1') {
        sig = value;
      }
    }

    // If simple signature format (just the hex string)
    if (!timestamp && !sig && signature.length === 64) {
      // For simple verification without timestamp
      return this.verifySimpleSignature(payload, signature, secret);
    }

    if (!timestamp || !sig) {
      return false;
    }

    // Use the helper function from model
    return verifySignatureHelper(payload, sig, timestamp, secret);
  }

  /**
   * Verify simple signature (without timestamp)
   * Used for SDK verification where timestamp is handled separately
   */
  private verifySimpleSignature(payload: string, signature: string, secret: string): boolean {
    try {
      const expectedSignature = createHmac('sha256', secret)
        .update(payload)
        .digest('hex');

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
   * Get webhook by ID
   */
  async getById(realmId: string, webhookId: string): Promise<WebhookResponse | null> {
    const webhook = await webhookRepository.getWebhookById(realmId, webhookId);
    if (!webhook) {
      return null;
    }
    return toWebhookResponse(webhook);
  }

  /**
   * List webhooks for a realm
   */
  async list(realmId: string, options?: {
    status?: 'active' | 'inactive' | 'deleted';
    limit?: number;
    cursor?: string;
  }): Promise<{ webhooks: WebhookResponse[]; next_cursor?: string }> {
    const result = await webhookRepository.listWebhooksByRealm(realmId, options);
    return {
      webhooks: result.webhooks,
      next_cursor: result.nextCursor
    };
  }

  /**
   * Update a webhook
   */
  async update(
    realmId: string,
    webhookId: string,
    input: UpdateWebhookInput,
    updatedBy?: string
  ): Promise<WebhookResponse | null> {
    // Validate URL if provided
    if (input.url && !isValidWebhookUrl(input.url)) {
      throw new WebhookServiceError(
        WebhookErrorCode.INVALID_URL,
        'Invalid webhook URL. Must be HTTPS.'
      );
    }

    // Validate events if provided
    if (input.events) {
      for (const event of input.events) {
        if (!isValidWebhookEvent(event)) {
          throw new WebhookServiceError(
            WebhookErrorCode.INVALID_EVENT,
            `Invalid webhook event: ${event}`
          );
        }
      }
    }

    const webhook = await webhookRepository.updateWebhook(realmId, webhookId, input);
    
    if (!webhook) {
      return null;
    }

    // Audit log
    await this.logAuditEvent(realmId, updatedBy, 'webhook_updated', {
      webhook_id: webhookId,
      changes: input
    });

    return toWebhookResponse(webhook);
  }

  /**
   * Delete a webhook (soft delete)
   */
  async delete(realmId: string, webhookId: string, deletedBy?: string): Promise<boolean> {
    const result = await webhookRepository.deleteWebhook(realmId, webhookId);
    
    if (result) {
      // Audit log
      await this.logAuditEvent(realmId, deletedBy, 'webhook_deleted', {
        webhook_id: webhookId
      });
    }

    return result;
  }

  /**
   * Get webhook statistics
   */
  async getStatistics(realmId: string): Promise<{
    active: number;
    inactive: number;
    deleted: number;
  }> {
    return webhookRepository.countWebhooksByStatus(realmId);
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Queue webhook delivery via SQS
   */
  private async queueDelivery(
    webhook: Webhook,
    delivery: WebhookDelivery,
    payload: WebhookPayload
  ): Promise<void> {
    const payloadString = JSON.stringify(payload);
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = createWebhookSignature(payloadString, timestamp, webhook.secret);

    const message = {
      webhook_id: webhook.id,
      delivery_id: delivery.id,
      url: webhook.url,
      payload: payloadString,
      signature: `t=${timestamp},v1=${signature}`,
      timestamp,
      attempt: 1,
      max_attempts: DEFAULT_MAX_ATTEMPTS
    };

    try {
      await this.sqsClient.send(new SendMessageCommand({
        QueueUrl: this.queueUrl,
        MessageBody: JSON.stringify(message),
        MessageGroupId: webhook.id, // FIFO queue support
        MessageDeduplicationId: delivery.id
      }));
    } catch (error) {
      console.error('Failed to queue webhook delivery:', error);
      // Update delivery status to failed
      await webhookDeliveryRepository.markDeliveryFailed(
        webhook.id,
        delivery.id,
        'Failed to queue delivery'
      );
      throw new WebhookServiceError(
        WebhookErrorCode.DISPATCH_FAILED,
        'Failed to queue webhook delivery'
      );
    }
  }

  /**
   * Log audit event
   */
  private async logAuditEvent(
    realmId: string,
    userId: string | undefined,
    action: string,
    details: Record<string, unknown>
  ): Promise<void> {
    try {
      await logAuditEvent({
        eventType: AuditEventType.ADMIN_ACTION,
        result: AuditResult.SUCCESS,
        realmId,
        userId: userId || 'system',
        ipAddress: '0.0.0.0',
        action,
        resource: `webhook:${details.webhook_id || 'unknown'}`,
        details
      });
    } catch (error) {
      // Log but don't fail the operation
      console.error('Failed to log audit event:', error);
    }
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

/**
 * Default webhook service instance
 */
export const webhookService = new WebhookService();

// ============================================================================
// Convenience Functions (for backward compatibility and external use)
// ============================================================================

/**
 * Create a new webhook
 */
export async function createWebhook(
  realmId: string,
  url: string,
  events: WebhookEventType[],
  options?: { description?: string; created_by?: string }
): Promise<WebhookWithSecret> {
  return webhookService.create({
    realm_id: realmId,
    url,
    events,
    description: options?.description,
    created_by: options?.created_by
  });
}

/**
 * Dispatch webhook event
 */
export async function dispatchWebhook(
  realmId: string,
  eventType: WebhookEventType,
  data: Record<string, unknown>
): Promise<DispatchResult> {
  return webhookService.dispatch({
    realm_id: realmId,
    event_type: eventType,
    data
  });
}

/**
 * Test a webhook
 */
export async function testWebhook(
  webhookId: string,
  realmId: string,
  testedBy?: string
): Promise<WebhookDeliveryResponse> {
  return webhookService.test({
    webhook_id: webhookId,
    realm_id: realmId,
    tested_by: testedBy
  });
}

/**
 * Get delivery logs for a webhook
 */
export async function getWebhookDeliveryLogs(
  webhookId: string,
  realmId: string,
  limit?: number
): Promise<{ deliveries: WebhookDeliveryResponse[]; next_cursor?: string }> {
  return webhookService.getDeliveryLogs({
    webhook_id: webhookId,
    realm_id: realmId,
    limit
  });
}

/**
 * Rotate webhook secret
 */
export async function rotateWebhookSecret(
  webhookId: string,
  realmId: string,
  rotatedBy?: string
): Promise<WebhookWithSecret> {
  return webhookService.rotateSecret({
    webhook_id: webhookId,
    realm_id: realmId,
    rotated_by: rotatedBy
  });
}

/**
 * Verify webhook signature
 * Utility function for SDK and external use
 */
export function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): boolean {
  return webhookService.verifySignature(payload, signature, secret);
}
