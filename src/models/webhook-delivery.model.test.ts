/**
 * WebhookDelivery Model Tests
 * Tests for webhook delivery model utilities and helper functions
 * 
 * Validates: Requirements 12.7 (Webhook Delivery Logs)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

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
  DELIVERY_ID_PREFIX,
  DEFAULT_MAX_ATTEMPTS,
  RETRY_DELAYS_SECONDS,
  MAX_RESPONSE_BODY_LENGTH,
  WebhookDelivery,
  DeliveryStatus,
  CreateWebhookDeliveryInput
} from './webhook-delivery.model';

describe('WebhookDelivery Model Utilities', () => {
  describe('generateDeliveryId', () => {
    it('should generate ID with del_ prefix', () => {
      const id = generateDeliveryId();
      expect(id).toMatch(/^del_[a-f0-9]{32}$/);
      expect(id.startsWith(DELIVERY_ID_PREFIX)).toBe(true);
    });
    
    it('should generate unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateDeliveryId());
      }
      expect(ids.size).toBe(100);
    });
  });

  describe('calculateRetryDelay', () => {
    it('should return correct delay for each attempt', () => {
      expect(calculateRetryDelay(1)).toBe(1);    // 1 second
      expect(calculateRetryDelay(2)).toBe(5);    // 5 seconds
      expect(calculateRetryDelay(3)).toBe(30);   // 30 seconds
      expect(calculateRetryDelay(4)).toBe(300);  // 5 minutes
    });
    
    it('should return null when max attempts exceeded', () => {
      expect(calculateRetryDelay(5)).toBeNull();
      expect(calculateRetryDelay(10)).toBeNull();
    });
    
    it('should match defined retry schedule', () => {
      for (const schedule of RETRY_DELAYS_SECONDS) {
        expect(calculateRetryDelay(schedule.attempt)).toBe(schedule.delay_seconds);
      }
    });
  });

  describe('calculateNextRetryAt', () => {
    it('should return ISO timestamp for valid attempts', () => {
      const nextRetry = calculateNextRetryAt(1);
      expect(nextRetry).not.toBeNull();
      expect(nextRetry).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
    
    it('should return null when max attempts exceeded', () => {
      expect(calculateNextRetryAt(5)).toBeNull();
    });
    
    it('should return future timestamp', () => {
      const now = Date.now();
      const nextRetry = calculateNextRetryAt(1);
      expect(nextRetry).not.toBeNull();
      const nextRetryTime = new Date(nextRetry!).getTime();
      expect(nextRetryTime).toBeGreaterThan(now);
    });
    
    it('should increase delay with each attempt', () => {
      const retry1 = new Date(calculateNextRetryAt(1)!).getTime();
      const retry2 = new Date(calculateNextRetryAt(2)!).getTime();
      const retry3 = new Date(calculateNextRetryAt(3)!).getTime();
      
      // Each retry should be further in the future
      expect(retry2 - retry1).toBeGreaterThan(0);
      expect(retry3 - retry2).toBeGreaterThan(0);
    });
  });

  describe('shouldRetry', () => {
    const createDelivery = (status: DeliveryStatus, attempts: number): WebhookDelivery => ({
      id: 'del_test',
      webhook_id: 'webhook_test',
      event_type: 'user.created',
      payload: { id: 'evt_1', type: 'user.created', timestamp: '', idempotency_key: '', data: {} },
      status,
      attempts,
      max_attempts: DEFAULT_MAX_ATTEMPTS,
      created_at: new Date().toISOString()
    });
    
    it('should not retry successful deliveries', () => {
      const delivery = createDelivery('success', 1);
      expect(shouldRetry(delivery)).toBe(false);
    });
    
    it('should retry pending deliveries', () => {
      const delivery = createDelivery('pending', 0);
      expect(shouldRetry(delivery)).toBe(true);
    });
    
    it('should retry retrying deliveries under max attempts', () => {
      const delivery = createDelivery('retrying', 2);
      expect(shouldRetry(delivery)).toBe(true);
    });
    
    it('should not retry when max attempts reached', () => {
      const delivery = createDelivery('retrying', DEFAULT_MAX_ATTEMPTS);
      expect(shouldRetry(delivery)).toBe(false);
    });
    
    it('should not retry failed deliveries at max attempts', () => {
      const delivery = createDelivery('failed', DEFAULT_MAX_ATTEMPTS);
      expect(shouldRetry(delivery)).toBe(false);
    });
  });

  describe('isDeliveryComplete', () => {
    const createDelivery = (status: DeliveryStatus, attempts: number): WebhookDelivery => ({
      id: 'del_test',
      webhook_id: 'webhook_test',
      event_type: 'user.created',
      payload: { id: 'evt_1', type: 'user.created', timestamp: '', idempotency_key: '', data: {} },
      status,
      attempts,
      max_attempts: DEFAULT_MAX_ATTEMPTS,
      created_at: new Date().toISOString()
    });
    
    it('should return true for successful deliveries', () => {
      const delivery = createDelivery('success', 1);
      expect(isDeliveryComplete(delivery)).toBe(true);
    });
    
    it('should return true for failed deliveries at max attempts', () => {
      const delivery = createDelivery('failed', DEFAULT_MAX_ATTEMPTS);
      expect(isDeliveryComplete(delivery)).toBe(true);
    });
    
    it('should return false for pending deliveries', () => {
      const delivery = createDelivery('pending', 0);
      expect(isDeliveryComplete(delivery)).toBe(false);
    });
    
    it('should return false for retrying deliveries', () => {
      const delivery = createDelivery('retrying', 2);
      expect(isDeliveryComplete(delivery)).toBe(false);
    });
  });

  describe('isReadyForRetry', () => {
    const createDelivery = (status: DeliveryStatus, nextRetryAt?: string): WebhookDelivery => ({
      id: 'del_test',
      webhook_id: 'webhook_test',
      event_type: 'user.created',
      payload: { id: 'evt_1', type: 'user.created', timestamp: '', idempotency_key: '', data: {} },
      status,
      attempts: 1,
      max_attempts: DEFAULT_MAX_ATTEMPTS,
      created_at: new Date().toISOString(),
      next_retry_at: nextRetryAt
    });
    
    it('should return false for non-retrying status', () => {
      expect(isReadyForRetry(createDelivery('pending'))).toBe(false);
      expect(isReadyForRetry(createDelivery('success'))).toBe(false);
      expect(isReadyForRetry(createDelivery('failed'))).toBe(false);
    });
    
    it('should return true for retrying without next_retry_at', () => {
      const delivery = createDelivery('retrying');
      expect(isReadyForRetry(delivery)).toBe(true);
    });
    
    it('should return true when next_retry_at is in the past', () => {
      const pastTime = new Date(Date.now() - 60000).toISOString();
      const delivery = createDelivery('retrying', pastTime);
      expect(isReadyForRetry(delivery)).toBe(true);
    });
    
    it('should return false when next_retry_at is in the future', () => {
      const futureTime = new Date(Date.now() + 60000).toISOString();
      const delivery = createDelivery('retrying', futureTime);
      expect(isReadyForRetry(delivery)).toBe(false);
    });
  });

  describe('determineDeliveryStatus', () => {
    it('should return success for successful result', () => {
      const result = { success: true, response_code: 200 };
      expect(determineDeliveryStatus(result, 1, 5)).toBe('success');
    });
    
    it('should return retrying when under max attempts', () => {
      const result = { success: false, error: 'Connection timeout' };
      expect(determineDeliveryStatus(result, 1, 5)).toBe('retrying');
      expect(determineDeliveryStatus(result, 4, 5)).toBe('retrying');
    });
    
    it('should return failed when max attempts reached', () => {
      const result = { success: false, error: 'Connection timeout' };
      expect(determineDeliveryStatus(result, 5, 5)).toBe('failed');
    });
  });

  describe('isSuccessStatusCode', () => {
    it('should return true for 2xx status codes', () => {
      expect(isSuccessStatusCode(200)).toBe(true);
      expect(isSuccessStatusCode(201)).toBe(true);
      expect(isSuccessStatusCode(204)).toBe(true);
      expect(isSuccessStatusCode(299)).toBe(true);
    });
    
    it('should return false for non-2xx status codes', () => {
      expect(isSuccessStatusCode(100)).toBe(false);
      expect(isSuccessStatusCode(301)).toBe(false);
      expect(isSuccessStatusCode(400)).toBe(false);
      expect(isSuccessStatusCode(500)).toBe(false);
    });
  });

  describe('isRetryableStatusCode', () => {
    it('should return true for retryable status codes', () => {
      expect(isRetryableStatusCode(408)).toBe(true);  // Request Timeout
      expect(isRetryableStatusCode(429)).toBe(true);  // Too Many Requests
      expect(isRetryableStatusCode(500)).toBe(true);  // Internal Server Error
      expect(isRetryableStatusCode(502)).toBe(true);  // Bad Gateway
      expect(isRetryableStatusCode(503)).toBe(true);  // Service Unavailable
      expect(isRetryableStatusCode(504)).toBe(true);  // Gateway Timeout
    });
    
    it('should return true for all 5xx status codes', () => {
      expect(isRetryableStatusCode(500)).toBe(true);
      expect(isRetryableStatusCode(501)).toBe(true);
      expect(isRetryableStatusCode(599)).toBe(true);
    });
    
    it('should return false for non-retryable status codes', () => {
      expect(isRetryableStatusCode(200)).toBe(false);
      expect(isRetryableStatusCode(400)).toBe(false);
      expect(isRetryableStatusCode(401)).toBe(false);
      expect(isRetryableStatusCode(403)).toBe(false);
      expect(isRetryableStatusCode(404)).toBe(false);
    });
  });

  describe('truncateResponseBody', () => {
    it('should not truncate short bodies', () => {
      const body = 'Short response';
      expect(truncateResponseBody(body)).toBe(body);
    });
    
    it('should truncate long bodies', () => {
      const body = 'x'.repeat(MAX_RESPONSE_BODY_LENGTH + 100);
      const truncated = truncateResponseBody(body);
      
      expect(truncated.length).toBeLessThan(body.length);
      expect(truncated).toContain('... [truncated]');
    });
    
    it('should truncate at exact max length', () => {
      const body = 'x'.repeat(MAX_RESPONSE_BODY_LENGTH + 1);
      const truncated = truncateResponseBody(body);
      
      expect(truncated.startsWith('x'.repeat(MAX_RESPONSE_BODY_LENGTH))).toBe(true);
    });
  });

  describe('sanitizeErrorMessage', () => {
    it('should sanitize Error objects', () => {
      const error = new Error('Connection failed at /path/to/file.js:123');
      const sanitized = sanitizeErrorMessage(error);
      
      expect(sanitized).not.toContain('/path/to/file.js');
      expect(sanitized).toContain('Connection failed');
    });
    
    it('should truncate long string errors', () => {
      const error = 'x'.repeat(1000);
      const sanitized = sanitizeErrorMessage(error);
      
      expect(sanitized.length).toBeLessThanOrEqual(500);
    });
    
    it('should handle unknown error types', () => {
      expect(sanitizeErrorMessage(null)).toBe('Unknown error');
      expect(sanitizeErrorMessage(undefined)).toBe('Unknown error');
      expect(sanitizeErrorMessage(123)).toBe('Unknown error');
    });
  });

  describe('toWebhookDeliveryResponse', () => {
    it('should convert delivery to response format', () => {
      const delivery: WebhookDelivery = {
        id: 'del_test123',
        webhook_id: 'webhook_abc',
        event_type: 'user.created',
        payload: {
          id: 'evt_1',
          type: 'user.created',
          timestamp: '2026-01-25T10:00:00Z',
          idempotency_key: 'idem_123',
          data: { user_id: 'user_123' }
        },
        status: 'success',
        attempts: 1,
        max_attempts: 5,
        response_code: 200,
        response_time_ms: 150,
        created_at: '2026-01-25T10:00:00Z',
        completed_at: '2026-01-25T10:00:01Z'
      };
      
      const response = toWebhookDeliveryResponse(delivery);
      
      expect(response.id).toBe(delivery.id);
      expect(response.webhook_id).toBe(delivery.webhook_id);
      expect(response.event_type).toBe(delivery.event_type);
      expect(response.status).toBe(delivery.status);
      expect(response.attempts).toBe(delivery.attempts);
      expect(response.max_attempts).toBe(delivery.max_attempts);
      expect(response.response_code).toBe(delivery.response_code);
      expect(response.response_time_ms).toBe(delivery.response_time_ms);
      expect(response.created_at).toBe(delivery.created_at);
      expect(response.completed_at).toBe(delivery.completed_at);
      
      // Should not include payload (sensitive data)
      expect((response as unknown as { payload?: unknown }).payload).toBeUndefined();
    });
    
    it('should handle delivery with error', () => {
      const delivery: WebhookDelivery = {
        id: 'del_test123',
        webhook_id: 'webhook_abc',
        event_type: 'user.created',
        payload: { id: 'evt_1', type: 'user.created', timestamp: '', idempotency_key: '', data: {} },
        status: 'failed',
        attempts: 5,
        max_attempts: 5,
        error: 'Connection timeout',
        created_at: '2026-01-25T10:00:00Z'
      };
      
      const response = toWebhookDeliveryResponse(delivery);
      
      expect(response.error).toBe('Connection timeout');
    });
  });

  describe('createWebhookDeliveryFromInput', () => {
    it('should create delivery with default values', () => {
      const input: CreateWebhookDeliveryInput = {
        webhook_id: 'webhook_abc',
        event_type: 'user.created',
        payload: {
          id: 'evt_1',
          type: 'user.created',
          timestamp: '2026-01-25T10:00:00Z',
          idempotency_key: 'idem_123',
          data: { user_id: 'user_123' }
        }
      };
      
      const delivery = createWebhookDeliveryFromInput(input);
      
      expect(delivery.id).toMatch(/^del_[a-f0-9]{32}$/);
      expect(delivery.webhook_id).toBe(input.webhook_id);
      expect(delivery.event_type).toBe(input.event_type);
      expect(delivery.payload).toEqual(input.payload);
      expect(delivery.status).toBe('pending');
      expect(delivery.attempts).toBe(0);
      expect(delivery.max_attempts).toBe(DEFAULT_MAX_ATTEMPTS);
      expect(delivery.created_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
    
    it('should include metadata if provided', () => {
      const input: CreateWebhookDeliveryInput = {
        webhook_id: 'webhook_abc',
        event_type: 'user.created',
        payload: { id: 'evt_1', type: 'user.created', timestamp: '', idempotency_key: '', data: {} },
        metadata: {
          realm_id: 'realm_123',
          target_url: 'https://example.com/webhook'
        }
      };
      
      const delivery = createWebhookDeliveryFromInput(input);
      
      expect(delivery.metadata?.realm_id).toBe('realm_123');
      expect(delivery.metadata?.target_url).toBe('https://example.com/webhook');
    });
  });

  describe('isValidDeliveryStatus', () => {
    it('should accept valid statuses', () => {
      expect(isValidDeliveryStatus('pending')).toBe(true);
      expect(isValidDeliveryStatus('success')).toBe(true);
      expect(isValidDeliveryStatus('failed')).toBe(true);
      expect(isValidDeliveryStatus('retrying')).toBe(true);
    });
    
    it('should reject invalid statuses', () => {
      expect(isValidDeliveryStatus('invalid')).toBe(false);
      expect(isValidDeliveryStatus('PENDING')).toBe(false);
      expect(isValidDeliveryStatus('')).toBe(false);
      expect(isValidDeliveryStatus('completed')).toBe(false);
    });
  });

  describe('getStatusDescription', () => {
    it('should return correct descriptions', () => {
      expect(getStatusDescription('pending')).toBe('Waiting to be delivered');
      expect(getStatusDescription('success')).toBe('Successfully delivered');
      expect(getStatusDescription('failed')).toBe('Delivery failed after all retries');
      expect(getStatusDescription('retrying')).toBe('Waiting for retry');
    });
  });

  describe('calculateDeliveryStats', () => {
    const createDelivery = (
      status: DeliveryStatus, 
      responseTimeMs?: number
    ): WebhookDelivery => ({
      id: generateDeliveryId(),
      webhook_id: 'webhook_test',
      event_type: 'user.created',
      payload: { id: 'evt_1', type: 'user.created', timestamp: '', idempotency_key: '', data: {} },
      status,
      attempts: status === 'pending' ? 0 : 1,
      max_attempts: DEFAULT_MAX_ATTEMPTS,
      response_time_ms: responseTimeMs,
      created_at: new Date().toISOString()
    });
    
    it('should calculate correct counts', () => {
      const deliveries = [
        createDelivery('pending'),
        createDelivery('success', 100),
        createDelivery('success', 200),
        createDelivery('failed'),
        createDelivery('retrying')
      ];
      
      const stats = calculateDeliveryStats(deliveries);
      
      expect(stats.total).toBe(5);
      expect(stats.pending).toBe(1);
      expect(stats.success).toBe(2);
      expect(stats.failed).toBe(1);
      expect(stats.retrying).toBe(1);
    });
    
    it('should calculate average response time', () => {
      const deliveries = [
        createDelivery('success', 100),
        createDelivery('success', 200),
        createDelivery('success', 300)
      ];
      
      const stats = calculateDeliveryStats(deliveries);
      
      expect(stats.averageResponseTime).toBe(200);
    });
    
    it('should calculate success rate', () => {
      const deliveries = [
        createDelivery('success'),
        createDelivery('success'),
        createDelivery('success'),
        createDelivery('failed')
      ];
      
      const stats = calculateDeliveryStats(deliveries);
      
      expect(stats.successRate).toBe(75);
    });
    
    it('should handle empty array', () => {
      const stats = calculateDeliveryStats([]);
      
      expect(stats.total).toBe(0);
      expect(stats.pending).toBe(0);
      expect(stats.success).toBe(0);
      expect(stats.failed).toBe(0);
      expect(stats.retrying).toBe(0);
      expect(stats.averageResponseTime).toBeNull();
      expect(stats.successRate).toBe(0);
    });
    
    it('should handle deliveries without response time', () => {
      const deliveries = [
        createDelivery('pending'),
        createDelivery('retrying')
      ];
      
      const stats = calculateDeliveryStats(deliveries);
      
      expect(stats.averageResponseTime).toBeNull();
    });
  });
});
