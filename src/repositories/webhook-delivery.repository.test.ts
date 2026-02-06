/**
 * WebhookDelivery Repository Tests
 * Tests for webhook delivery CRUD operations
 * 
 * Validates: Requirements 12.7 (Webhook Delivery Logs)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 * 
 * Security Requirements Tested:
 * - Payload must be stored securely
 * - Error messages must not leak sensitive information
 */

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  }
}));

// Import after mocks
import {
  createWebhookDelivery,
  getWebhookDeliveryById,
  listWebhookDeliveries,
  getPendingDeliveries,
  getRecentDeliveries,
  countDeliveriesByStatus,
  updateWebhookDelivery,
  recordDeliveryAttempt,
  markDeliverySuccess,
  markDeliveryFailed,
  deleteWebhookDelivery,
  deleteAllWebhookDeliveries,
  deleteOldDeliveries,
  getDeliveryStats
} from './webhook-delivery.repository';

import {
  DeliveryStatus,
  DEFAULT_MAX_ATTEMPTS
} from '../models/webhook-delivery.model';

describe('WebhookDelivery Repository', () => {
  const mockWebhookId = 'webhook_test123';
  const mockDeliveryId = 'del_abc123def456';
  const mockEventType = 'user.created';
  const mockPayload = {
    id: 'evt_123',
    type: 'user.created',
    timestamp: '2026-01-25T10:00:00Z',
    idempotency_key: 'idem_123',
    data: { user_id: 'user_123' }
  };

  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createWebhookDelivery', () => {
    it('should create a new webhook delivery', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        webhook_id: mockWebhookId,
        event_type: mockEventType,
        payload: mockPayload
      };
      
      const result = await createWebhookDelivery(input);
      
      expect(result).toBeDefined();
      expect(result.id).toMatch(/^del_[a-f0-9]{32}$/);
      expect(result.webhook_id).toBe(mockWebhookId);
      expect(result.event_type).toBe(mockEventType);
      expect(result.payload).toEqual(mockPayload);
      expect(result.status).toBe('pending');
      expect(result.attempts).toBe(0);
      expect(result.max_attempts).toBe(DEFAULT_MAX_ATTEMPTS);
      expect(result.created_at).toBeDefined();
      
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should include metadata if provided', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        webhook_id: mockWebhookId,
        event_type: mockEventType,
        payload: mockPayload,
        metadata: {
          realm_id: 'realm_123',
          target_url: 'https://example.com/webhook'
        }
      };
      
      const result = await createWebhookDelivery(input);
      
      expect(result.metadata?.realm_id).toBe('realm_123');
      expect(result.metadata?.target_url).toBe('https://example.com/webhook');
    });
  });

  describe('getWebhookDeliveryById', () => {
    it('should return delivery when found', async () => {
      const mockDelivery = {
        id: mockDeliveryId,
        webhook_id: mockWebhookId,
        event_type: mockEventType,
        payload: mockPayload,
        status: 'success',
        attempts: 1,
        max_attempts: 5,
        response_code: 200,
        response_time_ms: 150,
        created_at: '2026-01-25T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockDelivery]
      });
      
      const result = await getWebhookDeliveryById(mockWebhookId, mockDeliveryId);
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockDeliveryId);
      expect(result?.status).toBe('success');
      expect(result?.response_code).toBe(200);
    });
    
    it('should return null when delivery not found', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getWebhookDeliveryById(mockWebhookId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });

  describe('listWebhookDeliveries', () => {
    it('should return all deliveries for a webhook', async () => {
      const mockDeliveries = [
        {
          id: 'del_1',
          webhook_id: mockWebhookId,
          event_type: 'user.created',
          payload: mockPayload,
          status: 'success',
          attempts: 1,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        },
        {
          id: 'del_2',
          webhook_id: mockWebhookId,
          event_type: 'user.deleted',
          payload: mockPayload,
          status: 'failed',
          attempts: 5,
          max_attempts: 5,
          created_at: '2026-01-26T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockDeliveries
      });
      
      const result = await listWebhookDeliveries(mockWebhookId);
      
      expect(result.deliveries).toHaveLength(2);
      expect(result.deliveries[0].status).toBe('success');
      expect(result.deliveries[1].status).toBe('failed');
    });
    
    it('should filter by status when provided', async () => {
      const mockDeliveries = [
        {
          id: 'del_1',
          webhook_id: mockWebhookId,
          event_type: 'user.created',
          payload: mockPayload,
          status: 'success',
          attempts: 1,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockDeliveries
      });
      
      const result = await listWebhookDeliveries(mockWebhookId, { status: 'success' });
      
      expect(result.deliveries).toHaveLength(1);
      expect(result.deliveries[0].status).toBe('success');
    });
    
    it('should reject invalid status', async () => {
      await expect(
        listWebhookDeliveries(mockWebhookId, { status: 'invalid' as DeliveryStatus })
      ).rejects.toThrow('Invalid delivery status');
    });
    
    it('should return empty array when no deliveries', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await listWebhookDeliveries(mockWebhookId);
      
      expect(result.deliveries).toEqual([]);
    });
    
    it('should handle pagination cursor', async () => {
      const mockDeliveries = [
        {
          id: 'del_1',
          webhook_id: mockWebhookId,
          event_type: 'user.created',
          payload: mockPayload,
          status: 'success',
          attempts: 1,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      const lastKey = { pk: 'WEBHOOK#test#DELIVERY#del_1', sk: 'DELIVERY#2026-01-25T10:00:00Z' };
      
      mockSend.mockResolvedValueOnce({
        Items: mockDeliveries,
        LastEvaluatedKey: lastKey
      });
      
      const result = await listWebhookDeliveries(mockWebhookId, { limit: 1 });
      
      expect(result.deliveries).toHaveLength(1);
      expect(result.nextCursor).toBeDefined();
    });
  });

  describe('getPendingDeliveries', () => {
    it('should return pending and ready-to-retry deliveries', async () => {
      const mockDeliveries = [
        {
          id: 'del_1',
          webhook_id: mockWebhookId,
          event_type: 'user.created',
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        },
        {
          id: 'del_2',
          webhook_id: mockWebhookId,
          event_type: 'user.deleted',
          payload: mockPayload,
          status: 'retrying',
          attempts: 1,
          max_attempts: 5,
          next_retry_at: '2026-01-25T09:00:00Z', // Past time
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockDeliveries
      });
      
      const result = await getPendingDeliveries(mockWebhookId);
      
      expect(result).toHaveLength(2);
    });
    
    it('should return empty array when no pending deliveries', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getPendingDeliveries(mockWebhookId);
      
      expect(result).toEqual([]);
    });
  });

  describe('getRecentDeliveries', () => {
    it('should return recent deliveries', async () => {
      const mockDeliveries = [
        {
          id: 'del_1',
          webhook_id: mockWebhookId,
          event_type: 'user.created',
          payload: mockPayload,
          status: 'success',
          attempts: 1,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockDeliveries
      });
      
      const result = await getRecentDeliveries(mockWebhookId, 10);
      
      expect(result).toHaveLength(1);
    });
  });

  describe('countDeliveriesByStatus', () => {
    it('should count deliveries by status', async () => {
      const mockDeliveries = [
        { id: 'del_1', webhook_id: mockWebhookId, status: 'success', attempts: 1, max_attempts: 5, event_type: 'user.created', payload: mockPayload, created_at: '2026-01-25T10:00:00Z' },
        { id: 'del_2', webhook_id: mockWebhookId, status: 'success', attempts: 1, max_attempts: 5, event_type: 'user.created', payload: mockPayload, created_at: '2026-01-25T10:00:00Z' },
        { id: 'del_3', webhook_id: mockWebhookId, status: 'failed', attempts: 5, max_attempts: 5, event_type: 'user.created', payload: mockPayload, created_at: '2026-01-25T10:00:00Z' },
        { id: 'del_4', webhook_id: mockWebhookId, status: 'pending', attempts: 0, max_attempts: 5, event_type: 'user.created', payload: mockPayload, created_at: '2026-01-25T10:00:00Z' }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockDeliveries
      });
      
      const result = await countDeliveriesByStatus(mockWebhookId);
      
      expect(result.success).toBe(2);
      expect(result.failed).toBe(1);
      expect(result.pending).toBe(1);
      expect(result.retrying).toBe(0);
    });
    
    it('should return zero counts when no deliveries', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await countDeliveriesByStatus(mockWebhookId);
      
      expect(result.success).toBe(0);
      expect(result.failed).toBe(0);
      expect(result.pending).toBe(0);
      expect(result.retrying).toBe(0);
    });
  });

  describe('updateWebhookDelivery', () => {
    it('should update delivery status', async () => {
      // Mock getWebhookDeliveryById
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      // Mock UpdateCommand
      const updatedDelivery = {
        id: mockDeliveryId,
        webhook_id: mockWebhookId,
        event_type: mockEventType,
        payload: mockPayload,
        status: 'success',
        attempts: 1,
        max_attempts: 5,
        response_code: 200,
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-25T10:00:01Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedDelivery
      });
      
      const result = await updateWebhookDelivery(mockWebhookId, mockDeliveryId, {
        status: 'success',
        attempts: 1,
        response_code: 200
      });
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('success');
      expect(result?.response_code).toBe(200);
    });
    
    it('should return null when delivery not found', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await updateWebhookDelivery(mockWebhookId, 'nonexistent', {
        status: 'success'
      });
      
      expect(result).toBeNull();
    });
    
    it('should reject invalid status', async () => {
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      await expect(
        updateWebhookDelivery(mockWebhookId, mockDeliveryId, {
          status: 'invalid' as DeliveryStatus
        })
      ).rejects.toThrow('Invalid delivery status');
    });
  });

  describe('recordDeliveryAttempt', () => {
    it('should record successful delivery attempt', async () => {
      // Mock getWebhookDeliveryById
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      // Mock getWebhookDeliveryById for update
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      // Mock UpdateCommand
      mockSend.mockResolvedValueOnce({
        Attributes: {
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'success',
          attempts: 1,
          max_attempts: 5,
          response_code: 200,
          response_time_ms: 150,
          created_at: '2026-01-25T10:00:00Z',
          completed_at: '2026-01-25T10:00:01Z'
        }
      });
      
      const result = await recordDeliveryAttempt(mockWebhookId, mockDeliveryId, {
        success: true,
        response_code: 200,
        response_time_ms: 150
      });
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('success');
      expect(result?.attempts).toBe(1);
    });
    
    it('should record failed delivery attempt and set retrying status', async () => {
      // Mock getWebhookDeliveryById
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      // Mock getWebhookDeliveryById for update
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      // Mock UpdateCommand
      mockSend.mockResolvedValueOnce({
        Attributes: {
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'retrying',
          attempts: 1,
          max_attempts: 5,
          error: 'Connection timeout',
          next_retry_at: '2026-01-25T10:00:05Z',
          created_at: '2026-01-25T10:00:00Z'
        }
      });
      
      const result = await recordDeliveryAttempt(mockWebhookId, mockDeliveryId, {
        success: false,
        error: 'Connection timeout'
      });
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('retrying');
      expect(result?.error).toBe('Connection timeout');
    });
    
    it('should return null when delivery not found', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await recordDeliveryAttempt(mockWebhookId, 'nonexistent', {
        success: true,
        response_code: 200
      });
      
      expect(result).toBeNull();
    });
  });

  describe('markDeliverySuccess', () => {
    it('should mark delivery as success', async () => {
      // Mock getWebhookDeliveryById (twice - once for recordDeliveryAttempt, once for update)
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'pending',
          attempts: 0,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      // Mock UpdateCommand
      mockSend.mockResolvedValueOnce({
        Attributes: {
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'success',
          attempts: 1,
          max_attempts: 5,
          response_code: 200,
          response_time_ms: 150,
          created_at: '2026-01-25T10:00:00Z',
          completed_at: '2026-01-25T10:00:01Z'
        }
      });
      
      const result = await markDeliverySuccess(mockWebhookId, mockDeliveryId, 200, 150);
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('success');
      expect(result?.response_code).toBe(200);
      expect(result?.response_time_ms).toBe(150);
    });
  });

  describe('markDeliveryFailed', () => {
    it('should mark delivery as failed with error', async () => {
      // Mock getWebhookDeliveryById (twice)
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'retrying',
          attempts: 4,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'retrying',
          attempts: 4,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      // Mock UpdateCommand
      mockSend.mockResolvedValueOnce({
        Attributes: {
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'failed',
          attempts: 5,
          max_attempts: 5,
          error: 'Connection refused',
          response_code: 503,
          created_at: '2026-01-25T10:00:00Z',
          completed_at: '2026-01-25T10:00:01Z'
        }
      });
      
      const result = await markDeliveryFailed(mockWebhookId, mockDeliveryId, 'Connection refused', 503);
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('failed');
      expect(result?.error).toBe('Connection refused');
      expect(result?.response_code).toBe(503);
    });
  });

  describe('deleteWebhookDelivery', () => {
    it('should delete delivery', async () => {
      // Mock getWebhookDeliveryById
      mockSend.mockResolvedValueOnce({
        Items: [{
          id: mockDeliveryId,
          webhook_id: mockWebhookId,
          event_type: mockEventType,
          payload: mockPayload,
          status: 'success',
          attempts: 1,
          max_attempts: 5,
          created_at: '2026-01-25T10:00:00Z'
        }]
      });
      
      // Mock DeleteCommand
      mockSend.mockResolvedValueOnce({});
      
      const result = await deleteWebhookDelivery(mockWebhookId, mockDeliveryId);
      
      expect(result).toBe(true);
    });
    
    it('should return false when delivery not found', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await deleteWebhookDelivery(mockWebhookId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });

  describe('deleteAllWebhookDeliveries', () => {
    it('should delete all deliveries for a webhook', async () => {
      const mockDeliveries = [
        { pk: 'WEBHOOK#test#DELIVERY#del_1', sk: 'DELIVERY#2026-01-25T10:00:00Z', id: 'del_1', webhook_id: mockWebhookId },
        { pk: 'WEBHOOK#test#DELIVERY#del_2', sk: 'DELIVERY#2026-01-26T10:00:00Z', id: 'del_2', webhook_id: mockWebhookId }
      ];
      
      mockSend
        .mockResolvedValueOnce({ Items: mockDeliveries }) // QueryCommand
        .mockResolvedValueOnce({}); // BatchWriteCommand
      
      const result = await deleteAllWebhookDeliveries(mockWebhookId);
      
      expect(result).toBe(2);
    });
    
    it('should return 0 when no deliveries', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await deleteAllWebhookDeliveries(mockWebhookId);
      
      expect(result).toBe(0);
    });
  });

  describe('deleteOldDeliveries', () => {
    it('should delete deliveries older than specified date', async () => {
      const mockDeliveries = [
        { pk: 'WEBHOOK#test#DELIVERY#del_1', sk: 'DELIVERY#2026-01-20T10:00:00Z', id: 'del_1', webhook_id: mockWebhookId },
        { pk: 'WEBHOOK#test#DELIVERY#del_2', sk: 'DELIVERY#2026-01-21T10:00:00Z', id: 'del_2', webhook_id: mockWebhookId }
      ];
      
      mockSend
        .mockResolvedValueOnce({ Items: mockDeliveries }) // QueryCommand
        .mockResolvedValueOnce({}); // BatchWriteCommand
      
      const result = await deleteOldDeliveries(mockWebhookId, '2026-01-25T00:00:00Z');
      
      expect(result).toBe(2);
    });
    
    it('should return 0 when no old deliveries', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await deleteOldDeliveries(mockWebhookId, '2026-01-25T00:00:00Z');
      
      expect(result).toBe(0);
    });
  });

  describe('getDeliveryStats', () => {
    it('should calculate delivery statistics', async () => {
      const mockDeliveries = [
        { id: 'del_1', webhook_id: mockWebhookId, status: 'success', attempts: 1, max_attempts: 5, response_time_ms: 100, event_type: 'user.created', payload: mockPayload, created_at: '2026-01-25T10:00:00Z' },
        { id: 'del_2', webhook_id: mockWebhookId, status: 'success', attempts: 1, max_attempts: 5, response_time_ms: 200, event_type: 'user.created', payload: mockPayload, created_at: '2026-01-25T10:00:00Z' },
        { id: 'del_3', webhook_id: mockWebhookId, status: 'failed', attempts: 5, max_attempts: 5, event_type: 'user.created', payload: mockPayload, created_at: '2026-01-25T10:00:00Z' },
        { id: 'del_4', webhook_id: mockWebhookId, status: 'pending', attempts: 0, max_attempts: 5, event_type: 'user.created', payload: mockPayload, created_at: '2026-01-25T10:00:00Z' }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockDeliveries
      });
      
      const result = await getDeliveryStats(mockWebhookId);
      
      expect(result.total).toBe(4);
      expect(result.success).toBe(2);
      expect(result.failed).toBe(1);
      expect(result.pending).toBe(1);
      expect(result.retrying).toBe(0);
      expect(result.averageResponseTime).toBe(150);
      expect(result.successRate).toBe(67); // 2 success / 3 completed = 66.67%
    });
    
    it('should handle empty deliveries', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getDeliveryStats(mockWebhookId);
      
      expect(result.total).toBe(0);
      expect(result.success).toBe(0);
      expect(result.failed).toBe(0);
      expect(result.pending).toBe(0);
      expect(result.retrying).toBe(0);
      expect(result.averageResponseTime).toBeNull();
      expect(result.successRate).toBe(0);
    });
  });
});
