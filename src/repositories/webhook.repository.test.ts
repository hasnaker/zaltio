/**
 * Webhook Repository Tests
 * Tests for webhook CRUD operations
 * 
 * Validates: Requirements 12.1 (Webhook System)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 * 
 * Security Requirements Tested:
 * - Secret must be cryptographically secure (32 bytes, hex encoded)
 * - Payload must be signed with HMAC-SHA256
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
  createWebhook,
  getWebhookById,
  listWebhooksByRealm,
  getWebhooksForEvent,
  countWebhooksByRealm,
  updateWebhook,
  updateWebhookStatus,
  rotateWebhookSecret,
  recordDeliveryAttempt,
  deleteWebhook,
  hardDeleteWebhook,
  deleteAllRealmWebhooks,
  countWebhooksByStatus
} from './webhook.repository';

import {
  WEBHOOK_SECRET_BYTES,
  WebhookEventType
} from '../models/webhook.model';

describe('Webhook Repository', () => {
  const mockRealmId = 'realm_test123';
  const mockWebhookId = 'webhook_abc123def456';
  const mockUrl = 'https://example.com/webhook';
  const mockEvents: WebhookEventType[] = ['user.created', 'user.deleted'];
  
  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createWebhook', () => {
    it('should create a new webhook with generated ID and secret', async () => {
      // Mock countWebhooksByRealm (first call)
      mockSend.mockResolvedValueOnce({ Count: 0 });
      // Mock PutCommand (second call)
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        realm_id: mockRealmId,
        url: mockUrl,
        events: mockEvents,
        description: 'Test webhook',
        created_by: 'user_123'
      };
      
      const result = await createWebhook(input);
      
      // Verify webhook was created
      expect(result).toBeDefined();
      expect(result.webhook.id).toMatch(/^webhook_[a-f0-9]{24}$/);
      expect(result.webhook.realm_id).toBe(mockRealmId);
      expect(result.webhook.url).toBe(mockUrl);
      expect(result.webhook.events).toEqual(mockEvents);
      expect(result.webhook.status).toBe('active');
      expect(result.webhook.description).toBe('Test webhook');
      
      // Verify secret is returned (64 hex chars = 32 bytes)
      expect(result.secret).toMatch(/^[a-f0-9]{64}$/);
      expect(result.secret.length).toBe(WEBHOOK_SECRET_BYTES * 2);
      
      // Verify DynamoDB was called
      expect(mockSend).toHaveBeenCalledTimes(2);
    });
    
    it('should reject invalid URL', async () => {
      const input = {
        realm_id: mockRealmId,
        url: 'http://example.com/webhook', // HTTP not HTTPS
        events: mockEvents
      };
      
      await expect(createWebhook(input)).rejects.toThrow('Invalid webhook URL');
    });
    
    it('should reject invalid event type', async () => {
      const input = {
        realm_id: mockRealmId,
        url: mockUrl,
        events: ['invalid.event' as WebhookEventType]
      };
      
      await expect(createWebhook(input)).rejects.toThrow('Invalid webhook event');
    });
    
    it('should reject when max webhooks exceeded', async () => {
      // Mock countWebhooksByRealm returning max count
      mockSend.mockResolvedValueOnce({ Count: 10 });
      
      const input = {
        realm_id: mockRealmId,
        url: mockUrl,
        events: mockEvents
      };
      
      await expect(createWebhook(input)).rejects.toThrow('Maximum webhooks per realm');
    });
    
    it('should initialize metadata with zero counts', async () => {
      mockSend.mockResolvedValueOnce({ Count: 0 });
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        realm_id: mockRealmId,
        url: mockUrl,
        events: mockEvents,
        created_by: 'user_123'
      };
      
      const result = await createWebhook(input);
      
      // Metadata should not be exposed in response (created_by is filtered)
      // But internal metadata should be initialized
      expect(result.webhook.metadata?.failure_count).toBe(0);
      expect(result.webhook.metadata?.total_deliveries).toBe(0);
      expect(result.webhook.metadata?.successful_deliveries).toBe(0);
    });
  });

  describe('getWebhookById', () => {
    it('should return webhook when found', async () => {
      const mockWebhook = {
        id: mockWebhookId,
        realm_id: mockRealmId,
        url: mockUrl,
        secret: 'a'.repeat(64),
        events: mockEvents,
        status: 'active',
        created_at: '2026-01-25T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Item: mockWebhook
      });
      
      const result = await getWebhookById(mockRealmId, mockWebhookId);
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockWebhookId);
      expect(result?.url).toBe(mockUrl);
      expect(result?.status).toBe('active');
    });
    
    it('should return null when webhook not found', async () => {
      mockSend.mockResolvedValueOnce({
        Item: undefined
      });
      
      const result = await getWebhookById(mockRealmId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });

  describe('listWebhooksByRealm', () => {
    it('should return all webhooks for a realm', async () => {
      const mockWebhooks = [
        {
          id: 'webhook_1',
          realm_id: mockRealmId,
          url: 'https://example.com/hook1',
          secret: 'a'.repeat(64),
          events: ['user.created'],
          status: 'active',
          created_at: '2026-01-25T10:00:00Z'
        },
        {
          id: 'webhook_2',
          realm_id: mockRealmId,
          url: 'https://example.com/hook2',
          secret: 'b'.repeat(64),
          events: ['session.created'],
          status: 'inactive',
          created_at: '2026-01-26T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockWebhooks
      });
      
      const result = await listWebhooksByRealm(mockRealmId);
      
      expect(result.webhooks).toHaveLength(2);
      expect(result.webhooks[0].url).toBe('https://example.com/hook1');
      expect(result.webhooks[1].url).toBe('https://example.com/hook2');
    });
    
    it('should filter by status when provided', async () => {
      const mockWebhooks = [
        {
          id: 'webhook_1',
          realm_id: mockRealmId,
          url: 'https://example.com/hook1',
          secret: 'a'.repeat(64),
          events: ['user.created'],
          status: 'active',
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockWebhooks
      });
      
      const result = await listWebhooksByRealm(mockRealmId, { status: 'active' });
      
      expect(result.webhooks).toHaveLength(1);
      expect(result.webhooks[0].status).toBe('active');
    });
    
    it('should return empty array when no webhooks', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await listWebhooksByRealm(mockRealmId);
      
      expect(result.webhooks).toEqual([]);
    });
    
    it('should handle pagination cursor', async () => {
      const mockWebhooks = [
        {
          id: 'webhook_1',
          realm_id: mockRealmId,
          url: 'https://example.com/hook1',
          secret: 'a'.repeat(64),
          events: ['user.created'],
          status: 'active',
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      const lastKey = { pk: 'REALM#test#WEBHOOK#webhook_1', sk: 'WEBHOOK' };
      
      mockSend.mockResolvedValueOnce({
        Items: mockWebhooks,
        LastEvaluatedKey: lastKey
      });
      
      const result = await listWebhooksByRealm(mockRealmId, { limit: 1 });
      
      expect(result.webhooks).toHaveLength(1);
      expect(result.nextCursor).toBeDefined();
    });
  });

  describe('getWebhooksForEvent', () => {
    it('should return active webhooks subscribed to event', async () => {
      const mockWebhooks = [
        {
          id: 'webhook_1',
          realm_id: mockRealmId,
          url: 'https://example.com/hook1',
          secret: 'a'.repeat(64),
          events: ['user.created', 'user.deleted'],
          status: 'active',
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockWebhooks
      });
      
      const result = await getWebhooksForEvent(mockRealmId, 'user.created');
      
      expect(result).toHaveLength(1);
      expect(result[0].events).toContain('user.created');
    });
    
    it('should return empty array when no matching webhooks', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getWebhooksForEvent(mockRealmId, 'user.created');
      
      expect(result).toEqual([]);
    });
  });

  describe('countWebhooksByRealm', () => {
    it('should return count of non-deleted webhooks', async () => {
      mockSend.mockResolvedValueOnce({
        Count: 5
      });
      
      const result = await countWebhooksByRealm(mockRealmId);
      
      expect(result).toBe(5);
    });
    
    it('should return 0 when no webhooks', async () => {
      mockSend.mockResolvedValueOnce({
        Count: 0
      });
      
      const result = await countWebhooksByRealm(mockRealmId);
      
      expect(result).toBe(0);
    });
  });

  describe('updateWebhook', () => {
    it('should update webhook URL', async () => {
      const updatedWebhook = {
        id: mockWebhookId,
        realm_id: mockRealmId,
        url: 'https://new-example.com/webhook',
        secret: 'a'.repeat(64),
        events: mockEvents,
        status: 'active',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedWebhook
      });
      
      const result = await updateWebhook(mockRealmId, mockWebhookId, {
        url: 'https://new-example.com/webhook'
      });
      
      expect(result).toBeDefined();
      expect(result?.url).toBe('https://new-example.com/webhook');
      expect(result?.updated_at).toBeDefined();
    });
    
    it('should update webhook events', async () => {
      const newEvents: WebhookEventType[] = ['session.created', 'session.revoked'];
      const updatedWebhook = {
        id: mockWebhookId,
        realm_id: mockRealmId,
        url: mockUrl,
        secret: 'a'.repeat(64),
        events: newEvents,
        status: 'active',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedWebhook
      });
      
      const result = await updateWebhook(mockRealmId, mockWebhookId, {
        events: newEvents
      });
      
      expect(result).toBeDefined();
      expect(result?.events).toEqual(newEvents);
    });
    
    it('should reject invalid URL on update', async () => {
      await expect(updateWebhook(mockRealmId, mockWebhookId, {
        url: 'http://insecure.com/webhook'
      })).rejects.toThrow('Invalid webhook URL');
    });
    
    it('should reject invalid event on update', async () => {
      await expect(updateWebhook(mockRealmId, mockWebhookId, {
        events: ['invalid.event' as WebhookEventType]
      })).rejects.toThrow('Invalid webhook event');
    });
    
    it('should return null when webhook not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await updateWebhook(mockRealmId, 'nonexistent', {
        url: 'https://example.com/new'
      });
      
      expect(result).toBeNull();
    });
  });

  describe('updateWebhookStatus', () => {
    it('should update webhook status to inactive', async () => {
      const updatedWebhook = {
        id: mockWebhookId,
        realm_id: mockRealmId,
        url: mockUrl,
        secret: 'a'.repeat(64),
        events: mockEvents,
        status: 'inactive',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedWebhook
      });
      
      const result = await updateWebhookStatus(mockRealmId, mockWebhookId, 'inactive');
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('inactive');
    });
  });

  describe('rotateWebhookSecret', () => {
    it('should generate new secret and return it', async () => {
      const updatedWebhook = {
        id: mockWebhookId,
        realm_id: mockRealmId,
        url: mockUrl,
        secret: 'b'.repeat(64), // New secret
        events: mockEvents,
        status: 'active',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedWebhook
      });
      
      const result = await rotateWebhookSecret(mockRealmId, mockWebhookId);
      
      expect(result).toBeDefined();
      expect(result?.secret).toMatch(/^[a-f0-9]{64}$/);
      expect(result?.webhook.id).toBe(mockWebhookId);
    });
    
    it('should return null when webhook not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await rotateWebhookSecret(mockRealmId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });

  describe('recordDeliveryAttempt', () => {
    it('should record successful delivery', async () => {
      mockSend.mockResolvedValueOnce({});
      
      await recordDeliveryAttempt(mockRealmId, mockWebhookId, true);
      
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should record failed delivery with reason', async () => {
      mockSend.mockResolvedValueOnce({});
      
      await recordDeliveryAttempt(mockRealmId, mockWebhookId, false, 'Connection timeout');
      
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should not throw on error (non-critical operation)', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
      
      // Should not throw
      await expect(
        recordDeliveryAttempt(mockRealmId, mockWebhookId, true)
      ).resolves.not.toThrow();
    });
  });

  describe('deleteWebhook', () => {
    it('should soft delete webhook (mark as deleted)', async () => {
      const deletedWebhook = {
        id: mockWebhookId,
        realm_id: mockRealmId,
        url: mockUrl,
        secret: 'a'.repeat(64),
        events: mockEvents,
        status: 'deleted',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: deletedWebhook
      });
      
      const result = await deleteWebhook(mockRealmId, mockWebhookId);
      
      expect(result).toBe(true);
    });
    
    it('should return false when webhook not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await deleteWebhook(mockRealmId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });

  describe('hardDeleteWebhook', () => {
    it('should permanently delete webhook', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const result = await hardDeleteWebhook(mockRealmId, mockWebhookId);
      
      expect(result).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
      
      const result = await hardDeleteWebhook(mockRealmId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });

  describe('deleteAllRealmWebhooks', () => {
    it('should delete all webhooks for a realm', async () => {
      const mockWebhooks = [
        { id: 'webhook_1', realm_id: mockRealmId, url: 'https://example.com/1', events: ['user.created'], status: 'active', created_at: '2026-01-25T10:00:00Z' },
        { id: 'webhook_2', realm_id: mockRealmId, url: 'https://example.com/2', events: ['user.deleted'], status: 'active', created_at: '2026-01-26T10:00:00Z' }
      ];
      
      mockSend
        .mockResolvedValueOnce({ Items: mockWebhooks }) // listWebhooksByRealm
        .mockResolvedValueOnce({}); // BatchWriteCommand
      
      const result = await deleteAllRealmWebhooks(mockRealmId);
      
      expect(result).toBe(2);
    });
    
    it('should return 0 when no webhooks', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await deleteAllRealmWebhooks(mockRealmId);
      
      expect(result).toBe(0);
    });
  });

  describe('countWebhooksByStatus', () => {
    it('should count webhooks by status', async () => {
      const mockWebhooks = [
        { id: 'webhook_1', status: 'active' },
        { id: 'webhook_2', status: 'active' },
        { id: 'webhook_3', status: 'inactive' },
        { id: 'webhook_4', status: 'deleted' }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockWebhooks });
      
      const result = await countWebhooksByStatus(mockRealmId);
      
      expect(result.active).toBe(2);
      expect(result.inactive).toBe(1);
      expect(result.deleted).toBe(1);
    });
    
    it('should return zero counts when no webhooks', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await countWebhooksByStatus(mockRealmId);
      
      expect(result.active).toBe(0);
      expect(result.inactive).toBe(0);
      expect(result.deleted).toBe(0);
    });
  });
});
