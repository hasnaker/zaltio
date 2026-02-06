/**
 * API Key Repository Tests
 * Tests DynamoDB operations for SDK API keys
 * 
 * Validates: Requirements 4.1, 4.2 (API Key system)
 */

import { getKeyPrefix, isValidKeyFormat, parseKeyPrefix } from '../models/api-key.model';

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  },
  TableNames: {
    API_KEYS: 'zalt-api-keys'
  }
}));

// Import after mocks
import {
  createAPIKey,
  getAPIKeyById,
  validateAPIKey,
  listAPIKeysByCustomer,
  revokeAPIKey,
  recordKeyUsage,
  createDefaultAPIKeys
} from './api-key.repository';

describe('API Key Repository', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createAPIKey', () => {
    it('should create a publishable key with correct prefix', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await createAPIKey({
        customer_id: 'customer_abc123',
        realm_id: 'realm_xyz789',
        type: 'publishable',
        environment: 'live',
        name: 'Test Key'
      });

      expect(result.id).toMatch(/^key_[a-f0-9]{24}$/);
      expect(result.key_prefix).toBe('pk_live_');
      expect(result.full_key).toMatch(/^pk_live_/);
      expect(result.status).toBe('active');
      expect(result.usage_count).toBe(0);
    });

    it('should create a secret key with correct prefix', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await createAPIKey({
        customer_id: 'customer_abc123',
        realm_id: 'realm_xyz789',
        type: 'secret',
        environment: 'live',
        name: 'Test Secret Key'
      });

      expect(result.key_prefix).toBe('sk_live_');
      expect(result.full_key).toMatch(/^sk_live_/);
    });

    it('should create test environment keys', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await createAPIKey({
        customer_id: 'customer_abc123',
        realm_id: 'realm_xyz789',
        type: 'publishable',
        environment: 'test',
        name: 'Test Key'
      });

      expect(result.key_prefix).toBe('pk_test_');
      expect(result.full_key).toMatch(/^pk_test_/);
    });

    it('should return key hint (last 4 chars)', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await createAPIKey({
        customer_id: 'customer_abc123',
        realm_id: 'realm_xyz789',
        type: 'publishable',
        environment: 'live',
        name: 'Test Key'
      });

      expect(result.key_hint).toMatch(/^\.\.\.[a-zA-Z0-9]{4}$/);
    });
  });

  describe('getAPIKeyById', () => {
    it('should return API key when found', async () => {
      const mockKey = {
        pk: 'KEY#key_abc123',
        sk: 'CUSTOMER#customer_xyz',
        id: 'key_abc123',
        customer_id: 'customer_xyz',
        type: 'publishable',
        status: 'active'
      };

      mockSend.mockResolvedValueOnce({ Item: mockKey });

      const key = await getAPIKeyById('key_abc123', 'customer_xyz');

      expect(key).not.toBeNull();
      expect(key?.id).toBe('key_abc123');
      expect(key?.type).toBe('publishable');
    });

    it('should return null when key not found', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const key = await getAPIKeyById('nonexistent', 'customer_xyz');

      expect(key).toBeNull();
    });
  });

  describe('validateAPIKey', () => {
    it('should return null for invalid key format', async () => {
      const key = await validateAPIKey('invalid_key');

      expect(key).toBeNull();
      expect(mockSend).not.toHaveBeenCalled();
    });

    it('should return null for revoked key', async () => {
      const mockKey = {
        pk: 'KEY#key_abc123',
        sk: 'CUSTOMER#customer_xyz',
        id: 'key_abc123',
        status: 'revoked'
      };

      mockSend.mockResolvedValueOnce({ Items: [mockKey] });

      const key = await validateAPIKey('pk_live_mock_key_for_testing_only');

      expect(key).toBeNull();
    });

    it('should return null for expired key', async () => {
      const mockKey = {
        pk: 'KEY#key_abc123',
        sk: 'CUSTOMER#customer_xyz',
        id: 'key_abc123',
        status: 'active',
        expires_at: '2020-01-01T00:00:00Z'  // Past date
      };

      mockSend.mockResolvedValueOnce({ Items: [mockKey] });

      const key = await validateAPIKey('pk_live_mock_key_for_testing_only');

      expect(key).toBeNull();
    });

    it('should return key for valid active key', async () => {
      const mockKey = {
        pk: 'KEY#key_abc123',
        sk: 'CUSTOMER#customer_xyz',
        id: 'key_abc123',
        customer_id: 'customer_xyz',
        status: 'active'
      };

      mockSend.mockResolvedValueOnce({ Items: [mockKey] });
      mockSend.mockResolvedValueOnce({});  // For recordKeyUsage

      const key = await validateAPIKey('pk_live_mock_key_for_testing_only');

      expect(key).not.toBeNull();
      expect(key?.id).toBe('key_abc123');
    });
  });

  describe('listAPIKeysByCustomer', () => {
    it('should return empty array (stub implementation - needs GSI)', async () => {
      // Note: This is a stub implementation that returns empty array
      // Proper implementation needs customer-index GSI in DynamoDB
      const keys = await listAPIKeysByCustomer('cust');

      expect(keys).toHaveLength(0);
    });

    it('should return empty array when no keys', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const keys = await listAPIKeysByCustomer('cust');

      expect(keys).toHaveLength(0);
    });
  });

  describe('revokeAPIKey', () => {
    it('should set status to revoked', async () => {
      const revokedKey = {
        pk: 'KEY#key_abc123',
        sk: 'CUSTOMER#customer_xyz',
        id: 'key_abc123',
        status: 'revoked',
        revoked_at: expect.any(String),
        revoked_by: 'admin_user',
        revoked_reason: 'Security concern'
      };

      mockSend.mockResolvedValueOnce({ Attributes: revokedKey });

      const key = await revokeAPIKey('key_abc123', 'customer_xyz', 'admin_user', 'Security concern');

      expect(key?.status).toBe('revoked');
      expect(key?.revoked_by).toBe('admin_user');
      expect(key?.revoked_reason).toBe('Security concern');
    });
  });

  describe('recordKeyUsage', () => {
    it('should update last_used_at and increment usage_count', async () => {
      mockSend.mockResolvedValueOnce({});

      await recordKeyUsage('key_abc123', 'customer_xyz');

      expect(mockSend).toHaveBeenCalledTimes(1);
      const command = mockSend.mock.calls[0][0];
      expect(command.input.UpdateExpression).toContain('last_used_at');
      expect(command.input.UpdateExpression).toContain('usage_count');
    });
  });

  describe('createDefaultAPIKeys', () => {
    it('should create both publishable and secret keys', async () => {
      mockSend.mockResolvedValue({});

      const { publishableKey, secretKey } = await createDefaultAPIKeys('customer_abc', 'realm_xyz');

      expect(publishableKey.type).toBe('publishable');
      expect(publishableKey.key_prefix).toBe('pk_live_');
      expect(secretKey.type).toBe('secret');
      expect(secretKey.key_prefix).toBe('sk_live_');
    });
  });
});

describe('API Key Model Utilities', () => {
  describe('getKeyPrefix', () => {
    it('should return pk_live_ for publishable live', () => {
      expect(getKeyPrefix('publishable', 'live')).toBe('pk_live_');
    });

    it('should return sk_live_ for secret live', () => {
      expect(getKeyPrefix('secret', 'live')).toBe('sk_live_');
    });

    it('should return pk_test_ for publishable test', () => {
      expect(getKeyPrefix('publishable', 'test')).toBe('pk_test_');
    });

    it('should return sk_test_ for secret test', () => {
      expect(getKeyPrefix('secret', 'test')).toBe('sk_test_');
    });
  });

  describe('isValidKeyFormat', () => {
    it('should return true for valid publishable key', () => {
      expect(isValidKeyFormat('pk_live_mock_key_for_testing_only')).toBe(true);
    });

    it('should return true for valid secret key', () => {
      expect(isValidKeyFormat('sk_live_mock_key_for_testing_only')).toBe(true);
    });

    it('should return true for valid test key', () => {
      expect(isValidKeyFormat('pk_test_mock_key_for_testing_only')).toBe(true);
    });

    it('should return false for invalid prefix', () => {
      expect(isValidKeyFormat('xx_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456')).toBe(false);
    });

    it('should return false for wrong length', () => {
      expect(isValidKeyFormat('pk_live_short')).toBe(false);
    });

    it('should return false for invalid characters', () => {
      expect(isValidKeyFormat('pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ12!@')).toBe(false);
    });
  });

  describe('parseKeyPrefix', () => {
    it('should parse publishable live key', () => {
      const result = parseKeyPrefix('pk_live_xxx');
      expect(result).toEqual({ type: 'publishable', environment: 'live' });
    });

    it('should parse secret test key', () => {
      const result = parseKeyPrefix('sk_test_xxx');
      expect(result).toEqual({ type: 'secret', environment: 'test' });
    });

    it('should return null for invalid key', () => {
      const result = parseKeyPrefix('invalid_key');
      expect(result).toBeNull();
    });
  });
});
