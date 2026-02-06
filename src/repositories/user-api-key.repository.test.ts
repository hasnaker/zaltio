/**
 * User API Key Repository Tests
 * Task 2.1: Implement APIKey model and repository
 * 
 * Tests:
 * - Key creation
 * - Key validation
 * - Key listing
 * - Key revocation
 * - Key updates
 * 
 * Validates: Requirements 2.1, 2.2
 */

import {
  createUserAPIKey,
  getUserAPIKeyById,
  validateUserAPIKey,
  listUserAPIKeysByUser,
  revokeUserAPIKey,
  updateUserAPIKey,
  deleteUserAPIKey,
  revokeAllUserAPIKeys,
  hasActiveUserAPIKeys
} from './user-api-key.repository';
import {
  USER_API_KEY_PREFIX,
  USER_API_KEY_LENGTH,
  isValidUserAPIKeyFormat,
  validateUserAPIKeyScopes,
  userAPIKeyScopesAllowed,
  getKeyDisplayPrefix
} from '../models/user-api-key.model';
import { dynamoDb } from '../services/dynamodb.service';

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: any[]) => mockSend(...args)
  }
}));

describe('User API Key Repository', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Model validation functions', () => {
    describe('isValidUserAPIKeyFormat', () => {
      it('should validate correct key format', () => {
        const validKey = 'zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef';
        expect(isValidUserAPIKeyFormat(validKey)).toBe(true);
      });

      it('should reject key with wrong prefix', () => {
        const invalidKey = 'wrong_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef';
        expect(isValidUserAPIKeyFormat(invalidKey)).toBe(false);
      });

      it('should reject key with wrong length', () => {
        const shortKey = 'zalt_key_short';
        expect(isValidUserAPIKeyFormat(shortKey)).toBe(false);
      });

      it('should reject key with special characters', () => {
        const invalidKey = 'zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$';
        expect(isValidUserAPIKeyFormat(invalidKey)).toBe(false);
      });

      it('should accept alphanumeric suffix', () => {
        const validKey = 'zalt_key_0123456789ABCDEFGHIJKLMNOPQRab12';
        expect(isValidUserAPIKeyFormat(validKey)).toBe(true);
      });
    });

    describe('validateUserAPIKeyScopes', () => {
      it('should validate known scopes', () => {
        const result = validateUserAPIKeyScopes(['profile:read', 'sessions:read']);
        expect(result.valid).toBe(true);
        expect(result.invalid).toHaveLength(0);
      });

      it('should reject unknown scopes', () => {
        const result = validateUserAPIKeyScopes(['profile:read', 'unknown:scope']);
        expect(result.valid).toBe(false);
        expect(result.invalid).toContain('unknown:scope');
      });

      it('should validate full:access scope', () => {
        const result = validateUserAPIKeyScopes(['full:access']);
        expect(result.valid).toBe(true);
      });
    });

    describe('userAPIKeyScopesAllowed', () => {
      it('should allow subset of scopes', () => {
        const allowed = ['profile:read', 'profile:write', 'sessions:read'];
        const requested = ['profile:read'];
        expect(userAPIKeyScopesAllowed(requested, allowed)).toBe(true);
      });

      it('should reject scopes not in allowed list', () => {
        const allowed = ['profile:read'];
        const requested = ['profile:read', 'profile:write'];
        expect(userAPIKeyScopesAllowed(requested, allowed)).toBe(false);
      });

      it('should allow all scopes with full:access', () => {
        const allowed = ['full:access'];
        const requested = ['profile:read', 'sessions:revoke', 'tenants:write'];
        expect(userAPIKeyScopesAllowed(requested, allowed)).toBe(true);
      });
    });

    describe('getKeyDisplayPrefix', () => {
      it('should return first 12 chars with ellipsis', () => {
        const fullKey = 'zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef';
        expect(getKeyDisplayPrefix(fullKey)).toBe('zalt_key_ABC...');
      });
    });
  });

  describe('createUserAPIKey', () => {
    it('should create a new API key with default scopes', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await createUserAPIKey({
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'My API Key'
      });

      expect(result.full_key).toMatch(/^zalt_key_[a-zA-Z0-9]{32}$/);
      expect(result.key.name).toBe('My API Key');
      expect(result.key.user_id).toBe('user_123');
      expect(result.key.realm_id).toBe('realm_456');
      expect(result.key.scopes).toContain('full:access');
      expect(result.key.status).toBe('active');
      expect(result.key.usage_count).toBe(0);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });

    it('should create a key with custom scopes', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await createUserAPIKey({
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Limited Key',
        scopes: ['profile:read', 'sessions:read']
      });

      expect(result.key.scopes).toEqual(['profile:read', 'sessions:read']);
    });

    it('should create a key with tenant context', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await createUserAPIKey({
        user_id: 'user_123',
        realm_id: 'realm_456',
        tenant_id: 'tenant_789',
        name: 'Tenant Key'
      });

      expect(result.key.tenant_id).toBe('tenant_789');
    });

    it('should create a key with expiration', async () => {
      mockSend.mockResolvedValueOnce({});
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

      const result = await createUserAPIKey({
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Expiring Key',
        expires_at: expiresAt
      });

      expect(result.key.expires_at).toBe(expiresAt);
    });

    it('should create a key with IP restrictions', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await createUserAPIKey({
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'IP Restricted Key',
        ip_restrictions: ['192.168.1.0/24', '10.0.0.0/8']
      });

      expect(result.key.ip_restrictions).toEqual(['192.168.1.0/24', '10.0.0.0/8']);
    });

    it('should generate unique keys', async () => {
      mockSend.mockResolvedValue({});

      const keys = new Set<string>();
      for (let i = 0; i < 10; i++) {
        const result = await createUserAPIKey({
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: `Key ${i}`
        });
        keys.add(result.full_key);
      }

      expect(keys.size).toBe(10);
    });
  });

  describe('getUserAPIKeyById', () => {
    it('should return key when found', async () => {
      const mockKey = {
        pk: 'USER#user_123#KEY#key_abc',
        sk: 'KEY',
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'active',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      mockSend.mockResolvedValueOnce({ Item: mockKey });

      const result = await getUserAPIKeyById('user_123', 'key_abc');

      expect(result).not.toBeNull();
      expect(result?.id).toBe('key_abc');
      expect(result?.name).toBe('Test Key');
    });

    it('should return null when key not found', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const result = await getUserAPIKeyById('user_123', 'nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('validateUserAPIKey', () => {
    it('should validate active key', async () => {
      const mockKey = {
        pk: 'USER#user_123#KEY#key_abc',
        sk: 'KEY',
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        tenant_id: 'tenant_789',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['profile:read', 'sessions:read'],
        status: 'active',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      mockSend.mockResolvedValueOnce({ Items: [mockKey] });
      mockSend.mockResolvedValueOnce({}); // For usage recording

      const result = await validateUserAPIKey('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');

      expect(result).not.toBeNull();
      expect(result?.user_id).toBe('user_123');
      expect(result?.realm_id).toBe('realm_456');
      expect(result?.tenant_id).toBe('tenant_789');
      expect(result?.scopes).toEqual(['profile:read', 'sessions:read']);
    });

    it('should reject invalid key format', async () => {
      const result = await validateUserAPIKey('invalid_key');

      expect(result).toBeNull();
      expect(mockSend).not.toHaveBeenCalled();
    });

    it('should reject revoked key', async () => {
      const mockKey = {
        pk: 'USER#user_123#KEY#key_abc',
        sk: 'KEY',
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        status: 'revoked',
        scopes: ['full:access']
      };

      mockSend.mockResolvedValueOnce({ Items: [mockKey] });

      const result = await validateUserAPIKey('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');

      expect(result).toBeNull();
    });

    it('should reject expired key', async () => {
      const mockKey = {
        pk: 'USER#user_123#KEY#key_abc',
        sk: 'KEY',
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        status: 'active',
        expires_at: '2020-01-01T00:00:00Z', // Expired
        scopes: ['full:access']
      };

      mockSend.mockResolvedValueOnce({ Items: [mockKey] });

      const result = await validateUserAPIKey('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');

      expect(result).toBeNull();
    });

    it('should return null when key not found', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const result = await validateUserAPIKey('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');

      expect(result).toBeNull();
    });
  });

  describe('listUserAPIKeysByUser', () => {
    it('should return all keys for user', async () => {
      const mockKeys = [
        {
          pk: 'USER#user_123#KEY#key_1',
          sk: 'KEY',
          id: 'key_1',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Key 1',
          key_prefix: 'zalt_key_ABC...',
          key_hash: 'hash1',
          scopes: ['full:access'],
          status: 'active',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 10
        },
        {
          pk: 'USER#user_123#KEY#key_2',
          sk: 'KEY',
          id: 'key_2',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Key 2',
          key_prefix: 'zalt_key_DEF...',
          key_hash: 'hash2',
          scopes: ['profile:read'],
          status: 'revoked',
          created_at: '2026-01-02T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z',
          usage_count: 5
        }
      ];

      mockSend.mockResolvedValueOnce({ Items: mockKeys });

      const result = await listUserAPIKeysByUser('user_123');

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe('Key 1');
      expect(result[1].name).toBe('Key 2');
      // Should not include key_hash in response
      expect((result[0] as any).key_hash).toBeUndefined();
    });

    it('should return empty array when no keys', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const result = await listUserAPIKeysByUser('user_123');

      expect(result).toHaveLength(0);
    });
  });

  describe('revokeUserAPIKey', () => {
    it('should revoke active key', async () => {
      const mockUpdatedKey = {
        pk: 'USER#user_123#KEY#key_abc',
        sk: 'KEY',
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        status: 'revoked',
        revoked_at: '2026-02-01T00:00:00Z',
        revoked_by: 'admin_123'
      };

      mockSend.mockResolvedValueOnce({ Attributes: mockUpdatedKey });

      const result = await revokeUserAPIKey('user_123', 'key_abc', 'admin_123');

      expect(result).not.toBeNull();
      expect(result?.status).toBe('revoked');
      expect(result?.revoked_by).toBe('admin_123');
    });

    it('should return null when key not found', async () => {
      mockSend.mockResolvedValueOnce({ Attributes: undefined });

      const result = await revokeUserAPIKey('user_123', 'nonexistent');

      expect(result).toBeNull();
    });
  });

  describe('updateUserAPIKey', () => {
    it('should update key name', async () => {
      const mockUpdatedKey = {
        pk: 'USER#user_123#KEY#key_abc',
        sk: 'KEY',
        id: 'key_abc',
        name: 'Updated Name',
        updated_at: '2026-02-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Attributes: mockUpdatedKey });

      const result = await updateUserAPIKey('user_123', 'key_abc', { name: 'Updated Name' });

      expect(result).not.toBeNull();
      expect(result?.name).toBe('Updated Name');
    });

    it('should update key scopes', async () => {
      const mockUpdatedKey = {
        pk: 'USER#user_123#KEY#key_abc',
        sk: 'KEY',
        id: 'key_abc',
        scopes: ['profile:read'],
        updated_at: '2026-02-01T00:00:00Z'
      };

      mockSend.mockResolvedValueOnce({ Attributes: mockUpdatedKey });

      const result = await updateUserAPIKey('user_123', 'key_abc', { scopes: ['profile:read'] });

      expect(result).not.toBeNull();
      expect(result?.scopes).toEqual(['profile:read']);
    });
  });

  describe('deleteUserAPIKey', () => {
    it('should delete key successfully', async () => {
      mockSend.mockResolvedValueOnce({});

      const result = await deleteUserAPIKey('user_123', 'key_abc');

      expect(result).toBe(true);
    });

    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('Delete failed'));

      const result = await deleteUserAPIKey('user_123', 'key_abc');

      expect(result).toBe(false);
    });
  });

  describe('revokeAllUserAPIKeys', () => {
    it('should revoke all active keys', async () => {
      const mockKeys = [
        { id: 'key_1', status: 'active' },
        { id: 'key_2', status: 'active' },
        { id: 'key_3', status: 'revoked' }
      ];

      mockSend.mockResolvedValueOnce({ Items: mockKeys }); // listUserAPIKeysByUser
      mockSend.mockResolvedValueOnce({ Attributes: { status: 'revoked' } }); // revoke key_1
      mockSend.mockResolvedValueOnce({ Attributes: { status: 'revoked' } }); // revoke key_2

      const result = await revokeAllUserAPIKeys('user_123', 'admin_123');

      expect(result).toBe(2); // Only 2 active keys revoked
    });
  });

  describe('hasActiveUserAPIKeys', () => {
    it('should return true when user has active keys', async () => {
      const mockKeys = [
        { id: 'key_1', status: 'active' },
        { id: 'key_2', status: 'revoked' }
      ];

      mockSend.mockResolvedValueOnce({ Items: mockKeys });

      const result = await hasActiveUserAPIKeys('user_123');

      expect(result).toBe(true);
    });

    it('should return false when no active keys', async () => {
      const mockKeys = [
        { id: 'key_1', status: 'revoked' },
        { id: 'key_2', status: 'expired' }
      ];

      mockSend.mockResolvedValueOnce({ Items: mockKeys });

      const result = await hasActiveUserAPIKeys('user_123');

      expect(result).toBe(false);
    });
  });
});
