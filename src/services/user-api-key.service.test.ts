/**
 * User API Key Service Tests
 * Task 2.2: Implement APIKeyService
 * 
 * Tests:
 * - Key creation with validation
 * - Key validation and context
 * - Key listing
 * - Key revocation
 * - Key updates
 * 
 * Validates: Requirements 2.3, 2.4, 2.5, 2.6
 */

import { UserAPIKeyService, UserAPIKeyError } from './user-api-key.service';
import * as repository from '../repositories/user-api-key.repository';

// Mock the repository
jest.mock('../repositories/user-api-key.repository');

const mockRepository = repository as jest.Mocked<typeof repository>;

describe('UserAPIKeyService', () => {
  let service: UserAPIKeyService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new UserAPIKeyService();
  });

  describe('createKey', () => {
    it('should create a key with default scopes', async () => {
      const mockResult = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'My API Key',
          key_prefix: 'zalt_key_ABC...',
          scopes: ['full:access'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 0
        },
        full_key: 'zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
      };

      mockRepository.createUserAPIKey.mockResolvedValueOnce(mockResult);

      const result = await service.createKey('user_123', 'realm_456', {
        name: 'My API Key'
      });

      expect(result.full_key).toBe('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');
      expect(result.key.name).toBe('My API Key');
      expect(mockRepository.createUserAPIKey).toHaveBeenCalledWith({
        user_id: 'user_123',
        realm_id: 'realm_456',
        tenant_id: undefined,
        name: 'My API Key',
        description: undefined,
        scopes: undefined,
        expires_at: undefined,
        ip_restrictions: undefined
      });
    });

    it('should create a key with custom scopes', async () => {
      const mockResult = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Limited Key',
          key_prefix: 'zalt_key_ABC...',
          scopes: ['profile:read', 'sessions:read'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 0
        },
        full_key: 'zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
      };

      mockRepository.createUserAPIKey.mockResolvedValueOnce(mockResult);

      const result = await service.createKey('user_123', 'realm_456', {
        name: 'Limited Key',
        scopes: ['profile:read', 'sessions:read']
      });

      expect(result.key.scopes).toEqual(['profile:read', 'sessions:read']);
    });

    it('should reject empty name', async () => {
      await expect(
        service.createKey('user_123', 'realm_456', { name: '' })
      ).rejects.toThrow(UserAPIKeyError);

      await expect(
        service.createKey('user_123', 'realm_456', { name: '   ' })
      ).rejects.toThrow('API key name is required');
    });

    it('should reject name over 100 characters', async () => {
      const longName = 'a'.repeat(101);

      await expect(
        service.createKey('user_123', 'realm_456', { name: longName })
      ).rejects.toThrow('API key name must be 100 characters or less');
    });

    it('should reject invalid scopes', async () => {
      await expect(
        service.createKey('user_123', 'realm_456', {
          name: 'Test Key',
          scopes: ['invalid:scope']
        })
      ).rejects.toThrow('Invalid scopes: invalid:scope');
    });

    it('should reject past expiration date', async () => {
      await expect(
        service.createKey('user_123', 'realm_456', {
          name: 'Test Key',
          expiresAt: '2020-01-01T00:00:00Z'
        })
      ).rejects.toThrow('Expiration date must be in the future');
    });

    it('should reject invalid expiration date format', async () => {
      await expect(
        service.createKey('user_123', 'realm_456', {
          name: 'Test Key',
          expiresAt: 'not-a-date'
        })
      ).rejects.toThrow('Invalid expiration date format');
    });

    it('should create key with tenant context', async () => {
      const mockResult = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          tenant_id: 'tenant_789',
          name: 'Tenant Key',
          key_prefix: 'zalt_key_ABC...',
          scopes: ['full:access'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 0
        },
        full_key: 'zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
      };

      mockRepository.createUserAPIKey.mockResolvedValueOnce(mockResult);

      const result = await service.createKey('user_123', 'realm_456', {
        name: 'Tenant Key',
        tenantId: 'tenant_789'
      });

      expect(result.key.tenant_id).toBe('tenant_789');
    });
  });

  describe('validateKey', () => {
    it('should validate active key and return context', async () => {
      const mockContext = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          tenant_id: 'tenant_789',
          name: 'Test Key',
          key_prefix: 'zalt_key_ABC...',
          key_hash: 'hash123',
          scopes: ['profile:read'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 5
        },
        user_id: 'user_123',
        realm_id: 'realm_456',
        tenant_id: 'tenant_789',
        scopes: ['profile:read']
      };

      mockRepository.validateUserAPIKey.mockResolvedValueOnce(mockContext);

      const result = await service.validateKey('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef');

      expect(result.user_id).toBe('user_123');
      expect(result.realm_id).toBe('realm_456');
      expect(result.scopes).toEqual(['profile:read']);
    });

    it('should reject invalid key format', async () => {
      await expect(
        service.validateKey('invalid_key')
      ).rejects.toThrow(UserAPIKeyError);

      try {
        await service.validateKey('invalid_key');
      } catch (error) {
        expect((error as UserAPIKeyError).code).toBe('INVALID_KEY_FORMAT');
        expect((error as UserAPIKeyError).statusCode).toBe(401);
      }
    });

    it('should reject key not found', async () => {
      mockRepository.validateUserAPIKey.mockResolvedValueOnce(null);

      await expect(
        service.validateKey('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef')
      ).rejects.toThrow('API key not found or revoked');
    });

    it('should reject expired key', async () => {
      const mockContext = {
        key: {
          id: 'key_abc',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Test Key',
          key_prefix: 'zalt_key_ABC...',
          key_hash: 'hash123',
          scopes: ['profile:read'],
          status: 'active' as const,
          expires_at: '2020-01-01T00:00:00Z', // Expired
          created_at: '2019-01-01T00:00:00Z',
          updated_at: '2019-01-01T00:00:00Z',
          usage_count: 5
        },
        user_id: 'user_123',
        realm_id: 'realm_456',
        scopes: ['profile:read']
      };

      mockRepository.validateUserAPIKey.mockResolvedValueOnce(mockContext);

      await expect(
        service.validateKey('zalt_key_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef')
      ).rejects.toThrow('API key has expired');
    });
  });

  describe('listKeys', () => {
    it('should return all keys for user', async () => {
      const mockKeys = [
        {
          id: 'key_1',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Key 1',
          key_prefix: 'zalt_key_ABC...',
          scopes: ['full:access'],
          status: 'active' as const,
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
          usage_count: 10
        },
        {
          id: 'key_2',
          user_id: 'user_123',
          realm_id: 'realm_456',
          name: 'Key 2',
          key_prefix: 'zalt_key_DEF...',
          scopes: ['profile:read'],
          status: 'revoked' as const,
          created_at: '2026-01-02T00:00:00Z',
          updated_at: '2026-01-03T00:00:00Z',
          usage_count: 5
        }
      ];

      mockRepository.listUserAPIKeysByUser.mockResolvedValueOnce(mockKeys);

      const result = await service.listKeys('user_123');

      expect(result).toHaveLength(2);
      expect(result[0].name).toBe('Key 1');
      expect(result[1].name).toBe('Key 2');
    });

    it('should return empty array when no keys', async () => {
      mockRepository.listUserAPIKeysByUser.mockResolvedValueOnce([]);

      const result = await service.listKeys('user_123');

      expect(result).toHaveLength(0);
    });
  });

  describe('revokeKey', () => {
    it('should revoke active key', async () => {
      const mockKey = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'active' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      const mockRevokedKey = {
        ...mockKey,
        status: 'revoked' as const,
        revoked_at: '2026-02-01T00:00:00Z',
        revoked_by: 'user_123'
      };

      mockRepository.getUserAPIKeyById.mockResolvedValueOnce(mockKey);
      mockRepository.revokeUserAPIKey.mockResolvedValueOnce(mockRevokedKey);

      const result = await service.revokeKey('user_123', 'key_abc');

      expect(result.status).toBe('revoked');
    });

    it('should reject key not found', async () => {
      mockRepository.getUserAPIKeyById.mockResolvedValueOnce(null);

      await expect(
        service.revokeKey('user_123', 'nonexistent')
      ).rejects.toThrow('API key not found');
    });

    it('should reject already revoked key', async () => {
      const mockKey = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'revoked' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      mockRepository.getUserAPIKeyById.mockResolvedValueOnce(mockKey);

      await expect(
        service.revokeKey('user_123', 'key_abc')
      ).rejects.toThrow('API key is already revoked');
    });
  });

  describe('updateKey', () => {
    it('should update key name', async () => {
      const mockKey = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Old Name',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'active' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      const mockUpdatedKey = {
        ...mockKey,
        name: 'New Name',
        updated_at: '2026-02-01T00:00:00Z'
      };

      mockRepository.getUserAPIKeyById.mockResolvedValueOnce(mockKey);
      mockRepository.updateUserAPIKey.mockResolvedValueOnce(mockUpdatedKey);

      const result = await service.updateKey('user_123', 'key_abc', { name: 'New Name' });

      expect(result.name).toBe('New Name');
    });

    it('should reject update on inactive key', async () => {
      const mockKey = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'revoked' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      mockRepository.getUserAPIKeyById.mockResolvedValueOnce(mockKey);

      await expect(
        service.updateKey('user_123', 'key_abc', { name: 'New Name' })
      ).rejects.toThrow('Cannot update inactive API key');
    });

    it('should reject empty name update', async () => {
      const mockKey = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'active' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      mockRepository.getUserAPIKeyById.mockResolvedValueOnce(mockKey);

      await expect(
        service.updateKey('user_123', 'key_abc', { name: '' })
      ).rejects.toThrow('API key name cannot be empty');
    });
  });

  describe('revokeAllKeys', () => {
    it('should revoke all active keys', async () => {
      mockRepository.revokeAllUserAPIKeys.mockResolvedValueOnce(3);

      const result = await service.revokeAllKeys('user_123');

      expect(result).toBe(3);
      expect(mockRepository.revokeAllUserAPIKeys).toHaveBeenCalledWith('user_123', undefined);
    });
  });

  describe('hasActiveKeys', () => {
    it('should return true when user has active keys', async () => {
      mockRepository.hasActiveUserAPIKeys.mockResolvedValueOnce(true);

      const result = await service.hasActiveKeys('user_123');

      expect(result).toBe(true);
    });

    it('should return false when no active keys', async () => {
      mockRepository.hasActiveUserAPIKeys.mockResolvedValueOnce(false);

      const result = await service.hasActiveKeys('user_123');

      expect(result).toBe(false);
    });
  });

  describe('checkKeyScope', () => {
    it('should return true when key has required scope', () => {
      const key = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['profile:read', 'sessions:read'],
        status: 'active' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      expect(service.checkKeyScope(key, 'profile:read')).toBe(true);
    });

    it('should return false when key lacks required scope', () => {
      const key = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['profile:read'],
        status: 'active' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      expect(service.checkKeyScope(key, 'sessions:revoke')).toBe(false);
    });

    it('should return true for any scope with full:access', () => {
      const key = {
        id: 'key_abc',
        user_id: 'user_123',
        realm_id: 'realm_456',
        name: 'Test Key',
        key_prefix: 'zalt_key_ABC...',
        key_hash: 'hash123',
        scopes: ['full:access'],
        status: 'active' as const,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        usage_count: 5
      };

      expect(service.checkKeyScope(key, 'profile:read')).toBe(true);
      expect(service.checkKeyScope(key, 'sessions:revoke')).toBe(true);
      expect(service.checkKeyScope(key, 'tenants:write')).toBe(true);
    });
  });
});
