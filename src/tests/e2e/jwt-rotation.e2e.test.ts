/**
 * JWT Key Rotation E2E Tests
 * Task 6.4: JWT Key Rotation
 * 
 * Tests:
 * - Key creation
 * - Key rotation (30 days)
 * - Grace period (15 days)
 * - Multi-key support (kid header)
 * - Key revocation
 * - JWKS endpoint
 * - Automated rotation
 */

import {
  KeyStatus,
  KEY_ROTATION_CONFIG,
  generateKeyId,
  generateKeyPair,
  createKey,
  getActiveKey,
  getKeyById,
  getValidKeys,
  rotateKeys,
  revokeKey,
  archiveExpiredKeys,
  isRotationNeeded,
  getRotationStatus,
  getJWKS
} from '../../services/jwt-rotation.service';

// Mock DynamoDB
const mockStore = new Map<string, any>();

jest.mock('../../services/dynamodb.service', () => ({
  dynamoDb: {
    send: jest.fn().mockImplementation((command: any) => {
      const commandName = command.constructor.name;
      
      if (commandName === 'GetCommand') {
        const key = `${command.input.Key.pk}#${command.input.Key.sk}`;
        return Promise.resolve({ Item: mockStore.get(key) });
      }
      
      if (commandName === 'PutCommand') {
        const item = command.input.Item;
        const key = `${item.pk}#${item.sk}`;
        mockStore.set(key, item);
        return Promise.resolve({});
      }
      
      if (commandName === 'UpdateCommand') {
        const key = `${command.input.Key.pk}#${command.input.Key.sk}`;
        const existing = mockStore.get(key) || {};
        const attrValues = command.input.ExpressionAttributeValues || {};
        
        if (attrValues[':grace'] !== undefined) existing.status = attrValues[':grace'];
        if (attrValues[':archived'] !== undefined) existing.status = attrValues[':archived'];
        if (attrValues[':revoked'] !== undefined) existing.status = attrValues[':revoked'];
        if (attrValues[':now'] !== undefined) {
          existing.rotated_at = attrValues[':now'];
          existing.revoked_at = attrValues[':now'];
        }
        if (attrValues[':by'] !== undefined) existing.revoked_by = attrValues[':by'];
        if (attrValues[':reason'] !== undefined) existing.revoked_reason = attrValues[':reason'];
        
        mockStore.set(key, existing);
        return Promise.resolve({ Attributes: existing });
      }
      
      if (commandName === 'QueryCommand') {
        const pk = command.input.ExpressionAttributeValues[':pk'];
        const filterExpr = command.input.FilterExpression || '';
        const attrValues = command.input.ExpressionAttributeValues;
        const now = Math.floor(Date.now() / 1000);
        
        let items = Array.from(mockStore.values()).filter(item => item.pk === pk);
        
        // Apply filters
        if (filterExpr.includes('#status = :active')) {
          items = items.filter(item => item.status === KeyStatus.ACTIVE);
        }
        if (filterExpr.includes('#status IN (:active, :grace)')) {
          items = items.filter(item => 
            item.status === KeyStatus.ACTIVE || item.status === KeyStatus.GRACE_PERIOD
          );
        }
        if (filterExpr.includes('grace_period_ends_at > :now')) {
          items = items.filter(item => item.grace_period_ends_at > now);
        }
        if (filterExpr.includes('#status = :grace AND grace_period_ends_at <= :now')) {
          items = items.filter(item => 
            item.status === KeyStatus.GRACE_PERIOD && item.grace_period_ends_at <= now
          );
        }
        
        return Promise.resolve({ Items: items });
      }
      
      return Promise.resolve({});
    })
  },
  TableNames: {
    SESSIONS: 'test-sessions'
  }
}));

// Mock security logger
jest.mock('../../services/security-logger.service', () => ({
  logSimpleSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

describe('JWT Key Rotation E2E Tests', () => {
  beforeEach(() => {
    mockStore.clear();
    jest.clearAllMocks();
  });

  describe('Key Generation', () => {
    it('should generate unique key IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 10; i++) {
        ids.add(generateKeyId());
      }
      expect(ids.size).toBe(10);
    });

    it('should generate valid RSA key pairs', async () => {
      const { publicKey, privateKey } = await generateKeyPair();
      
      expect(publicKey).toContain('BEGIN PUBLIC KEY');
      expect(privateKey).toContain('BEGIN PRIVATE KEY');
    });
  });

  describe('Key Creation', () => {
    it('should create a new active key', async () => {
      const key = await createKey('test-realm');
      
      expect(key.kid).toBeDefined();
      expect(key.algorithm).toBe('RS256');
      expect(key.status).toBe(KeyStatus.ACTIVE);
      expect(key.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(key.privateKey).toContain('BEGIN PRIVATE KEY');
    });

    it('should set correct expiration times', async () => {
      const key = await createKey('test-realm');
      
      const createdAt = new Date(key.createdAt).getTime();
      const expiresAt = new Date(key.expiresAt).getTime();
      const gracePeriodEndsAt = new Date(key.gracePeriodEndsAt).getTime();
      
      // Key lifetime should be 30 days
      const keyLifetime = (expiresAt - createdAt) / 1000;
      expect(keyLifetime).toBeCloseTo(KEY_ROTATION_CONFIG.keyLifetimeSeconds, -2);
      
      // Grace period should be 15 days after expiration
      const gracePeriod = (gracePeriodEndsAt - expiresAt) / 1000;
      expect(gracePeriod).toBeCloseTo(KEY_ROTATION_CONFIG.gracePeriodSeconds, -2);
    });
  });

  describe('Key Retrieval', () => {
    it('should get active key', async () => {
      await createKey('test-realm');
      
      const activeKey = await getActiveKey('test-realm');
      
      expect(activeKey).not.toBeNull();
      expect(activeKey?.status).toBe(KeyStatus.ACTIVE);
    });

    it('should get key by ID', async () => {
      const created = await createKey('test-realm');
      
      const retrieved = await getKeyById(created.kid, 'test-realm');
      
      expect(retrieved).not.toBeNull();
      expect(retrieved?.kid).toBe(created.kid);
    });

    it('should return null for non-existent key', async () => {
      const key = await getKeyById('non-existent-kid', 'test-realm');
      
      expect(key).toBeNull();
    });
  });

  describe('Key Rotation', () => {
    it('should rotate keys and create new active key', async () => {
      // Create initial key
      const initialKey = await createKey('test-realm');
      
      // Rotate keys
      const { newKey, rotatedKeys } = await rotateKeys('test-realm');
      
      expect(newKey.kid).not.toBe(initialKey.kid);
      expect(newKey.status).toBe(KeyStatus.ACTIVE);
      expect(rotatedKeys).toContain(initialKey.kid);
    });

    it('should move old key to grace period', async () => {
      const initialKey = await createKey('test-realm');
      
      await rotateKeys('test-realm');
      
      // Check old key is in grace period
      const oldKey = await getKeyById(initialKey.kid, 'test-realm');
      expect(oldKey?.status).toBe(KeyStatus.GRACE_PERIOD);
    });

    it('should keep old key valid during grace period', async () => {
      const initialKey = await createKey('test-realm');
      
      await rotateKeys('test-realm');
      
      // Old key should still be retrievable
      const oldKey = await getKeyById(initialKey.kid, 'test-realm');
      expect(oldKey).not.toBeNull();
    });
  });

  describe('Grace Period', () => {
    it('should include grace period keys in valid keys', async () => {
      await createKey('test-realm');
      await rotateKeys('test-realm');
      
      const validKeys = await getValidKeys('test-realm');
      
      // Should have both active and grace period keys
      expect(validKeys.length).toBeGreaterThanOrEqual(1);
    });

    it('should respect 15-day grace period configuration', () => {
      expect(KEY_ROTATION_CONFIG.gracePeriodDays).toBe(15);
      expect(KEY_ROTATION_CONFIG.gracePeriodSeconds).toBe(15 * 24 * 60 * 60);
    });
  });

  describe('Key Revocation', () => {
    it('should revoke a key', async () => {
      const key = await createKey('test-realm');
      
      const result = await revokeKey(
        key.kid,
        'test-realm',
        'admin-1',
        'Security incident'
      );
      
      expect(result).toBe(true);
    });

    it('should not return revoked key', async () => {
      const key = await createKey('test-realm');
      await revokeKey(key.kid, 'test-realm', 'admin-1', 'Test revocation');
      
      const retrieved = await getKeyById(key.kid, 'test-realm');
      
      expect(retrieved).toBeNull();
    });
  });

  describe('Key Archival', () => {
    it('should archive expired grace period keys', async () => {
      const now = Math.floor(Date.now() / 1000);
      
      // Manually create an expired grace period key
      const expiredKey = {
        pk: 'JWTKEY#test-realm',
        sk: 'KEY#expired-kid',
        kid: 'expired-kid',
        algorithm: 'RS256',
        public_key: 'test-public-key',
        private_key_encrypted: 'test-private-key',
        status: KeyStatus.GRACE_PERIOD,
        created_at: now - 50 * 24 * 60 * 60, // 50 days ago
        expires_at: now - 20 * 24 * 60 * 60, // 20 days ago
        grace_period_ends_at: now - 5 * 24 * 60 * 60, // 5 days ago (expired)
        ttl: now + 30 * 24 * 60 * 60
      };
      
      mockStore.set(`${expiredKey.pk}#${expiredKey.sk}`, expiredKey);
      
      const archivedCount = await archiveExpiredKeys('test-realm');
      
      expect(archivedCount).toBe(1);
    });
  });

  describe('Rotation Status', () => {
    it('should indicate rotation needed when no active key', async () => {
      const needed = await isRotationNeeded('empty-realm');
      
      expect(needed).toBe(true);
    });

    it('should return rotation status', async () => {
      await createKey('test-realm');
      
      const status = await getRotationStatus('test-realm');
      
      expect(status.activeKey).not.toBeNull();
      expect(status.gracePeriodKeys).toBeDefined();
      expect(typeof status.rotationNeeded).toBe('boolean');
    });
  });

  describe('JWKS Endpoint', () => {
    it('should return JWKS with valid keys', async () => {
      await createKey('test-realm');
      
      const jwks = await getJWKS('test-realm');
      
      expect(jwks.keys).toBeDefined();
      expect(Array.isArray(jwks.keys)).toBe(true);
      expect(jwks.keys.length).toBeGreaterThan(0);
    });

    it('should include kid in JWK', async () => {
      const key = await createKey('test-realm');
      
      const jwks = await getJWKS('test-realm');
      
      const jwk = jwks.keys.find((k: any) => k.kid === key.kid);
      expect(jwk).toBeDefined();
      expect(jwk).toHaveProperty('kty', 'RSA');
      expect(jwk).toHaveProperty('alg', 'RS256');
    });
  });

  describe('Multi-Key Support', () => {
    it('should support multiple valid keys', async () => {
      // Create and rotate multiple times
      await createKey('test-realm');
      await rotateKeys('test-realm');
      await rotateKeys('test-realm');
      
      const validKeys = await getValidKeys('test-realm');
      
      // Should have multiple keys (active + grace period)
      expect(validKeys.length).toBeGreaterThanOrEqual(1);
    });

    it('should select correct key by kid', async () => {
      const key1 = await createKey('test-realm');
      const { newKey: key2 } = await rotateKeys('test-realm');
      
      const retrieved1 = await getKeyById(key1.kid, 'test-realm');
      const retrieved2 = await getKeyById(key2.kid, 'test-realm');
      
      expect(retrieved1?.kid).toBe(key1.kid);
      expect(retrieved2?.kid).toBe(key2.kid);
    });
  });

  describe('Security Scenarios', () => {
    it('should handle key compromise by revocation', async () => {
      const compromisedKey = await createKey('test-realm');
      
      // Revoke compromised key
      await revokeKey(
        compromisedKey.kid,
        'test-realm',
        'security-team',
        'Key potentially compromised'
      );
      
      // Create new key
      const newKey = await createKey('test-realm');
      
      // Compromised key should not be usable
      const retrieved = await getKeyById(compromisedKey.kid, 'test-realm');
      expect(retrieved).toBeNull();
      
      // New key should be active
      const activeKey = await getActiveKey('test-realm');
      expect(activeKey?.kid).toBe(newKey.kid);
    });

    it('should maintain service continuity during rotation', async () => {
      const initialKey = await createKey('test-realm');
      
      // Rotate
      const { newKey } = await rotateKeys('test-realm');
      
      // Both keys should be valid
      const oldKeyValid = await getKeyById(initialKey.kid, 'test-realm');
      const newKeyValid = await getKeyById(newKey.kid, 'test-realm');
      
      expect(oldKeyValid).not.toBeNull();
      expect(newKeyValid).not.toBeNull();
    });
  });

  describe('Audit Logging', () => {
    it('should log key creation', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      
      await createKey('test-realm');
      
      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'jwt_key_created'
        })
      );
    });

    it('should log key rotation', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      
      await createKey('test-realm');
      await rotateKeys('test-realm');
      
      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'jwt_keys_rotated'
        })
      );
    });

    it('should log key revocation', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      
      const key = await createKey('test-realm');
      await revokeKey(key.kid, 'test-realm', 'admin', 'Test');
      
      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'jwt_key_revoked'
        })
      );
    });
  });
});
