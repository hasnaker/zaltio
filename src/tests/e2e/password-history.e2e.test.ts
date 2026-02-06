/**
 * Password History E2E Tests
 * Task 6.10: Password History
 * 
 * Tests:
 * - Password history storage and retrieval
 * - Password reuse prevention
 * - History size limits
 * - Minimum/maximum password age
 * - Healthcare compliance
 */

import {
  getPasswordHistory,
  isPasswordInHistory,
  isCurrentPassword,
  canChangePassword,
  isPasswordExpired,
  validateNewPassword,
  addPasswordToHistory,
  clearPasswordHistory,
  getRealmPasswordHistoryConfig,
  getPasswordAgeInfo,
  DEFAULT_PASSWORD_HISTORY_CONFIG,
  HEALTHCARE_PASSWORD_HISTORY_CONFIG,
  PasswordHistoryRecord
} from '../../services/password-history.service';
import * as crypto from 'crypto';

// Generate unique ID
function generateId(): string {
  return crypto.randomUUID();
}

// Mock password utilities
jest.mock('../../utils/password', () => ({
  hashPassword: jest.fn().mockImplementation((password: string) => 
    Promise.resolve(`$argon2id$hash_of_${password}`)
  ),
  verifyPassword: jest.fn().mockImplementation((password: string, hash: string) => 
    Promise.resolve(hash === `$argon2id$hash_of_${password}`)
  )
}));

// Mock DynamoDB
const mockUsers = new Map<string, any>();

jest.mock('../../services/dynamodb.service', () => ({
  dynamoDb: {
    send: jest.fn().mockImplementation((command: any) => {
      const commandName = command.constructor.name;
      
      if (commandName === 'GetCommand') {
        const key = `${command.input.Key.pk}#${command.input.Key.sk}`;
        const item = mockUsers.get(key);
        return Promise.resolve({ Item: item });
      }
      
      if (commandName === 'UpdateCommand') {
        const key = `${command.input.Key.pk}#${command.input.Key.sk}`;
        let item = mockUsers.get(key) || {};
        
        // Parse update expression
        const values = command.input.ExpressionAttributeValues;
        if (values[':history']) item.password_history = values[':history'];
        if (values[':now']) item.password_changed_at = values[':now'];
        if (values[':empty']) item.password_history = values[':empty'];
        
        mockUsers.set(key, item);
        return Promise.resolve({});
      }
      
      return Promise.resolve({});
    })
  },
  TableNames: {
    USERS: 'zalt-users'
  }
}));

// Mock security logger
jest.mock('../../services/security-logger.service', () => ({
  logSimpleSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

describe('Password History E2E Tests', () => {
  const testRealmId = 'clinisyn-psychologists';
  
  beforeEach(() => {
    jest.clearAllMocks();
    mockUsers.clear();
  });

  describe('Password History Storage', () => {
    it('should store password in history', async () => {
      const userId = generateId();
      const passwordHash = '$argon2id$hash_of_password1';
      
      await addPasswordToHistory(userId, testRealmId, passwordHash);
      
      const history = await getPasswordHistory(userId, testRealmId);
      expect(history.length).toBe(1);
      expect(history[0].hash).toBe(passwordHash);
    });

    it('should store multiple passwords in order', async () => {
      const userId = generateId();
      
      await addPasswordToHistory(userId, testRealmId, '$argon2id$hash_of_password1');
      await addPasswordToHistory(userId, testRealmId, '$argon2id$hash_of_password2');
      await addPasswordToHistory(userId, testRealmId, '$argon2id$hash_of_password3');
      
      const history = await getPasswordHistory(userId, testRealmId);
      expect(history.length).toBe(3);
      // Most recent first
      expect(history[0].hash).toBe('$argon2id$hash_of_password3');
    });

    it('should limit history to config size', async () => {
      const userId = generateId();
      const config = DEFAULT_PASSWORD_HISTORY_CONFIG;
      
      // Add more than history size
      for (let i = 0; i < 10; i++) {
        await addPasswordToHistory(userId, testRealmId, `$argon2id$hash_of_password${i}`, config);
      }
      
      const history = await getPasswordHistory(userId, testRealmId);
      expect(history.length).toBeLessThanOrEqual(config.historySize);
    });

    it('should include timestamp for each entry', async () => {
      const userId = generateId();
      const before = Math.floor(Date.now() / 1000);
      
      await addPasswordToHistory(userId, testRealmId, '$argon2id$hash');
      
      const history = await getPasswordHistory(userId, testRealmId);
      expect(history[0].changedAt).toBeGreaterThanOrEqual(before);
    });
  });

  describe('Password Reuse Prevention', () => {
    it('should detect password in history', async () => {
      const userId = generateId();
      
      // Setup user with password history
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_history: [
          { hash: '$argon2id$hash_of_oldpassword1', changedAt: Date.now() - 86400000 },
          { hash: '$argon2id$hash_of_oldpassword2', changedAt: Date.now() - 172800000 }
        ]
      });
      
      const result = await isPasswordInHistory('oldpassword1', userId, testRealmId);
      expect(result.inHistory).toBe(true);
      expect(result.position).toBe(1);
    });

    it('should allow new password not in history', async () => {
      const userId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_history: [
          { hash: '$argon2id$hash_of_oldpassword1', changedAt: Date.now() }
        ]
      });
      
      const result = await isPasswordInHistory('newpassword', userId, testRealmId);
      expect(result.inHistory).toBe(false);
    });

    it('should check all passwords in history', async () => {
      const userId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_history: [
          { hash: '$argon2id$hash_of_password1', changedAt: Date.now() },
          { hash: '$argon2id$hash_of_password2', changedAt: Date.now() },
          { hash: '$argon2id$hash_of_password3', changedAt: Date.now() },
          { hash: '$argon2id$hash_of_password4', changedAt: Date.now() },
          { hash: '$argon2id$hash_of_password5', changedAt: Date.now() }
        ]
      });
      
      // Check last password in history
      const result = await isPasswordInHistory('password5', userId, testRealmId);
      expect(result.inHistory).toBe(true);
      expect(result.position).toBe(5);
    });
  });

  describe('Current Password Check', () => {
    it('should detect current password', async () => {
      const userId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_hash: '$argon2id$hash_of_currentpassword'
      });
      
      const isCurrent = await isCurrentPassword('currentpassword', userId, testRealmId);
      expect(isCurrent).toBe(true);
    });

    it('should reject non-current password', async () => {
      const userId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_hash: '$argon2id$hash_of_currentpassword'
      });
      
      const isCurrent = await isCurrentPassword('wrongpassword', userId, testRealmId);
      expect(isCurrent).toBe(false);
    });
  });

  describe('Minimum Password Age', () => {
    it('should prevent change within minimum age', async () => {
      const userId = generateId();
      const now = Math.floor(Date.now() / 1000);
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_changed_at: now - 3600 // 1 hour ago
      });
      
      const result = await canChangePassword(userId, testRealmId);
      expect(result.allowed).toBe(false);
      expect(result.waitSeconds).toBeGreaterThan(0);
    });

    it('should allow change after minimum age', async () => {
      const userId = generateId();
      const now = Math.floor(Date.now() / 1000);
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_changed_at: now - (2 * 86400) // 2 days ago
      });
      
      const result = await canChangePassword(userId, testRealmId);
      expect(result.allowed).toBe(true);
    });

    it('should allow first password change', async () => {
      const userId = generateId();
      
      // No password_changed_at set
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {});
      
      const result = await canChangePassword(userId, testRealmId);
      expect(result.allowed).toBe(true);
    });
  });

  describe('Maximum Password Age', () => {
    it('should detect expired password', async () => {
      const userId = generateId();
      const now = Math.floor(Date.now() / 1000);
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_changed_at: now - (100 * 86400) // 100 days ago
      });
      
      const result = await isPasswordExpired(userId, testRealmId);
      expect(result.expired).toBe(true);
      expect(result.daysOverdue).toBeGreaterThan(0);
    });

    it('should not flag non-expired password', async () => {
      const userId = generateId();
      const now = Math.floor(Date.now() / 1000);
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_changed_at: now - (30 * 86400) // 30 days ago
      });
      
      const result = await isPasswordExpired(userId, testRealmId);
      expect(result.expired).toBe(false);
    });
  });

  describe('Password Validation', () => {
    it('should reject same as current password', async () => {
      const userId = generateId();
      
      const result = await validateNewPassword(
        'samepassword',
        'samepassword',
        userId,
        testRealmId
      );
      
      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('SAME_AS_CURRENT');
    });

    it('should reject password in history', async () => {
      const userId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_history: [
          { hash: '$argon2id$hash_of_oldpassword', changedAt: Date.now() }
        ],
        password_changed_at: Math.floor(Date.now() / 1000) - (2 * 86400)
      });
      
      const result = await validateNewPassword(
        'oldpassword',
        'currentpassword',
        userId,
        testRealmId
      );
      
      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('IN_HISTORY');
    });

    it('should accept valid new password', async () => {
      const userId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_history: [],
        password_changed_at: Math.floor(Date.now() / 1000) - (2 * 86400)
      });
      
      const result = await validateNewPassword(
        'newpassword',
        'currentpassword',
        userId,
        testRealmId
      );
      
      expect(result.success).toBe(true);
    });
  });

  describe('Clear Password History', () => {
    it('should clear password history', async () => {
      const userId = generateId();
      const adminId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_history: [
          { hash: '$argon2id$hash1', changedAt: Date.now() },
          { hash: '$argon2id$hash2', changedAt: Date.now() }
        ]
      });
      
      await clearPasswordHistory(userId, testRealmId, adminId);
      
      const history = await getPasswordHistory(userId, testRealmId);
      expect(history).toEqual([]);
    });

    it('should log security event on clear', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      const userId = generateId();
      const adminId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_history: []
      });
      
      await clearPasswordHistory(userId, testRealmId, adminId);
      
      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'password_history_cleared',
          details: expect.objectContaining({
            cleared_by: adminId
          })
        })
      );
    });
  });

  describe('Password Age Info', () => {
    it('should return password age info', async () => {
      const userId = generateId();
      const now = Math.floor(Date.now() / 1000);
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_changed_at: now - (30 * 86400) // 30 days ago
      });
      
      const info = await getPasswordAgeInfo(userId, testRealmId);
      
      expect(info.daysSinceChange).toBe(30);
      expect(info.isExpired).toBe(false);
      expect(info.lastChanged).toBeDefined();
    });

    it('should indicate expired password', async () => {
      const userId = generateId();
      const now = Math.floor(Date.now() / 1000);
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {
        password_changed_at: now - (100 * 86400) // 100 days ago
      });
      
      const info = await getPasswordAgeInfo(userId, testRealmId);
      
      expect(info.isExpired).toBe(true);
      expect(info.mustChangeImmediately).toBe(true);
    });

    it('should handle no previous password change', async () => {
      const userId = generateId();
      
      mockUsers.set(`REALM#${testRealmId}#USER#${userId}`, {});
      
      const info = await getPasswordAgeInfo(userId, testRealmId);
      
      expect(info.lastChanged).toBeNull();
      expect(info.isExpired).toBe(false);
    });
  });

  describe('Realm Configuration', () => {
    it('should use healthcare config for clinisyn', () => {
      const config = getRealmPasswordHistoryConfig('clinisyn-psychologists');
      expect(config.historySize).toBe(12);
      expect(config.maxPasswordAge).toBe(60 * 86400);
    });

    it('should use default config for other realms', () => {
      const config = getRealmPasswordHistoryConfig('other-company');
      expect(config.historySize).toBe(5);
      expect(config.maxPasswordAge).toBe(90 * 86400);
    });
  });

  describe('Healthcare Compliance', () => {
    it('should enforce stricter history for healthcare', async () => {
      const config = HEALTHCARE_PASSWORD_HISTORY_CONFIG;
      expect(config.historySize).toBeGreaterThanOrEqual(12);
    });

    it('should enforce shorter max age for healthcare', async () => {
      const config = HEALTHCARE_PASSWORD_HISTORY_CONFIG;
      expect(config.maxPasswordAge).toBeLessThanOrEqual(60 * 86400);
    });
  });

  describe('Audit Logging', () => {
    it('should log password history update', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      const userId = generateId();
      
      await addPasswordToHistory(userId, testRealmId, '$argon2id$hash');
      
      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'password_history_updated',
          user_id: userId,
          realm_id: testRealmId
        })
      );
    });
  });
});
