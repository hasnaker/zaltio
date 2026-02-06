/**
 * Account Lockout E2E Tests
 * Task 6.3: Account Lockout
 * 
 * Tests:
 * - 5 failures → 15 min lock
 * - 10 failures → email verification required
 * - 20 failures → admin intervention required
 * - Lock expiration
 * - Email unlock
 * - Admin unlock
 * - Progressive delays
 * - Audit logging
 */

import {
  LockoutLevel,
  LOCKOUT_CONFIG,
  getLockoutStatus,
  recordFailedAttempt,
  recordSuccessfulLogin,
  unlockViaEmail,
  unlockViaAdmin,
  generateUnlockToken,
  getProgressiveDelay,
  canAttemptLogin
} from '../../services/account-lockout.service';

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
        
        // Apply updates based on expression
        if (attrValues[':zero'] !== undefined) existing.failed_attempts = attrValues[':zero'];
        if (attrValues[':none'] !== undefined) existing.lockout_level = attrValues[':none'];
        if (attrValues[':null'] !== undefined) {
          existing.locked_until = null;
          existing.unlock_token = null;
        }
        if (attrValues[':false'] !== undefined) {
          existing.requires_email_verification = false;
          existing.requires_admin_intervention = false;
        }
        if (attrValues[':reduced'] !== undefined) existing.failed_attempts = attrValues[':reduced'];
        if (attrValues[':token'] !== undefined) existing.unlock_token = attrValues[':token'];
        if (attrValues[':expires'] !== undefined) existing.unlock_token_expires = attrValues[':expires'];
        
        mockStore.set(key, existing);
        return Promise.resolve({ Attributes: existing });
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

describe('Account Lockout E2E Tests', () => {
  beforeEach(() => {
    mockStore.clear();
    jest.clearAllMocks();
  });

  describe('Lockout Levels', () => {
    describe('Level 1: Temporary Lock (5 failures)', () => {
      it('should lock account after 5 failed attempts', async () => {
        const realmId = 'test-realm';
        const userId = 'user-1';
        const email = 'user@example.com';
        const ip = '192.168.1.1';
        
        // Record 5 failed attempts
        let status;
        for (let i = 0; i < 5; i++) {
          status = await recordFailedAttempt(realmId, userId, email, ip);
        }
        
        expect(status?.isLocked).toBe(true);
        expect(status?.level).toBe(LockoutLevel.TEMPORARY);
        expect(status?.lockedUntil).toBeDefined();
        expect(status?.unlockMethod).toBe('time');
      });

      it('should not lock before 5 failures', async () => {
        const realmId = 'test-realm';
        const userId = 'user-2';
        const email = 'user2@example.com';
        const ip = '192.168.1.1';
        
        // Record 4 failed attempts
        let status;
        for (let i = 0; i < 4; i++) {
          status = await recordFailedAttempt(realmId, userId, email, ip);
        }
        
        expect(status?.isLocked).toBe(false);
        expect(status?.level).toBe(LockoutLevel.NONE);
        expect(status?.remainingAttempts).toBe(1);
      });

      it('should set 15 minute lock duration', async () => {
        const realmId = 'test-realm';
        const userId = 'user-3';
        const email = 'user3@example.com';
        const ip = '192.168.1.1';
        
        // Record 5 failed attempts
        let status;
        for (let i = 0; i < 5; i++) {
          status = await recordFailedAttempt(realmId, userId, email, ip);
        }
        
        const lockedUntil = new Date(status!.lockedUntil!).getTime();
        const now = Date.now();
        const lockDuration = (lockedUntil - now) / 1000;
        
        // Should be approximately 15 minutes (900 seconds)
        expect(lockDuration).toBeGreaterThan(890);
        expect(lockDuration).toBeLessThanOrEqual(900);
      });
    });

    describe('Level 2: Email Verification Required (10 failures)', () => {
      it('should require email verification after 10 failures', async () => {
        const realmId = 'test-realm';
        const userId = 'user-10';
        const email = 'user10@example.com';
        const ip = '192.168.1.1';
        
        // Record 10 failed attempts
        let status;
        for (let i = 0; i < 10; i++) {
          status = await recordFailedAttempt(realmId, userId, email, ip);
        }
        
        expect(status?.isLocked).toBe(true);
        expect(status?.level).toBe(LockoutLevel.EMAIL_REQUIRED);
        expect(status?.requiresEmailVerification).toBe(true);
        expect(status?.unlockMethod).toBe('email');
      });
    });

    describe('Level 3: Admin Intervention Required (20 failures)', () => {
      it('should require admin intervention after 20 failures', async () => {
        const realmId = 'test-realm';
        const userId = 'user-20';
        const email = 'user20@example.com';
        const ip = '192.168.1.1';
        
        // Record 20 failed attempts
        let status;
        for (let i = 0; i < 20; i++) {
          status = await recordFailedAttempt(realmId, userId, email, ip);
        }
        
        expect(status?.isLocked).toBe(true);
        expect(status?.level).toBe(LockoutLevel.ADMIN_REQUIRED);
        expect(status?.requiresAdminIntervention).toBe(true);
        expect(status?.unlockMethod).toBe('admin');
      });
    });
  });

  describe('Lock Expiration', () => {
    it('should allow login after temporary lock expires', async () => {
      const realmId = 'test-realm';
      const userId = 'user-expire';
      
      // Manually set an expired lock
      const now = Math.floor(Date.now() / 1000);
      mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
        pk: `LOCKOUT#${realmId}`,
        sk: `USER#${userId}`,
        failed_attempts: 5,
        locked_until: now - 100, // Expired 100 seconds ago
        lockout_level: LockoutLevel.TEMPORARY,
        requires_email_verification: false,
        requires_admin_intervention: false
      });
      
      const status = await getLockoutStatus(realmId, userId);
      
      expect(status.isLocked).toBe(false);
      expect(status.level).toBe(LockoutLevel.NONE);
    });
  });

  describe('Unlock Methods', () => {
    describe('Email Unlock', () => {
      it('should unlock account with valid token', async () => {
        const realmId = 'test-realm';
        const userId = 'user-email-unlock';
        const token = 'valid-unlock-token';
        const now = Math.floor(Date.now() / 1000);
        
        // Set up locked account with unlock token
        mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
          pk: `LOCKOUT#${realmId}`,
          sk: `USER#${userId}`,
          failed_attempts: 10,
          lockout_level: LockoutLevel.EMAIL_REQUIRED,
          requires_email_verification: true,
          requires_admin_intervention: false,
          unlock_token: token,
          unlock_token_expires: now + 3600
        });
        
        const result = await unlockViaEmail(realmId, userId, token);
        
        expect(result.success).toBe(true);
      });

      it('should reject invalid token', async () => {
        const realmId = 'test-realm';
        const userId = 'user-invalid-token';
        const now = Math.floor(Date.now() / 1000);
        
        mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
          pk: `LOCKOUT#${realmId}`,
          sk: `USER#${userId}`,
          failed_attempts: 10,
          lockout_level: LockoutLevel.EMAIL_REQUIRED,
          requires_email_verification: true,
          requires_admin_intervention: false,
          unlock_token: 'correct-token',
          unlock_token_expires: now + 3600
        });
        
        const result = await unlockViaEmail(realmId, userId, 'wrong-token');
        
        expect(result.success).toBe(false);
        expect(result.message).toContain('Invalid');
      });

      it('should reject expired token', async () => {
        const realmId = 'test-realm';
        const userId = 'user-expired-token';
        const token = 'expired-token';
        const now = Math.floor(Date.now() / 1000);
        
        mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
          pk: `LOCKOUT#${realmId}`,
          sk: `USER#${userId}`,
          failed_attempts: 10,
          lockout_level: LockoutLevel.EMAIL_REQUIRED,
          requires_email_verification: true,
          requires_admin_intervention: false,
          unlock_token: token,
          unlock_token_expires: now - 100 // Expired
        });
        
        const result = await unlockViaEmail(realmId, userId, token);
        
        expect(result.success).toBe(false);
        expect(result.message).toContain('expired');
      });

      it('should not allow email unlock for admin-required level', async () => {
        const realmId = 'test-realm';
        const userId = 'user-admin-required';
        const token = 'some-token';
        const now = Math.floor(Date.now() / 1000);
        
        mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
          pk: `LOCKOUT#${realmId}`,
          sk: `USER#${userId}`,
          failed_attempts: 20,
          lockout_level: LockoutLevel.ADMIN_REQUIRED,
          requires_email_verification: true,
          requires_admin_intervention: true,
          unlock_token: token,
          unlock_token_expires: now + 3600
        });
        
        const result = await unlockViaEmail(realmId, userId, token);
        
        expect(result.success).toBe(false);
        expect(result.message).toContain('Admin');
      });
    });

    describe('Admin Unlock', () => {
      it('should unlock account via admin', async () => {
        const realmId = 'test-realm';
        const userId = 'user-admin-unlock';
        const adminId = 'admin-1';
        
        mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
          pk: `LOCKOUT#${realmId}`,
          sk: `USER#${userId}`,
          failed_attempts: 20,
          lockout_level: LockoutLevel.ADMIN_REQUIRED,
          requires_email_verification: true,
          requires_admin_intervention: true
        });
        
        const result = await unlockViaAdmin(realmId, userId, adminId, 'User verified identity');
        
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Successful Login Reset', () => {
    it('should reset lockout status on successful login', async () => {
      const realmId = 'test-realm';
      const userId = 'user-success';
      
      // Set up some failed attempts
      mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
        pk: `LOCKOUT#${realmId}`,
        sk: `USER#${userId}`,
        failed_attempts: 3,
        lockout_level: LockoutLevel.NONE,
        requires_email_verification: false,
        requires_admin_intervention: false
      });
      
      await recordSuccessfulLogin(realmId, userId);
      
      const status = await getLockoutStatus(realmId, userId);
      
      expect(status.failedAttempts).toBe(0);
      expect(status.isLocked).toBe(false);
    });
  });

  describe('Progressive Delays', () => {
    it('should return correct delays for each attempt', () => {
      expect(getProgressiveDelay(0)).toBe(0);
      expect(getProgressiveDelay(1)).toBe(1000);
      expect(getProgressiveDelay(2)).toBe(2000);
      expect(getProgressiveDelay(3)).toBe(4000);
      expect(getProgressiveDelay(4)).toBe(8000);
      expect(getProgressiveDelay(5)).toBe(16000);
    });

    it('should cap delay at maximum', () => {
      expect(getProgressiveDelay(10)).toBe(16000);
      expect(getProgressiveDelay(100)).toBe(16000);
    });
  });

  describe('Can Attempt Login', () => {
    it('should allow login for unlocked account', async () => {
      const realmId = 'test-realm';
      const userId = 'user-can-login';
      
      const result = await canAttemptLogin(realmId, userId);
      
      expect(result.allowed).toBe(true);
    });

    it('should deny login for temporarily locked account', async () => {
      const realmId = 'test-realm';
      const userId = 'user-temp-locked';
      const now = Math.floor(Date.now() / 1000);
      
      mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
        pk: `LOCKOUT#${realmId}`,
        sk: `USER#${userId}`,
        failed_attempts: 5,
        locked_until: now + 900,
        lockout_level: LockoutLevel.TEMPORARY,
        requires_email_verification: false,
        requires_admin_intervention: false
      });
      
      const result = await canAttemptLogin(realmId, userId);
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('temporarily locked');
    });

    it('should deny login for email-required account', async () => {
      const realmId = 'test-realm';
      const userId = 'user-email-required';
      
      mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
        pk: `LOCKOUT#${realmId}`,
        sk: `USER#${userId}`,
        failed_attempts: 10,
        lockout_level: LockoutLevel.EMAIL_REQUIRED,
        requires_email_verification: true,
        requires_admin_intervention: false
      });
      
      const result = await canAttemptLogin(realmId, userId);
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('email');
    });

    it('should deny login for admin-required account', async () => {
      const realmId = 'test-realm';
      const userId = 'user-admin-required-2';
      
      mockStore.set(`LOCKOUT#${realmId}#USER#${userId}`, {
        pk: `LOCKOUT#${realmId}`,
        sk: `USER#${userId}`,
        failed_attempts: 20,
        lockout_level: LockoutLevel.ADMIN_REQUIRED,
        requires_email_verification: true,
        requires_admin_intervention: true
      });
      
      const result = await canAttemptLogin(realmId, userId);
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('administrator');
    });
  });

  describe('Security Scenarios', () => {
    it('should handle brute force attack progression', async () => {
      const realmId = 'clinisyn-psychologists';
      const userId = 'dr-smith';
      const email = 'dr.smith@clinic.com';
      const attackerIp = '203.0.113.1';
      
      // Simulate brute force attack
      const statuses = [];
      for (let i = 0; i < 25; i++) {
        const status = await recordFailedAttempt(realmId, userId, email, attackerIp);
        statuses.push(status);
      }
      
      // Check progression
      expect(statuses[4].level).toBe(LockoutLevel.TEMPORARY); // 5th attempt
      expect(statuses[9].level).toBe(LockoutLevel.EMAIL_REQUIRED); // 10th attempt
      expect(statuses[19].level).toBe(LockoutLevel.ADMIN_REQUIRED); // 20th attempt
    });

    it('should protect healthcare accounts with strict lockout', async () => {
      const realmId = 'clinisyn-psychologists';
      const userId = 'healthcare-user';
      const email = 'doctor@hospital.com';
      const ip = '192.168.1.1';
      
      // 5 failed attempts should lock
      for (let i = 0; i < 5; i++) {
        await recordFailedAttempt(realmId, userId, email, ip);
      }
      
      const canLogin = await canAttemptLogin(realmId, userId);
      
      expect(canLogin.allowed).toBe(false);
      expect(canLogin.status.isLocked).toBe(true);
    });
  });

  describe('Audit Logging', () => {
    it('should log lockout events', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      
      const realmId = 'test-realm';
      const userId = 'audit-user';
      const email = 'audit@example.com';
      const ip = '192.168.1.1';
      
      // Trigger lockout
      for (let i = 0; i < 5; i++) {
        await recordFailedAttempt(realmId, userId, email, ip);
      }
      
      expect(logSimpleSecurityEvent).toHaveBeenCalled();
    });
  });
});
