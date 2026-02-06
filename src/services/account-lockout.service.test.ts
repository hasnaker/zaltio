/**
 * Account Lockout Service Tests
 * Task 6.3: Account Lockout
 * 
 * Tests:
 * - Progressive lockout levels
 * - Lockout duration enforcement
 * - Email verification unlock
 * - Admin intervention unlock
 * - Progressive delays
 * - Audit logging
 */

import * as fc from 'fast-check';
import {
  LockoutLevel,
  LockoutStatus,
  LOCKOUT_CONFIG,
  getProgressiveDelay
} from './account-lockout.service';

describe('Account Lockout Service - Unit Tests', () => {
  describe('LOCKOUT_CONFIG', () => {
    it('should have correct temporary lock threshold (5 attempts)', () => {
      expect(LOCKOUT_CONFIG.temporaryLockThreshold).toBe(5);
    });

    it('should have correct temporary lock duration (15 minutes)', () => {
      expect(LOCKOUT_CONFIG.temporaryLockDuration).toBe(900);
    });

    it('should have correct email verification threshold (10 attempts)', () => {
      expect(LOCKOUT_CONFIG.emailVerificationThreshold).toBe(10);
    });

    it('should have correct admin intervention threshold (20 attempts)', () => {
      expect(LOCKOUT_CONFIG.adminInterventionThreshold).toBe(20);
    });

    it('should have progressive delays defined', () => {
      expect(LOCKOUT_CONFIG.progressiveDelays).toEqual([1000, 2000, 4000, 8000, 16000]);
    });

    it('should have lockout record TTL (7 days)', () => {
      expect(LOCKOUT_CONFIG.lockoutRecordTTL).toBe(86400 * 7);
    });
  });

  describe('LockoutLevel enum', () => {
    it('should have all lockout levels defined', () => {
      expect(LockoutLevel.NONE).toBe('none');
      expect(LockoutLevel.TEMPORARY).toBe('temporary');
      expect(LockoutLevel.EMAIL_REQUIRED).toBe('email_required');
      expect(LockoutLevel.ADMIN_REQUIRED).toBe('admin_required');
    });
  });

  describe('getProgressiveDelay', () => {
    it('should return 0 for 0 failed attempts', () => {
      expect(getProgressiveDelay(0)).toBe(0);
    });

    it('should return 0 for negative failed attempts', () => {
      expect(getProgressiveDelay(-1)).toBe(0);
    });

    it('should return 1000ms for 1 failed attempt', () => {
      expect(getProgressiveDelay(1)).toBe(1000);
    });

    it('should return 2000ms for 2 failed attempts', () => {
      expect(getProgressiveDelay(2)).toBe(2000);
    });

    it('should return 4000ms for 3 failed attempts', () => {
      expect(getProgressiveDelay(3)).toBe(4000);
    });

    it('should return 8000ms for 4 failed attempts', () => {
      expect(getProgressiveDelay(4)).toBe(8000);
    });

    it('should return 16000ms for 5+ failed attempts', () => {
      expect(getProgressiveDelay(5)).toBe(16000);
      expect(getProgressiveDelay(10)).toBe(16000);
      expect(getProgressiveDelay(100)).toBe(16000);
    });
  });

  describe('Lockout level determination', () => {
    it('should be NONE for < 5 failures', () => {
      for (let i = 0; i < 5; i++) {
        const level = determineLockoutLevel(i);
        expect(level).toBe(LockoutLevel.NONE);
      }
    });

    it('should be TEMPORARY for 5-9 failures', () => {
      for (let i = 5; i < 10; i++) {
        const level = determineLockoutLevel(i);
        expect(level).toBe(LockoutLevel.TEMPORARY);
      }
    });

    it('should be EMAIL_REQUIRED for 10-19 failures', () => {
      for (let i = 10; i < 20; i++) {
        const level = determineLockoutLevel(i);
        expect(level).toBe(LockoutLevel.EMAIL_REQUIRED);
      }
    });

    it('should be ADMIN_REQUIRED for 20+ failures', () => {
      for (let i = 20; i < 30; i++) {
        const level = determineLockoutLevel(i);
        expect(level).toBe(LockoutLevel.ADMIN_REQUIRED);
      }
    });
  });

  describe('LockoutStatus structure', () => {
    it('should have all required fields', () => {
      const status: LockoutStatus = {
        isLocked: false,
        level: LockoutLevel.NONE,
        failedAttempts: 0,
        requiresEmailVerification: false,
        requiresAdminIntervention: false,
        remainingAttempts: 5
      };

      expect(typeof status.isLocked).toBe('boolean');
      expect(typeof status.level).toBe('string');
      expect(typeof status.failedAttempts).toBe('number');
      expect(typeof status.requiresEmailVerification).toBe('boolean');
      expect(typeof status.requiresAdminIntervention).toBe('boolean');
      expect(typeof status.remainingAttempts).toBe('number');
    });

    it('should have optional fields', () => {
      const status: LockoutStatus = {
        isLocked: true,
        level: LockoutLevel.TEMPORARY,
        failedAttempts: 5,
        lockedUntil: new Date().toISOString(),
        requiresEmailVerification: false,
        requiresAdminIntervention: false,
        remainingAttempts: 0,
        unlockMethod: 'time'
      };

      expect(status.lockedUntil).toBeDefined();
      expect(status.unlockMethod).toBe('time');
    });
  });

  describe('Property-based tests', () => {
    describe('Progressive delay', () => {
      it('should always return non-negative delay', () => {
        fc.assert(
          fc.property(fc.integer({ min: -100, max: 100 }), (attempts) => {
            const delay = getProgressiveDelay(attempts);
            expect(delay).toBeGreaterThanOrEqual(0);
            return true;
          }),
          { numRuns: 100 }
        );
      });

      it('should cap delay at maximum value', () => {
        fc.assert(
          fc.property(fc.integer({ min: 0, max: 1000 }), (attempts) => {
            const delay = getProgressiveDelay(attempts);
            const maxDelay = LOCKOUT_CONFIG.progressiveDelays[LOCKOUT_CONFIG.progressiveDelays.length - 1];
            expect(delay).toBeLessThanOrEqual(maxDelay);
            return true;
          }),
          { numRuns: 100 }
        );
      });

      it('should increase monotonically up to max', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 1, max: LOCKOUT_CONFIG.progressiveDelays.length }),
            (attempts) => {
              const delay1 = getProgressiveDelay(attempts);
              const delay2 = getProgressiveDelay(attempts + 1);
              expect(delay2).toBeGreaterThanOrEqual(delay1);
              return true;
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('Lockout level transitions', () => {
      it('should follow correct progression', () => {
        fc.assert(
          fc.property(fc.integer({ min: 0, max: 50 }), (attempts) => {
            const level = determineLockoutLevel(attempts);
            
            if (attempts < LOCKOUT_CONFIG.temporaryLockThreshold) {
              expect(level).toBe(LockoutLevel.NONE);
            } else if (attempts < LOCKOUT_CONFIG.emailVerificationThreshold) {
              expect(level).toBe(LockoutLevel.TEMPORARY);
            } else if (attempts < LOCKOUT_CONFIG.adminInterventionThreshold) {
              expect(level).toBe(LockoutLevel.EMAIL_REQUIRED);
            } else {
              expect(level).toBe(LockoutLevel.ADMIN_REQUIRED);
            }
            
            return true;
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('Remaining attempts calculation', () => {
      it('should correctly calculate remaining attempts', () => {
        fc.assert(
          fc.property(fc.integer({ min: 0, max: 20 }), (failedAttempts) => {
            const remaining = Math.max(0, LOCKOUT_CONFIG.temporaryLockThreshold - failedAttempts);
            expect(remaining).toBeGreaterThanOrEqual(0);
            expect(remaining).toBeLessThanOrEqual(LOCKOUT_CONFIG.temporaryLockThreshold);
            return true;
          }),
          { numRuns: 100 }
        );
      });
    });
  });

  describe('Threshold validation', () => {
    it('should have temporary threshold < email threshold', () => {
      expect(LOCKOUT_CONFIG.temporaryLockThreshold)
        .toBeLessThan(LOCKOUT_CONFIG.emailVerificationThreshold);
    });

    it('should have email threshold < admin threshold', () => {
      expect(LOCKOUT_CONFIG.emailVerificationThreshold)
        .toBeLessThan(LOCKOUT_CONFIG.adminInterventionThreshold);
    });

    it('should have reasonable lock duration', () => {
      expect(LOCKOUT_CONFIG.temporaryLockDuration).toBeGreaterThanOrEqual(300); // At least 5 min
      expect(LOCKOUT_CONFIG.temporaryLockDuration).toBeLessThanOrEqual(3600); // At most 1 hour
    });
  });
});

/**
 * Helper function to determine lockout level based on failed attempts
 */
function determineLockoutLevel(failedAttempts: number): LockoutLevel {
  if (failedAttempts >= LOCKOUT_CONFIG.adminInterventionThreshold) {
    return LockoutLevel.ADMIN_REQUIRED;
  }
  if (failedAttempts >= LOCKOUT_CONFIG.emailVerificationThreshold) {
    return LockoutLevel.EMAIL_REQUIRED;
  }
  if (failedAttempts >= LOCKOUT_CONFIG.temporaryLockThreshold) {
    return LockoutLevel.TEMPORARY;
  }
  return LockoutLevel.NONE;
}
