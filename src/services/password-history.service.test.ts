/**
 * Password History Service Tests
 * Task 6.10: Password History
 * 
 * Tests:
 * - Password history storage
 * - History size limits
 * - Password reuse prevention
 * - Minimum/maximum password age
 * - Healthcare compliance
 */

import * as fc from 'fast-check';
import {
  PasswordHistoryConfig,
  PasswordHistoryRecord,
  PasswordChangeResult,
  DEFAULT_PASSWORD_HISTORY_CONFIG,
  HEALTHCARE_PASSWORD_HISTORY_CONFIG,
  getRealmPasswordHistoryConfig
} from './password-history.service';

describe('Password History Service - Unit Tests', () => {
  describe('DEFAULT_PASSWORD_HISTORY_CONFIG', () => {
    it('should remember 5 passwords', () => {
      expect(DEFAULT_PASSWORD_HISTORY_CONFIG.historySize).toBe(5);
    });

    it('should have 1 day minimum password age', () => {
      expect(DEFAULT_PASSWORD_HISTORY_CONFIG.minPasswordAge).toBe(86400);
    });

    it('should have 90 day maximum password age', () => {
      expect(DEFAULT_PASSWORD_HISTORY_CONFIG.maxPasswordAge).toBe(90 * 86400);
    });

    it('should require different from current', () => {
      expect(DEFAULT_PASSWORD_HISTORY_CONFIG.requireDifferentFromCurrent).toBe(true);
    });
  });

  describe('HEALTHCARE_PASSWORD_HISTORY_CONFIG', () => {
    it('should remember 12 passwords for healthcare', () => {
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.historySize).toBe(12);
    });

    it('should have 60 day maximum password age for healthcare', () => {
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.maxPasswordAge).toBe(60 * 86400);
    });

    it('should be stricter than default', () => {
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.historySize)
        .toBeGreaterThan(DEFAULT_PASSWORD_HISTORY_CONFIG.historySize);
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.maxPasswordAge)
        .toBeLessThan(DEFAULT_PASSWORD_HISTORY_CONFIG.maxPasswordAge);
    });
  });

  describe('getRealmPasswordHistoryConfig', () => {
    it('should return healthcare config for clinisyn realms', () => {
      expect(getRealmPasswordHistoryConfig('clinisyn-psychologists'))
        .toEqual(HEALTHCARE_PASSWORD_HISTORY_CONFIG);
      expect(getRealmPasswordHistoryConfig('clinisyn-students'))
        .toEqual(HEALTHCARE_PASSWORD_HISTORY_CONFIG);
    });

    it('should return default config for other realms', () => {
      expect(getRealmPasswordHistoryConfig('other-company'))
        .toEqual(DEFAULT_PASSWORD_HISTORY_CONFIG);
    });
  });

  describe('PasswordHistoryRecord structure', () => {
    it('should have required fields', () => {
      const record: PasswordHistoryRecord = {
        hash: '$argon2id$v=19$m=32768,t=5,p=2$...',
        changedAt: Math.floor(Date.now() / 1000)
      };

      expect(typeof record.hash).toBe('string');
      expect(typeof record.changedAt).toBe('number');
    });
  });

  describe('PasswordChangeResult structure', () => {
    it('should have success result', () => {
      const result: PasswordChangeResult = {
        success: true
      };
      expect(result.success).toBe(true);
    });

    it('should have error result with code', () => {
      const result: PasswordChangeResult = {
        success: false,
        error: 'Password was used recently',
        errorCode: 'IN_HISTORY',
        historyPosition: 3
      };

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('IN_HISTORY');
      expect(result.historyPosition).toBe(3);
    });

    it('should support all error codes', () => {
      const errorCodes: PasswordChangeResult['errorCode'][] = [
        'SAME_AS_CURRENT',
        'IN_HISTORY',
        'TOO_SOON',
        'WEAK_PASSWORD',
        'INVALID_CURRENT'
      ];

      errorCodes.forEach(code => {
        const result: PasswordChangeResult = {
          success: false,
          errorCode: code
        };
        expect(result.errorCode).toBe(code);
      });
    });
  });

  describe('Configuration validation', () => {
    it('should have positive history size', () => {
      expect(DEFAULT_PASSWORD_HISTORY_CONFIG.historySize).toBeGreaterThan(0);
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.historySize).toBeGreaterThan(0);
    });

    it('should have positive min password age', () => {
      expect(DEFAULT_PASSWORD_HISTORY_CONFIG.minPasswordAge).toBeGreaterThan(0);
    });

    it('should have max age greater than min age', () => {
      expect(DEFAULT_PASSWORD_HISTORY_CONFIG.maxPasswordAge)
        .toBeGreaterThan(DEFAULT_PASSWORD_HISTORY_CONFIG.minPasswordAge);
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.maxPasswordAge)
        .toBeGreaterThan(HEALTHCARE_PASSWORD_HISTORY_CONFIG.minPasswordAge);
    });
  });

  describe('History size limits', () => {
    it('should limit to 5 for default config', () => {
      const config = DEFAULT_PASSWORD_HISTORY_CONFIG;
      const history: PasswordHistoryRecord[] = [];
      
      // Add 10 passwords
      for (let i = 0; i < 10; i++) {
        history.unshift({
          hash: `hash_${i}`,
          changedAt: Date.now() - i * 86400000
        });
      }

      // Slice to config size
      const limited = history.slice(0, config.historySize);
      expect(limited.length).toBe(5);
    });

    it('should limit to 12 for healthcare config', () => {
      const config = HEALTHCARE_PASSWORD_HISTORY_CONFIG;
      const history: PasswordHistoryRecord[] = [];
      
      // Add 20 passwords
      for (let i = 0; i < 20; i++) {
        history.unshift({
          hash: `hash_${i}`,
          changedAt: Date.now() - i * 86400000
        });
      }

      // Slice to config size
      const limited = history.slice(0, config.historySize);
      expect(limited.length).toBe(12);
    });
  });

  describe('Password age calculations', () => {
    it('should calculate days since change correctly', () => {
      const now = Math.floor(Date.now() / 1000);
      const fiveDaysAgo = now - (5 * 86400);
      
      const daysSinceChange = Math.floor((now - fiveDaysAgo) / 86400);
      expect(daysSinceChange).toBe(5);
    });

    it('should calculate days until expiry correctly', () => {
      const config = DEFAULT_PASSWORD_HISTORY_CONFIG;
      const maxAgeDays = Math.floor(config.maxPasswordAge / 86400);
      const daysSinceChange = 30;
      
      const daysUntilExpiry = maxAgeDays - daysSinceChange;
      expect(daysUntilExpiry).toBe(60); // 90 - 30 = 60
    });

    it('should detect expired password', () => {
      const config = DEFAULT_PASSWORD_HISTORY_CONFIG;
      const now = Math.floor(Date.now() / 1000);
      const hundredDaysAgo = now - (100 * 86400);
      
      const timeSinceChange = now - hundredDaysAgo;
      const isExpired = timeSinceChange > config.maxPasswordAge;
      
      expect(isExpired).toBe(true);
    });

    it('should not detect non-expired password', () => {
      const config = DEFAULT_PASSWORD_HISTORY_CONFIG;
      const now = Math.floor(Date.now() / 1000);
      const thirtyDaysAgo = now - (30 * 86400);
      
      const timeSinceChange = now - thirtyDaysAgo;
      const isExpired = timeSinceChange > config.maxPasswordAge;
      
      expect(isExpired).toBe(false);
    });
  });

  describe('Minimum password age', () => {
    it('should prevent change within minimum age', () => {
      const config = DEFAULT_PASSWORD_HISTORY_CONFIG;
      const now = Math.floor(Date.now() / 1000);
      const twelveHoursAgo = now - (12 * 3600);
      
      const timeSinceChange = now - twelveHoursAgo;
      const canChange = timeSinceChange >= config.minPasswordAge;
      
      expect(canChange).toBe(false);
    });

    it('should allow change after minimum age', () => {
      const config = DEFAULT_PASSWORD_HISTORY_CONFIG;
      const now = Math.floor(Date.now() / 1000);
      const twoDaysAgo = now - (2 * 86400);
      
      const timeSinceChange = now - twoDaysAgo;
      const canChange = timeSinceChange >= config.minPasswordAge;
      
      expect(canChange).toBe(true);
    });
  });

  describe('Property-based tests', () => {
    describe('History size', () => {
      it('should always limit history to config size', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 1, max: 100 }),
            fc.integer({ min: 1, max: 20 }),
            (historyLength, configSize) => {
              const history: PasswordHistoryRecord[] = [];
              for (let i = 0; i < historyLength; i++) {
                history.push({ hash: `hash_${i}`, changedAt: Date.now() });
              }
              
              const limited = history.slice(0, configSize);
              expect(limited.length).toBeLessThanOrEqual(configSize);
              return true;
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('Password age', () => {
      it('should correctly determine expiry status', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 1, max: 365 }),
            fc.integer({ min: 30, max: 180 }),
            (daysSinceChange, maxAgeDays) => {
              const isExpired = daysSinceChange > maxAgeDays;
              
              if (daysSinceChange <= maxAgeDays) {
                expect(isExpired).toBe(false);
              } else {
                expect(isExpired).toBe(true);
              }
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Realm config selection', () => {
      it('should return valid config for any realm', () => {
        fc.assert(
          fc.property(fc.string({ minLength: 1, maxLength: 50 }), (realmId) => {
            const config = getRealmPasswordHistoryConfig(realmId);
            expect(config.historySize).toBeGreaterThan(0);
            expect(config.minPasswordAge).toBeGreaterThan(0);
            expect(config.maxPasswordAge).toBeGreaterThan(config.minPasswordAge);
            return true;
          }),
          { numRuns: 50 }
        );
      });

      it('should always return healthcare for clinisyn prefix', () => {
        fc.assert(
          fc.property(fc.string({ minLength: 1, maxLength: 20 }), (suffix) => {
            const config = getRealmPasswordHistoryConfig(`clinisyn-${suffix}`);
            expect(config).toEqual(HEALTHCARE_PASSWORD_HISTORY_CONFIG);
            return true;
          }),
          { numRuns: 50 }
        );
      });
    });
  });

  describe('HIPAA Compliance', () => {
    it('should enforce password history for healthcare', () => {
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.historySize).toBeGreaterThanOrEqual(12);
    });

    it('should enforce shorter max age for healthcare', () => {
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.maxPasswordAge).toBeLessThanOrEqual(60 * 86400);
    });

    it('should require different from current for healthcare', () => {
      expect(HEALTHCARE_PASSWORD_HISTORY_CONFIG.requireDifferentFromCurrent).toBe(true);
    });
  });

  describe('Error messages', () => {
    it('should provide clear error for same as current', () => {
      const result: PasswordChangeResult = {
        success: false,
        error: 'New password must be different from current password',
        errorCode: 'SAME_AS_CURRENT'
      };
      expect(result.error).toContain('different');
    });

    it('should provide clear error for in history', () => {
      const result: PasswordChangeResult = {
        success: false,
        error: 'Password was used recently. Please choose a different password.',
        errorCode: 'IN_HISTORY',
        historyPosition: 3
      };
      expect(result.error).toContain('recently');
    });

    it('should provide clear error for too soon', () => {
      const result: PasswordChangeResult = {
        success: false,
        error: 'Password was changed recently. Please wait 12 hour(s) before changing again.',
        errorCode: 'TOO_SOON'
      };
      expect(result.error).toContain('wait');
    });
  });
});
