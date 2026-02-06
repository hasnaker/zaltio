/**
 * Session Timeout Service Tests
 * Task 6.6: Session Timeout Policies
 * 
 * HEALTHCARE CRITICAL:
 * - Idle timeout: 30 minutes inactivity → logout
 * - Absolute timeout: 8-12 hours → forced logout
 * - Activity tracking: Every API call updates last_activity
 * - Realm-based configuration
 */

import * as fc from 'fast-check';
import {
  SessionTimeoutConfig,
  SessionStatus,
  TIMEOUT_CONFIGS,
  DEFAULT_HEALTHCARE_TIMEOUT,
  getRealmTimeoutConfig,
  needsTimeoutWarning,
  getTimeoutInfo
} from './session-timeout.service';

describe('Session Timeout Service - Unit Tests', () => {
  describe('TIMEOUT_CONFIGS', () => {
    describe('Healthcare config', () => {
      it('should have 30 minute idle timeout', () => {
        expect(TIMEOUT_CONFIGS.healthcare.idleTimeoutSeconds).toBe(1800);
      });

      it('should have 8 hour absolute timeout', () => {
        expect(TIMEOUT_CONFIGS.healthcare.absoluteTimeoutSeconds).toBe(28800);
      });

      it('should have 5 minute warning', () => {
        expect(TIMEOUT_CONFIGS.healthcare.warningBeforeTimeoutSeconds).toBe(300);
      });

      it('should have activity tracking enabled', () => {
        expect(TIMEOUT_CONFIGS.healthcare.activityTrackingEnabled).toBe(true);
      });

      it('should extend on activity', () => {
        expect(TIMEOUT_CONFIGS.healthcare.extendOnActivity).toBe(true);
      });
    });

    describe('Standard config', () => {
      it('should have 1 hour idle timeout', () => {
        expect(TIMEOUT_CONFIGS.standard.idleTimeoutSeconds).toBe(3600);
      });

      it('should have 12 hour absolute timeout', () => {
        expect(TIMEOUT_CONFIGS.standard.absoluteTimeoutSeconds).toBe(43200);
      });
    });

    describe('Extended config', () => {
      it('should have 2 hour idle timeout', () => {
        expect(TIMEOUT_CONFIGS.extended.idleTimeoutSeconds).toBe(7200);
      });

      it('should have 24 hour absolute timeout', () => {
        expect(TIMEOUT_CONFIGS.extended.absoluteTimeoutSeconds).toBe(86400);
      });
    });
  });

  describe('DEFAULT_HEALTHCARE_TIMEOUT', () => {
    it('should be healthcare config', () => {
      expect(DEFAULT_HEALTHCARE_TIMEOUT).toEqual(TIMEOUT_CONFIGS.healthcare);
    });

    it('should have strict timeouts for HIPAA compliance', () => {
      expect(DEFAULT_HEALTHCARE_TIMEOUT.idleTimeoutSeconds).toBeLessThanOrEqual(1800);
      expect(DEFAULT_HEALTHCARE_TIMEOUT.absoluteTimeoutSeconds).toBeLessThanOrEqual(28800);
    });
  });

  describe('getRealmTimeoutConfig', () => {
    it('should return healthcare config for clinisyn realms', () => {
      const config = getRealmTimeoutConfig('clinisyn-psychologists');
      expect(config).toEqual(TIMEOUT_CONFIGS.healthcare);
    });

    it('should return healthcare config for clinisyn-students', () => {
      const config = getRealmTimeoutConfig('clinisyn-students');
      expect(config).toEqual(TIMEOUT_CONFIGS.healthcare);
    });

    it('should return standard config for non-clinisyn realms', () => {
      const config = getRealmTimeoutConfig('other-realm');
      expect(config).toEqual(TIMEOUT_CONFIGS.standard);
    });

    it('should use realm settings when provided', () => {
      const config = getRealmTimeoutConfig('custom-realm', {
        session_timeout_type: 'extended'
      });
      expect(config.idleTimeoutSeconds).toBe(TIMEOUT_CONFIGS.extended.idleTimeoutSeconds);
    });

    it('should allow custom idle timeout', () => {
      const config = getRealmTimeoutConfig('custom-realm', {
        session_timeout_type: 'standard',
        custom_idle_timeout: 900
      });
      expect(config.idleTimeoutSeconds).toBe(900);
    });

    it('should allow custom absolute timeout', () => {
      const config = getRealmTimeoutConfig('custom-realm', {
        session_timeout_type: 'standard',
        custom_absolute_timeout: 14400
      });
      expect(config.absoluteTimeoutSeconds).toBe(14400);
    });

    it('should prioritize clinisyn over custom settings', () => {
      const config = getRealmTimeoutConfig('clinisyn-test', {
        session_timeout_type: 'extended'
      });
      expect(config).toEqual(TIMEOUT_CONFIGS.healthcare);
    });
  });

  describe('needsTimeoutWarning', () => {
    const config = TIMEOUT_CONFIGS.healthcare;

    it('should return false for invalid session', () => {
      const status: SessionStatus = {
        isValid: false,
        isExpired: true,
        warningActive: false
      };
      expect(needsTimeoutWarning(status, config)).toBe(false);
    });

    it('should return false for expired session', () => {
      const status: SessionStatus = {
        isValid: false,
        isExpired: true,
        expiredReason: 'idle',
        warningActive: false
      };
      expect(needsTimeoutWarning(status, config)).toBe(false);
    });

    it('should return true when idle time is within warning threshold', () => {
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 200, // 200 seconds < 300 warning threshold
        absoluteTimeRemaining: 10000,
        warningActive: true
      };
      expect(needsTimeoutWarning(status, config)).toBe(true);
    });

    it('should return true when absolute time is within warning threshold', () => {
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 1000,
        absoluteTimeRemaining: 200, // 200 seconds < 300 warning threshold
        warningActive: true
      };
      expect(needsTimeoutWarning(status, config)).toBe(true);
    });

    it('should return false when both times are above warning threshold', () => {
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 1000,
        absoluteTimeRemaining: 10000,
        warningActive: false
      };
      expect(needsTimeoutWarning(status, config)).toBe(false);
    });
  });

  describe('getTimeoutInfo', () => {
    const config = TIMEOUT_CONFIGS.healthcare;

    it('should return null values for invalid session', () => {
      const status: SessionStatus = {
        isValid: false,
        isExpired: true,
        warningActive: false
      };
      const info = getTimeoutInfo(status, config);
      expect(info.timeoutType).toBeNull();
      expect(info.secondsRemaining).toBeNull();
      expect(info.warningActive).toBe(false);
    });

    it('should return idle timeout when idle is sooner', () => {
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 500,
        absoluteTimeRemaining: 10000,
        warningActive: false
      };
      const info = getTimeoutInfo(status, config);
      expect(info.timeoutType).toBe('idle');
      expect(info.secondsRemaining).toBe(500);
    });

    it('should return absolute timeout when absolute is sooner', () => {
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 10000,
        absoluteTimeRemaining: 500,
        warningActive: false
      };
      const info = getTimeoutInfo(status, config);
      expect(info.timeoutType).toBe('absolute');
      expect(info.secondsRemaining).toBe(500);
    });

    it('should indicate warning when within threshold', () => {
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        idleTimeRemaining: 200,
        absoluteTimeRemaining: 10000,
        warningActive: true
      };
      const info = getTimeoutInfo(status, config);
      expect(info.warningActive).toBe(true);
    });
  });

  describe('SessionStatus structure', () => {
    it('should have all required fields for valid session', () => {
      const status: SessionStatus = {
        isValid: true,
        isExpired: false,
        lastActivity: new Date().toISOString(),
        sessionStart: new Date().toISOString(),
        idleTimeRemaining: 1800,
        absoluteTimeRemaining: 28800,
        warningActive: false
      };

      expect(typeof status.isValid).toBe('boolean');
      expect(typeof status.isExpired).toBe('boolean');
      expect(typeof status.lastActivity).toBe('string');
      expect(typeof status.sessionStart).toBe('string');
      expect(typeof status.idleTimeRemaining).toBe('number');
      expect(typeof status.absoluteTimeRemaining).toBe('number');
      expect(typeof status.warningActive).toBe('boolean');
    });

    it('should have expiredReason for expired session', () => {
      const status: SessionStatus = {
        isValid: false,
        isExpired: true,
        expiredReason: 'idle',
        warningActive: false
      };

      expect(status.expiredReason).toBe('idle');
    });
  });

  describe('SessionTimeoutConfig structure', () => {
    it('should have all required fields', () => {
      const config: SessionTimeoutConfig = {
        idleTimeoutSeconds: 1800,
        absoluteTimeoutSeconds: 28800,
        warningBeforeTimeoutSeconds: 300,
        activityTrackingEnabled: true,
        extendOnActivity: true
      };

      expect(typeof config.idleTimeoutSeconds).toBe('number');
      expect(typeof config.absoluteTimeoutSeconds).toBe('number');
      expect(typeof config.warningBeforeTimeoutSeconds).toBe('number');
      expect(typeof config.activityTrackingEnabled).toBe('boolean');
      expect(typeof config.extendOnActivity).toBe('boolean');
    });
  });

  describe('Property-based tests', () => {
    describe('Timeout config validation', () => {
      it('should always have idle timeout < absolute timeout', () => {
        Object.values(TIMEOUT_CONFIGS).forEach(config => {
          expect(config.idleTimeoutSeconds).toBeLessThan(config.absoluteTimeoutSeconds);
        });
      });

      it('should always have warning < idle timeout', () => {
        Object.values(TIMEOUT_CONFIGS).forEach(config => {
          expect(config.warningBeforeTimeoutSeconds).toBeLessThan(config.idleTimeoutSeconds);
        });
      });

      it('should have positive timeout values', () => {
        Object.values(TIMEOUT_CONFIGS).forEach(config => {
          expect(config.idleTimeoutSeconds).toBeGreaterThan(0);
          expect(config.absoluteTimeoutSeconds).toBeGreaterThan(0);
          expect(config.warningBeforeTimeoutSeconds).toBeGreaterThan(0);
        });
      });
    });

    describe('Realm config selection', () => {
      it('should return valid config for any realm', () => {
        fc.assert(
          fc.property(fc.string({ minLength: 1, maxLength: 50 }), (realmId) => {
            const config = getRealmTimeoutConfig(realmId);
            expect(config.idleTimeoutSeconds).toBeGreaterThan(0);
            expect(config.absoluteTimeoutSeconds).toBeGreaterThan(0);
            return true;
          }),
          { numRuns: 50 }
        );
      });

      it('should always return healthcare for clinisyn prefix', () => {
        fc.assert(
          fc.property(fc.string({ minLength: 1, maxLength: 20 }), (suffix) => {
            const config = getRealmTimeoutConfig(`clinisyn-${suffix}`);
            expect(config).toEqual(TIMEOUT_CONFIGS.healthcare);
            return true;
          }),
          { numRuns: 50 }
        );
      });
    });

    describe('Timeout info calculation', () => {
      it('should return correct timeout type based on remaining time', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 1, max: 10000 }),
            fc.integer({ min: 1, max: 100000 }),
            (idleRemaining, absoluteRemaining) => {
              const status: SessionStatus = {
                isValid: true,
                isExpired: false,
                idleTimeRemaining: idleRemaining,
                absoluteTimeRemaining: absoluteRemaining,
                warningActive: false
              };
              const info = getTimeoutInfo(status, TIMEOUT_CONFIGS.healthcare);
              
              if (idleRemaining <= absoluteRemaining) {
                expect(info.timeoutType).toBe('idle');
                expect(info.secondsRemaining).toBe(idleRemaining);
              } else {
                expect(info.timeoutType).toBe('absolute');
                expect(info.secondsRemaining).toBe(absoluteRemaining);
              }
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Warning threshold', () => {
      it('should correctly identify warning state', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 1, max: 5000 }),
            fc.integer({ min: 1, max: 50000 }),
            (idleRemaining, absoluteRemaining) => {
              const config = TIMEOUT_CONFIGS.healthcare;
              const status: SessionStatus = {
                isValid: true,
                isExpired: false,
                idleTimeRemaining: idleRemaining,
                absoluteTimeRemaining: absoluteRemaining,
                warningActive: idleRemaining <= config.warningBeforeTimeoutSeconds ||
                              absoluteRemaining <= config.warningBeforeTimeoutSeconds
              };
              
              const needsWarning = needsTimeoutWarning(status, config);
              const expectedWarning = idleRemaining <= config.warningBeforeTimeoutSeconds ||
                                     absoluteRemaining <= config.warningBeforeTimeoutSeconds;
              
              expect(needsWarning).toBe(expectedWarning);
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });
  });

  describe('HIPAA Compliance', () => {
    it('should enforce 30 minute idle timeout for healthcare', () => {
      expect(TIMEOUT_CONFIGS.healthcare.idleTimeoutSeconds).toBe(30 * 60);
    });

    it('should enforce 8 hour absolute timeout for healthcare', () => {
      expect(TIMEOUT_CONFIGS.healthcare.absoluteTimeoutSeconds).toBe(8 * 60 * 60);
    });

    it('should require activity tracking for healthcare', () => {
      expect(TIMEOUT_CONFIGS.healthcare.activityTrackingEnabled).toBe(true);
    });

    it('should provide warning before timeout', () => {
      expect(TIMEOUT_CONFIGS.healthcare.warningBeforeTimeoutSeconds).toBeGreaterThanOrEqual(60);
    });
  });

  describe('Expired reason types', () => {
    it('should support idle expiration', () => {
      const status: SessionStatus = {
        isValid: false,
        isExpired: true,
        expiredReason: 'idle',
        warningActive: false
      };
      expect(status.expiredReason).toBe('idle');
    });

    it('should support absolute expiration', () => {
      const status: SessionStatus = {
        isValid: false,
        isExpired: true,
        expiredReason: 'absolute',
        warningActive: false
      };
      expect(status.expiredReason).toBe('absolute');
    });

    it('should support revoked expiration', () => {
      const status: SessionStatus = {
        isValid: false,
        isExpired: true,
        expiredReason: 'revoked',
        warningActive: false
      };
      expect(status.expiredReason).toBe('revoked');
    });
  });
});
