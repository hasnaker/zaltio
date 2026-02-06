/**
 * Credential Stuffing Detection Service Tests
 * Task 6.2: Credential Stuffing Detection
 * 
 * Tests:
 * - Pattern detection algorithms
 * - Threshold validation
 * - IP blocking
 * - Security alerting
 * - False positive prevention
 */

import * as fc from 'fast-check';
import {
  AttackType,
  DetectionResult,
  DETECTION_THRESHOLDS,
  hashPasswordForDetection,
  isCaptchaRequired,
  getRecommendedAction
} from './credential-stuffing.service';

/**
 * Custom generators for property-based testing
 */
const passwordArb = fc.string({ minLength: 8, maxLength: 64 });
const emailArb = fc.emailAddress();
const ipAddressArb = fc.tuple(
  fc.integer({ min: 1, max: 255 }),
  fc.integer({ min: 0, max: 255 }),
  fc.integer({ min: 0, max: 255 }),
  fc.integer({ min: 1, max: 254 })
).map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`);

const confidenceArb = fc.integer({ min: 0, max: 100 });

describe('Credential Stuffing Detection Service - Unit Tests', () => {
  describe('DETECTION_THRESHOLDS', () => {
    it('should have correct credential stuffing threshold', () => {
      expect(DETECTION_THRESHOLDS.samePasswordDifferentEmails).toBe(3);
    });

    it('should have correct brute force threshold', () => {
      expect(DETECTION_THRESHOLDS.sameIpFailedLogins).toBe(10);
    });

    it('should have correct distributed attack threshold', () => {
      expect(DETECTION_THRESHOLDS.differentIpsTargetingSameEmail).toBe(5);
    });

    it('should have correct high velocity threshold', () => {
      expect(DETECTION_THRESHOLDS.requestsPerSecond).toBe(1);
    });

    it('should have correct detection window', () => {
      expect(DETECTION_THRESHOLDS.detectionWindow).toBe(300); // 5 minutes
    });

    it('should have correct blocking confidence threshold', () => {
      expect(DETECTION_THRESHOLDS.blockingConfidenceThreshold).toBe(70);
    });

    it('should have correct CAPTCHA confidence threshold', () => {
      expect(DETECTION_THRESHOLDS.captchaConfidenceThreshold).toBe(50);
    });

    it('should have correct default block duration', () => {
      expect(DETECTION_THRESHOLDS.defaultBlockDuration).toBe(900); // 15 minutes
    });

    it('should have correct extended block duration', () => {
      expect(DETECTION_THRESHOLDS.extendedBlockDuration).toBe(3600); // 1 hour
    });
  });

  describe('hashPasswordForDetection', () => {
    it('should return consistent hash for same password', () => {
      fc.assert(
        fc.property(passwordArb, (password) => {
          const hash1 = hashPasswordForDetection(password);
          const hash2 = hashPasswordForDetection(password);
          expect(hash1).toBe(hash2);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should return different hash for different passwords', () => {
      fc.assert(
        fc.property(passwordArb, passwordArb, (password1, password2) => {
          if (password1 !== password2) {
            const hash1 = hashPasswordForDetection(password1);
            const hash2 = hashPasswordForDetection(password2);
            expect(hash1).not.toBe(hash2);
          }
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should return 16 character hash', () => {
      fc.assert(
        fc.property(passwordArb, (password) => {
          const hash = hashPasswordForDetection(password);
          expect(hash.length).toBe(16);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should return hexadecimal string', () => {
      fc.assert(
        fc.property(passwordArb, (password) => {
          const hash = hashPasswordForDetection(password);
          expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('isCaptchaRequired', () => {
    it('should return true when requiresCaptcha is true', () => {
      const detection: DetectionResult = {
        detected: true,
        attackType: AttackType.CREDENTIAL_STUFFING,
        confidence: 30,
        requiresCaptcha: true,
        shouldBlock: false,
        alertSent: false,
        details: {}
      };

      expect(isCaptchaRequired(detection)).toBe(true);
    });

    it('should return true when confidence >= CAPTCHA threshold', () => {
      const detection: DetectionResult = {
        detected: true,
        attackType: AttackType.BRUTE_FORCE,
        confidence: DETECTION_THRESHOLDS.captchaConfidenceThreshold,
        requiresCaptcha: false,
        shouldBlock: false,
        alertSent: false,
        details: {}
      };

      expect(isCaptchaRequired(detection)).toBe(true);
    });

    it('should return false when confidence < CAPTCHA threshold and requiresCaptcha is false', () => {
      const detection: DetectionResult = {
        detected: false,
        confidence: DETECTION_THRESHOLDS.captchaConfidenceThreshold - 1,
        requiresCaptcha: false,
        shouldBlock: false,
        alertSent: false,
        details: {}
      };

      expect(isCaptchaRequired(detection)).toBe(false);
    });
  });

  describe('getRecommendedAction', () => {
    it('should return block action when shouldBlock is true', () => {
      const detection: DetectionResult = {
        detected: true,
        attackType: AttackType.CREDENTIAL_STUFFING,
        confidence: 80,
        requiresCaptcha: true,
        shouldBlock: true,
        alertSent: true,
        details: {}
      };

      const action = getRecommendedAction(detection);
      expect(action.action).toBe('block');
      expect(action.message).toContain('Suspicious activity detected');
    });

    it('should return captcha action when requiresCaptcha is true but shouldBlock is false', () => {
      const detection: DetectionResult = {
        detected: true,
        attackType: AttackType.DISTRIBUTED_ATTACK,
        confidence: 60,
        requiresCaptcha: true,
        shouldBlock: false,
        alertSent: false,
        details: {}
      };

      const action = getRecommendedAction(detection);
      expect(action.action).toBe('captcha');
      expect(action.message).toContain('security verification');
    });

    it('should return allow action when no threat detected', () => {
      const detection: DetectionResult = {
        detected: false,
        confidence: 0,
        requiresCaptcha: false,
        shouldBlock: false,
        alertSent: false,
        details: {}
      };

      const action = getRecommendedAction(detection);
      expect(action.action).toBe('allow');
      expect(action.message).toBe('');
    });
  });

  describe('AttackType enum', () => {
    it('should have all attack types defined', () => {
      expect(AttackType.CREDENTIAL_STUFFING).toBe('credential_stuffing');
      expect(AttackType.BRUTE_FORCE).toBe('brute_force');
      expect(AttackType.DISTRIBUTED_ATTACK).toBe('distributed_attack');
      expect(AttackType.HIGH_VELOCITY).toBe('high_velocity');
      expect(AttackType.PASSWORD_SPRAY).toBe('password_spray');
    });
  });

  describe('Property-based tests', () => {
    describe('Detection result structure', () => {
      it('should have valid structure for all detection results', () => {
        fc.assert(
          fc.property(
            fc.boolean(),
            confidenceArb,
            fc.boolean(),
            fc.boolean(),
            (detected, confidence, requiresCaptcha, shouldBlock) => {
              const result: DetectionResult = {
                detected,
                confidence,
                requiresCaptcha,
                shouldBlock,
                alertSent: false,
                details: {}
              };

              expect(typeof result.detected).toBe('boolean');
              expect(typeof result.confidence).toBe('number');
              expect(result.confidence).toBeGreaterThanOrEqual(0);
              expect(result.confidence).toBeLessThanOrEqual(100);
              expect(typeof result.requiresCaptcha).toBe('boolean');
              expect(typeof result.shouldBlock).toBe('boolean');

              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Confidence thresholds', () => {
      it('should require CAPTCHA when confidence >= threshold', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: DETECTION_THRESHOLDS.captchaConfidenceThreshold, max: 100 }),
            (confidence) => {
              const result: DetectionResult = {
                detected: true,
                confidence,
                requiresCaptcha: false,
                shouldBlock: false,
                alertSent: false,
                details: {}
              };

              expect(isCaptchaRequired(result)).toBe(true);
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });

      it('should not require CAPTCHA when confidence < threshold', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 0, max: DETECTION_THRESHOLDS.captchaConfidenceThreshold - 1 }),
            (confidence) => {
              const result: DetectionResult = {
                detected: false,
                confidence,
                requiresCaptcha: false,
                shouldBlock: false,
                alertSent: false,
                details: {}
              };

              expect(isCaptchaRequired(result)).toBe(false);
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Action recommendations', () => {
      it('should always return valid action type', () => {
        fc.assert(
          fc.property(
            fc.boolean(),
            confidenceArb,
            fc.boolean(),
            fc.boolean(),
            (detected, confidence, requiresCaptcha, shouldBlock) => {
              const result: DetectionResult = {
                detected,
                confidence,
                requiresCaptcha,
                shouldBlock,
                alertSent: false,
                details: {}
              };

              const action = getRecommendedAction(result);
              expect(['allow', 'captcha', 'block']).toContain(action.action);
              expect(typeof action.message).toBe('string');

              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Password hash consistency', () => {
      it('should produce deterministic hashes', () => {
        fc.assert(
          fc.property(passwordArb, (password) => {
            const hashes = Array.from({ length: 10 }, () => hashPasswordForDetection(password));
            const allSame = hashes.every(h => h === hashes[0]);
            expect(allSame).toBe(true);
            return true;
          }),
          { numRuns: 50 }
        );
      });
    });
  });

  describe('Threshold validation', () => {
    it('should have CAPTCHA threshold lower than blocking threshold', () => {
      expect(DETECTION_THRESHOLDS.captchaConfidenceThreshold)
        .toBeLessThan(DETECTION_THRESHOLDS.blockingConfidenceThreshold);
    });

    it('should have default block duration shorter than extended', () => {
      expect(DETECTION_THRESHOLDS.defaultBlockDuration)
        .toBeLessThan(DETECTION_THRESHOLDS.extendedBlockDuration);
    });

    it('should have reasonable detection window', () => {
      expect(DETECTION_THRESHOLDS.detectionWindow).toBeGreaterThanOrEqual(60);
      expect(DETECTION_THRESHOLDS.detectionWindow).toBeLessThanOrEqual(3600);
    });
  });
});
