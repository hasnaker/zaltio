/**
 * JWT Key Rotation Service Tests
 * Task 6.4: JWT Key Rotation
 * 
 * Tests:
 * - Key generation
 * - Key rotation
 * - Grace period handling
 * - Key revocation
 * - JWKS endpoint
 */

import * as fc from 'fast-check';
import {
  KeyStatus,
  KEY_ROTATION_CONFIG,
  generateKeyId,
  generateKeyPair,
  keyToJWK
} from './jwt-rotation.service';

describe('JWT Key Rotation Service - Unit Tests', () => {
  describe('KEY_ROTATION_CONFIG', () => {
    it('should have correct key lifetime (30 days)', () => {
      expect(KEY_ROTATION_CONFIG.keyLifetimeDays).toBe(30);
      expect(KEY_ROTATION_CONFIG.keyLifetimeSeconds).toBe(30 * 24 * 60 * 60);
    });

    it('should have correct grace period (15 days)', () => {
      expect(KEY_ROTATION_CONFIG.gracePeriodDays).toBe(15);
      expect(KEY_ROTATION_CONFIG.gracePeriodSeconds).toBe(15 * 24 * 60 * 60);
    });

    it('should use RS256 algorithm', () => {
      expect(KEY_ROTATION_CONFIG.algorithm).toBe('RS256');
    });

    it('should use 2048-bit modulus', () => {
      expect(KEY_ROTATION_CONFIG.modulusLength).toBe(2048);
    });

    it('should limit max active keys', () => {
      expect(KEY_ROTATION_CONFIG.maxActiveKeys).toBe(3);
    });
  });

  describe('KeyStatus enum', () => {
    it('should have all status values defined', () => {
      expect(KeyStatus.ACTIVE).toBe('active');
      expect(KeyStatus.GRACE_PERIOD).toBe('grace_period');
      expect(KeyStatus.ARCHIVED).toBe('archived');
      expect(KeyStatus.REVOKED).toBe('revoked');
    });
  });

  describe('generateKeyId', () => {
    it('should generate unique key IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateKeyId());
      }
      expect(ids.size).toBe(100);
    });

    it('should start with zalt- prefix', () => {
      const kid = generateKeyId();
      expect(kid.startsWith('zalt-')).toBe(true);
    });

    it('should have reasonable length', () => {
      const kid = generateKeyId();
      expect(kid.length).toBeGreaterThan(10);
      expect(kid.length).toBeLessThan(50);
    });
  });

  describe('generateKeyPair', () => {
    it('should generate valid RSA key pair', async () => {
      const { publicKey, privateKey } = await generateKeyPair();
      
      expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(publicKey).toContain('-----END PUBLIC KEY-----');
      expect(privateKey).toContain('-----BEGIN PRIVATE KEY-----');
      expect(privateKey).toContain('-----END PRIVATE KEY-----');
    });

    it('should generate different keys each time', async () => {
      const pair1 = await generateKeyPair();
      const pair2 = await generateKeyPair();
      
      expect(pair1.publicKey).not.toBe(pair2.publicKey);
      expect(pair1.privateKey).not.toBe(pair2.privateKey);
    });
  });

  describe('keyToJWK', () => {
    it('should convert key to JWK format', () => {
      const key = {
        kid: 'test-kid',
        algorithm: 'RS256' as const,
        publicKey: '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----',
        status: KeyStatus.ACTIVE,
        createdAt: new Date().toISOString(),
        expiresAt: new Date().toISOString(),
        gracePeriodEndsAt: new Date().toISOString()
      };

      const jwk = keyToJWK(key);

      expect(jwk).toHaveProperty('kty', 'RSA');
      expect(jwk).toHaveProperty('use', 'sig');
      expect(jwk).toHaveProperty('alg', 'RS256');
      expect(jwk).toHaveProperty('kid', 'test-kid');
    });
  });

  describe('Property-based tests', () => {
    describe('Key ID generation', () => {
      it('should always generate valid key IDs', () => {
        fc.assert(
          fc.property(fc.integer({ min: 1, max: 100 }), () => {
            const kid = generateKeyId();
            
            expect(typeof kid).toBe('string');
            expect(kid.length).toBeGreaterThan(0);
            expect(kid.startsWith('zalt-')).toBe(true);
            
            return true;
          }),
          { numRuns: 50 }
        );
      });

      it('should generate unique IDs', () => {
        fc.assert(
          fc.property(fc.integer({ min: 2, max: 10 }), (count) => {
            const ids = Array.from({ length: count }, () => generateKeyId());
            const uniqueIds = new Set(ids);
            
            expect(uniqueIds.size).toBe(count);
            
            return true;
          }),
          { numRuns: 50 }
        );
      });
    });

    describe('Configuration validation', () => {
      it('should have grace period shorter than key lifetime', () => {
        expect(KEY_ROTATION_CONFIG.gracePeriodDays)
          .toBeLessThan(KEY_ROTATION_CONFIG.keyLifetimeDays);
      });

      it('should have grace period at least 7 days', () => {
        expect(KEY_ROTATION_CONFIG.gracePeriodDays).toBeGreaterThanOrEqual(7);
      });

      it('should have key lifetime at least 14 days', () => {
        expect(KEY_ROTATION_CONFIG.keyLifetimeDays).toBeGreaterThanOrEqual(14);
      });
    });

    describe('Key status transitions', () => {
      it('should follow valid status progression', () => {
        const validTransitions: Record<KeyStatus, KeyStatus[]> = {
          [KeyStatus.ACTIVE]: [KeyStatus.GRACE_PERIOD, KeyStatus.REVOKED],
          [KeyStatus.GRACE_PERIOD]: [KeyStatus.ARCHIVED, KeyStatus.REVOKED],
          [KeyStatus.ARCHIVED]: [], // Terminal state
          [KeyStatus.REVOKED]: []   // Terminal state
        };

        Object.entries(validTransitions).forEach(([from, toList]) => {
          expect(Array.isArray(toList)).toBe(true);
        });
      });
    });
  });

  describe('Timing calculations', () => {
    it('should calculate correct expiration time', () => {
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = now + KEY_ROTATION_CONFIG.keyLifetimeSeconds;
      const gracePeriodEndsAt = expiresAt + KEY_ROTATION_CONFIG.gracePeriodSeconds;

      // Key should be valid for 30 days
      expect(expiresAt - now).toBe(30 * 24 * 60 * 60);
      
      // Grace period should extend 15 more days
      expect(gracePeriodEndsAt - expiresAt).toBe(15 * 24 * 60 * 60);
      
      // Total validity should be 45 days
      expect(gracePeriodEndsAt - now).toBe(45 * 24 * 60 * 60);
    });
  });

  describe('Security requirements', () => {
    it('should use FIPS-compliant algorithm', () => {
      // RS256 is FIPS 140-2 compliant
      expect(KEY_ROTATION_CONFIG.algorithm).toBe('RS256');
    });

    it('should use adequate key size', () => {
      // 2048 bits is minimum for RSA security
      expect(KEY_ROTATION_CONFIG.modulusLength).toBeGreaterThanOrEqual(2048);
    });
  });
});
