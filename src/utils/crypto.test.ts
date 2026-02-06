/**
 * Cryptographic Utilities Tests
 * Task 6.7: Timing Attack Prevention
 * 
 * Tests:
 * - Constant-time string comparison
 * - Constant-time buffer comparison
 * - HMAC verification
 * - Token hash verification
 * - Timing attack resistance
 */

import * as fc from 'fast-check';
import * as crypto from 'crypto';
import {
  constantTimeCompare,
  constantTimeEqual,
  constantTimeHexCompare,
  verifyHmacConstantTime,
  verifyTokenHashConstantTime,
  secureRandomBytes,
  secureRandomHex,
  secureRandomInt,
  sha256,
  sha512,
  createHmac,
  timingSafeUserVerify,
  addTimingJitter,
  verifyApiKey,
  verifySessionToken,
  verifyRefreshToken
} from './crypto';

describe('Crypto Utilities - Unit Tests', () => {
  describe('constantTimeCompare', () => {
    it('should return true for equal strings', () => {
      expect(constantTimeCompare('hello', 'hello')).toBe(true);
      expect(constantTimeCompare('password123', 'password123')).toBe(true);
      expect(constantTimeCompare('', '')).toBe(true);
    });

    it('should return false for different strings', () => {
      expect(constantTimeCompare('hello', 'world')).toBe(false);
      expect(constantTimeCompare('password123', 'password124')).toBe(false);
      expect(constantTimeCompare('abc', 'abcd')).toBe(false);
    });

    it('should return false for different length strings', () => {
      expect(constantTimeCompare('short', 'longer_string')).toBe(false);
      expect(constantTimeCompare('a', 'ab')).toBe(false);
    });

    it('should handle empty strings', () => {
      expect(constantTimeCompare('', '')).toBe(true);
      expect(constantTimeCompare('', 'a')).toBe(false);
      expect(constantTimeCompare('a', '')).toBe(false);
    });

    it('should handle special characters', () => {
      expect(constantTimeCompare('héllo', 'héllo')).toBe(true);
      expect(constantTimeCompare('🔐', '🔐')).toBe(true);
      expect(constantTimeCompare('héllo', 'hello')).toBe(false);
    });

    it('should return false for non-string inputs', () => {
      expect(constantTimeCompare(null as any, 'test')).toBe(false);
      expect(constantTimeCompare('test', undefined as any)).toBe(false);
      expect(constantTimeCompare(123 as any, '123')).toBe(false);
    });
  });

  describe('constantTimeEqual', () => {
    it('should return true for equal buffers', () => {
      const buf1 = Buffer.from('hello');
      const buf2 = Buffer.from('hello');
      expect(constantTimeEqual(buf1, buf2)).toBe(true);
    });

    it('should return false for different buffers', () => {
      const buf1 = Buffer.from('hello');
      const buf2 = Buffer.from('world');
      expect(constantTimeEqual(buf1, buf2)).toBe(false);
    });

    it('should return false for different length buffers', () => {
      const buf1 = Buffer.from('short');
      const buf2 = Buffer.from('longer');
      expect(constantTimeEqual(buf1, buf2)).toBe(false);
    });

    it('should handle empty buffers', () => {
      expect(constantTimeEqual(Buffer.alloc(0), Buffer.alloc(0))).toBe(true);
      expect(constantTimeEqual(Buffer.alloc(0), Buffer.from('a'))).toBe(false);
    });

    it('should return false for non-buffer inputs', () => {
      expect(constantTimeEqual(null as any, Buffer.from('test'))).toBe(false);
      expect(constantTimeEqual(Buffer.from('test'), 'string' as any)).toBe(false);
    });
  });

  describe('constantTimeHexCompare', () => {
    it('should return true for equal hex strings', () => {
      expect(constantTimeHexCompare('abcd1234', 'abcd1234')).toBe(true);
      expect(constantTimeHexCompare('ABCD', 'abcd')).toBe(true); // Case insensitive
    });

    it('should return false for different hex strings', () => {
      expect(constantTimeHexCompare('abcd1234', 'abcd1235')).toBe(false);
    });

    it('should return false for invalid hex strings', () => {
      expect(constantTimeHexCompare('ghij', 'abcd')).toBe(false);
      expect(constantTimeHexCompare('abcd', 'xyz!')).toBe(false);
    });

    it('should handle empty strings', () => {
      expect(constantTimeHexCompare('', '')).toBe(true);
    });

    it('should return false for non-string inputs', () => {
      expect(constantTimeHexCompare(null as any, 'abcd')).toBe(false);
    });
  });

  describe('verifyHmacConstantTime', () => {
    const secret = 'test_secret_key';
    const message = 'test message';

    it('should verify valid HMAC signature', () => {
      const signature = crypto
        .createHmac('sha256', secret)
        .update(message)
        .digest('hex');

      expect(verifyHmacConstantTime(message, signature, secret)).toBe(true);
    });

    it('should reject invalid HMAC signature', () => {
      const fakeSignature = crypto
        .createHmac('sha256', 'wrong_secret')
        .update(message)
        .digest('hex');

      expect(verifyHmacConstantTime(message, fakeSignature, secret)).toBe(false);
    });

    it('should reject tampered message', () => {
      const signature = crypto
        .createHmac('sha256', secret)
        .update(message)
        .digest('hex');

      expect(verifyHmacConstantTime('tampered', signature, secret)).toBe(false);
    });

    it('should handle different algorithms', () => {
      const signature = crypto
        .createHmac('sha512', secret)
        .update(message)
        .digest('hex');

      expect(verifyHmacConstantTime(message, signature, secret, 'sha512')).toBe(true);
    });

    it('should return false for empty inputs', () => {
      expect(verifyHmacConstantTime('', 'sig', secret)).toBe(false);
      expect(verifyHmacConstantTime(message, '', secret)).toBe(false);
      expect(verifyHmacConstantTime(message, 'sig', '')).toBe(false);
    });
  });

  describe('verifyTokenHashConstantTime', () => {
    it('should verify valid token hash', () => {
      const token = 'my_secret_token';
      const hash = crypto.createHash('sha256').update(token).digest('hex');

      expect(verifyTokenHashConstantTime(token, hash)).toBe(true);
    });

    it('should reject invalid token', () => {
      const token = 'my_secret_token';
      const hash = crypto.createHash('sha256').update(token).digest('hex');

      expect(verifyTokenHashConstantTime('wrong_token', hash)).toBe(false);
    });

    it('should handle different algorithms', () => {
      const token = 'my_secret_token';
      const hash = crypto.createHash('sha512').update(token).digest('hex');

      expect(verifyTokenHashConstantTime(token, hash, 'sha512')).toBe(true);
    });

    it('should return false for empty inputs', () => {
      expect(verifyTokenHashConstantTime('', 'hash')).toBe(false);
      expect(verifyTokenHashConstantTime('token', '')).toBe(false);
    });
  });

  describe('secureRandomBytes', () => {
    it('should generate bytes of correct length', () => {
      expect(secureRandomBytes(16).length).toBe(16);
      expect(secureRandomBytes(32).length).toBe(32);
      expect(secureRandomBytes(64).length).toBe(64);
    });

    it('should generate different values each time', () => {
      const bytes1 = secureRandomBytes(32);
      const bytes2 = secureRandomBytes(32);
      expect(bytes1.equals(bytes2)).toBe(false);
    });

    it('should throw for invalid length', () => {
      expect(() => secureRandomBytes(0)).toThrow();
      expect(() => secureRandomBytes(-1)).toThrow();
      expect(() => secureRandomBytes(100000)).toThrow();
    });
  });

  describe('secureRandomHex', () => {
    it('should generate hex string of correct length', () => {
      expect(secureRandomHex(16).length).toBe(32); // 16 bytes = 32 hex chars
      expect(secureRandomHex(32).length).toBe(64);
    });

    it('should generate valid hex characters', () => {
      const hex = secureRandomHex(32);
      expect(/^[0-9a-f]+$/.test(hex)).toBe(true);
    });

    it('should generate different values each time', () => {
      const hex1 = secureRandomHex(32);
      const hex2 = secureRandomHex(32);
      expect(hex1).not.toBe(hex2);
    });
  });

  describe('secureRandomInt', () => {
    it('should generate integers in range', () => {
      for (let i = 0; i < 100; i++) {
        const num = secureRandomInt(0, 10);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(10);
      }
    });

    it('should throw for invalid range', () => {
      expect(() => secureRandomInt(10, 5)).toThrow();
      expect(() => secureRandomInt(5, 5)).toThrow();
    });
  });

  describe('sha256', () => {
    it('should produce consistent hash', () => {
      const hash1 = sha256('test');
      const hash2 = sha256('test');
      expect(hash1).toBe(hash2);
    });

    it('should produce different hash for different input', () => {
      const hash1 = sha256('test1');
      const hash2 = sha256('test2');
      expect(hash1).not.toBe(hash2);
    });

    it('should produce 64 character hex string', () => {
      const hash = sha256('test');
      expect(hash.length).toBe(64);
      expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
    });
  });

  describe('sha512', () => {
    it('should produce consistent hash', () => {
      const hash1 = sha512('test');
      const hash2 = sha512('test');
      expect(hash1).toBe(hash2);
    });

    it('should produce 128 character hex string', () => {
      const hash = sha512('test');
      expect(hash.length).toBe(128);
    });
  });

  describe('createHmac', () => {
    it('should create valid HMAC', () => {
      const hmac = createHmac('message', 'secret');
      expect(hmac.length).toBe(64); // SHA-256 = 64 hex chars
    });

    it('should produce consistent HMAC', () => {
      const hmac1 = createHmac('message', 'secret');
      const hmac2 = createHmac('message', 'secret');
      expect(hmac1).toBe(hmac2);
    });

    it('should produce different HMAC for different secrets', () => {
      const hmac1 = createHmac('message', 'secret1');
      const hmac2 = createHmac('message', 'secret2');
      expect(hmac1).not.toBe(hmac2);
    });
  });

  describe('timingSafeUserVerify', () => {
    it('should return true only when user exists AND hash matches', () => {
      const hash = sha256('password');
      expect(timingSafeUserVerify(true, hash, hash)).toBe(true);
    });

    it('should return false when user does not exist', () => {
      const hash = sha256('password');
      expect(timingSafeUserVerify(false, hash, hash)).toBe(false);
    });

    it('should return false when hash does not match', () => {
      const storedHash = sha256('password1');
      const providedHash = sha256('password2');
      expect(timingSafeUserVerify(true, storedHash, providedHash)).toBe(false);
    });

    it('should return false when both conditions fail', () => {
      const storedHash = sha256('password1');
      const providedHash = sha256('password2');
      expect(timingSafeUserVerify(false, storedHash, providedHash)).toBe(false);
    });
  });

  describe('addTimingJitter', () => {
    it('should add delay', async () => {
      const start = Date.now();
      await addTimingJitter(50, 10);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(50);
    });

    it('should handle zero delay', async () => {
      const start = Date.now();
      await addTimingJitter(0, 0);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(50);
    });
  });

  describe('verifyApiKey', () => {
    it('should verify valid API key', () => {
      const key = 'zalt_live_abcd1234efgh5678';
      expect(verifyApiKey(key, key)).toBe(true);
    });

    it('should reject invalid API key', () => {
      expect(verifyApiKey('wrong_key', 'correct_key')).toBe(false);
    });

    it('should handle empty keys', () => {
      expect(verifyApiKey('', 'key')).toBe(false);
      expect(verifyApiKey('key', '')).toBe(false);
    });
  });

  describe('verifySessionToken', () => {
    it('should verify valid session token', () => {
      const token = secureRandomHex(32);
      expect(verifySessionToken(token, token)).toBe(true);
    });

    it('should reject invalid session token', () => {
      const token1 = secureRandomHex(32);
      const token2 = secureRandomHex(32);
      expect(verifySessionToken(token1, token2)).toBe(false);
    });
  });

  describe('verifyRefreshToken', () => {
    it('should verify valid refresh token', () => {
      const token = secureRandomHex(32);
      const hash = sha256(token);
      expect(verifyRefreshToken(token, hash)).toBe(true);
    });

    it('should reject invalid refresh token', () => {
      const token = secureRandomHex(32);
      const wrongHash = sha256('wrong_token');
      expect(verifyRefreshToken(token, wrongHash)).toBe(false);
    });
  });

  describe('Property-based tests', () => {
    describe('constantTimeCompare', () => {
      it('should be reflexive (a == a)', () => {
        fc.assert(
          fc.property(fc.string(), (s) => {
            expect(constantTimeCompare(s, s)).toBe(true);
          }),
          { numRuns: 100 }
        );
      });

      it('should be symmetric (a == b implies b == a)', () => {
        fc.assert(
          fc.property(fc.string(), fc.string(), (a, b) => {
            expect(constantTimeCompare(a, b)).toBe(constantTimeCompare(b, a));
          }),
          { numRuns: 100 }
        );
      });

      it('should match standard equality', () => {
        fc.assert(
          fc.property(fc.string(), fc.string(), (a, b) => {
            expect(constantTimeCompare(a, b)).toBe(a === b);
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('constantTimeEqual', () => {
      it('should be reflexive for buffers', () => {
        fc.assert(
          fc.property(fc.uint8Array({ minLength: 0, maxLength: 100 }), (arr) => {
            const buf = Buffer.from(arr);
            expect(constantTimeEqual(buf, Buffer.from(buf))).toBe(true);
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('Hash functions', () => {
      it('sha256 should be deterministic', () => {
        fc.assert(
          fc.property(fc.string(), (s) => {
            expect(sha256(s)).toBe(sha256(s));
          }),
          { numRuns: 100 }
        );
      });

      it('sha512 should be deterministic', () => {
        fc.assert(
          fc.property(fc.string(), (s) => {
            expect(sha512(s)).toBe(sha512(s));
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('HMAC verification', () => {
      it('should verify correctly generated HMACs', () => {
        fc.assert(
          fc.property(
            fc.string({ minLength: 1 }),
            fc.string({ minLength: 1 }),
            (message, secret) => {
              const signature = createHmac(message, secret);
              expect(verifyHmacConstantTime(message, signature, secret)).toBe(true);
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('Token verification', () => {
      it('should verify correctly hashed tokens', () => {
        fc.assert(
          fc.property(fc.string({ minLength: 1 }), (token) => {
            const hash = sha256(token);
            expect(verifyTokenHashConstantTime(token, hash)).toBe(true);
          }),
          { numRuns: 50 }
        );
      });
    });

    describe('Random generation', () => {
      it('should generate unique random bytes', () => {
        fc.assert(
          fc.property(fc.integer({ min: 1, max: 64 }), (length) => {
            const bytes1 = secureRandomBytes(length);
            const bytes2 = secureRandomBytes(length);
            // Very unlikely to be equal for length > 1
            if (length > 1) {
              expect(bytes1.equals(bytes2)).toBe(false);
            }
            return true;
          }),
          { numRuns: 50 }
        );
      });

      it('should generate integers in valid range', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 0, max: 1000 }),
            fc.integer({ min: 1, max: 1000 }),
            (min, range) => {
              const max = min + range;
              const num = secureRandomInt(min, max);
              expect(num).toBeGreaterThanOrEqual(min);
              expect(num).toBeLessThan(max);
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });
  });

  describe('Timing attack resistance', () => {
    it('should take similar time for matching vs non-matching strings', () => {
      const secret = 'super_secret_password_12345678';
      const wrongFirst = 'Xuper_secret_password_12345678';
      const wrongLast = 'super_secret_password_1234567X';

      const iterations = 100;
      const matchTimes: number[] = [];
      const wrongFirstTimes: number[] = [];
      const wrongLastTimes: number[] = [];

      for (let i = 0; i < iterations; i++) {
        let start = process.hrtime.bigint();
        constantTimeCompare(secret, secret);
        matchTimes.push(Number(process.hrtime.bigint() - start));

        start = process.hrtime.bigint();
        constantTimeCompare(secret, wrongFirst);
        wrongFirstTimes.push(Number(process.hrtime.bigint() - start));

        start = process.hrtime.bigint();
        constantTimeCompare(secret, wrongLast);
        wrongLastTimes.push(Number(process.hrtime.bigint() - start));
      }

      const avgMatch = matchTimes.reduce((a, b) => a + b) / iterations;
      const avgWrongFirst = wrongFirstTimes.reduce((a, b) => a + b) / iterations;
      const avgWrongLast = wrongLastTimes.reduce((a, b) => a + b) / iterations;

      // All averages should be within 1ms (1,000,000 nanoseconds) of each other
      const tolerance = 1000000;
      expect(Math.abs(avgMatch - avgWrongFirst)).toBeLessThan(tolerance);
      expect(Math.abs(avgMatch - avgWrongLast)).toBeLessThan(tolerance);
      expect(Math.abs(avgWrongFirst - avgWrongLast)).toBeLessThan(tolerance);
    });
  });
});
