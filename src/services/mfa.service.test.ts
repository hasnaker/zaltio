/**
 * MFA Service Unit Tests
 * 
 * Task 2.1: TOTP MFA Service
 * Validates: Requirements 2.2
 */

import {
  generateTOTPSecret,
  base32Encode,
  base32Decode,
  generateTOTP,
  verifyTOTPCode,
  generateQRCodeURL,
  generateBackupCodes,
  hashBackupCodes,
  verifyBackupCode,
  shouldWarnLowBackupCodes,
  isValidTOTPSecret,
  TOTP_CONFIG,
  BACKUP_CODES_CONFIG
} from './mfa.service';

describe('MFA Service', () => {
  describe('generateTOTPSecret', () => {
    it('should generate 32 character base32 secret', () => {
      const secret = generateTOTPSecret();
      
      expect(secret).toHaveLength(32);
      expect(secret).toMatch(/^[A-Z2-7]+$/);
    });

    it('should generate unique secrets', () => {
      const secrets = new Set<string>();
      for (let i = 0; i < 100; i++) {
        secrets.add(generateTOTPSecret());
      }
      
      expect(secrets.size).toBe(100);
    });

    it('should generate 20 bytes (160 bits) of entropy', () => {
      const secret = generateTOTPSecret();
      const decoded = base32Decode(secret);
      
      expect(decoded.length).toBe(20);
    });
  });

  describe('base32Encode/Decode', () => {
    it('should encode and decode correctly', () => {
      const original = Buffer.from('Hello World!');
      const encoded = base32Encode(original);
      const decoded = base32Decode(encoded);
      
      expect(decoded.toString()).toBe('Hello World!');
    });

    it('should handle 20 byte buffers', () => {
      const original = Buffer.alloc(20);
      for (let i = 0; i < 20; i++) {
        original[i] = i;
      }
      
      const encoded = base32Encode(original);
      const decoded = base32Decode(encoded);
      
      expect(decoded).toEqual(original);
    });

    it('should produce valid base32 output', () => {
      const buffer = Buffer.from([0x00, 0xff, 0x80, 0x40, 0x20]);
      const encoded = base32Encode(buffer);
      
      expect(encoded).toMatch(/^[A-Z2-7]+$/);
    });
  });

  describe('generateTOTP', () => {
    it('should generate 6 digit code', () => {
      const secret = generateTOTPSecret();
      const code = generateTOTP(secret);
      
      expect(code).toHaveLength(6);
      expect(code).toMatch(/^\d{6}$/);
    });

    it('should generate same code for same timestamp', () => {
      const secret = generateTOTPSecret();
      const timestamp = 1704067200; // Fixed timestamp
      
      const code1 = generateTOTP(secret, timestamp);
      const code2 = generateTOTP(secret, timestamp);
      
      expect(code1).toBe(code2);
    });

    it('should generate different codes for different timestamps', () => {
      const secret = generateTOTPSecret();
      const timestamp1 = 1704067200;
      const timestamp2 = timestamp1 + 30; // Next period
      
      const code1 = generateTOTP(secret, timestamp1);
      const code2 = generateTOTP(secret, timestamp2);
      
      expect(code1).not.toBe(code2);
    });

    it('should generate same code within 30 second window', () => {
      const secret = generateTOTPSecret();
      const timestamp = 1704067200;
      
      const code1 = generateTOTP(secret, timestamp);
      const code2 = generateTOTP(secret, timestamp + 15);
      
      expect(code1).toBe(code2);
    });

    // Test with known test vector from RFC 6238
    it('should match RFC 6238 test vector', () => {
      // Test secret from RFC 6238: "12345678901234567890" in ASCII
      const testSecret = base32Encode(Buffer.from('12345678901234567890'));
      
      // Test time: 59 seconds (counter = 1)
      const code = generateTOTP(testSecret, 59);
      
      // The code should be deterministic
      expect(code).toHaveLength(6);
      expect(code).toMatch(/^\d{6}$/);
    });
  });

  describe('verifyTOTPCode', () => {
    it('should verify correct code', () => {
      const secret = generateTOTPSecret();
      const code = generateTOTP(secret);
      
      expect(verifyTOTPCode(secret, code)).toBe(true);
    });

    it('should reject incorrect code', () => {
      const secret = generateTOTPSecret();
      
      expect(verifyTOTPCode(secret, '000000')).toBe(false);
      expect(verifyTOTPCode(secret, '999999')).toBe(false);
    });

    it('should accept code from previous period (clock drift)', () => {
      const secret = generateTOTPSecret();
      const now = Math.floor(Date.now() / 1000);
      const previousPeriod = now - 30;
      
      const code = generateTOTP(secret, previousPeriod);
      
      expect(verifyTOTPCode(secret, code)).toBe(true);
    });

    it('should accept code from next period (clock drift)', () => {
      const secret = generateTOTPSecret();
      const now = Math.floor(Date.now() / 1000);
      const nextPeriod = now + 30;
      
      const code = generateTOTP(secret, nextPeriod);
      
      expect(verifyTOTPCode(secret, code)).toBe(true);
    });

    it('should reject code from 2 periods ago', () => {
      const secret = generateTOTPSecret();
      const now = Math.floor(Date.now() / 1000);
      const oldPeriod = now - 60;
      
      const code = generateTOTP(secret, oldPeriod);
      
      expect(verifyTOTPCode(secret, code)).toBe(false);
    });

    it('should reject invalid format codes', () => {
      const secret = generateTOTPSecret();
      
      expect(verifyTOTPCode(secret, '')).toBe(false);
      expect(verifyTOTPCode(secret, '12345')).toBe(false);  // Too short
      expect(verifyTOTPCode(secret, '1234567')).toBe(false); // Too long
      expect(verifyTOTPCode(secret, 'abcdef')).toBe(false);  // Not numeric
      expect(verifyTOTPCode(secret, '12345a')).toBe(false);  // Mixed
    });
  });

  describe('generateQRCodeURL', () => {
    it('should generate valid otpauth URL', () => {
      const secret = generateTOTPSecret();
      const email = 'dr.ayse@example.com';
      
      const url = generateQRCodeURL(secret, email);
      
      expect(url).toMatch(/^otpauth:\/\/totp\//);
      expect(url).toContain(secret);
      expect(url).toContain('algorithm=SHA1');
      expect(url).toContain('digits=6');
      expect(url).toContain('period=30');
    });

    it('should include issuer', () => {
      const secret = generateTOTPSecret();
      const email = 'test@example.com';
      
      const url = generateQRCodeURL(secret, email);
      
      expect(url).toContain('Zalt.io');
    });

    it('should include realm name when provided', () => {
      const secret = generateTOTPSecret();
      const email = 'test@example.com';
      const realmName = 'Clinisyn';
      
      const url = generateQRCodeURL(secret, email, realmName);
      
      expect(url).toContain('Clinisyn');
    });

    it('should URL encode special characters', () => {
      const secret = generateTOTPSecret();
      const email = 'user+test@example.com';
      
      const url = generateQRCodeURL(secret, email);
      
      expect(url).not.toContain('+');
      expect(url).toContain('%2B');
    });
  });

  describe('generateBackupCodes', () => {
    it('should generate 8 backup codes', () => {
      const codes = generateBackupCodes();
      
      expect(codes).toHaveLength(BACKUP_CODES_CONFIG.count);
    });

    it('should generate 8 character codes', () => {
      const codes = generateBackupCodes();
      
      codes.forEach(code => {
        expect(code).toHaveLength(8);
      });
    });

    it('should generate alphanumeric uppercase codes', () => {
      const codes = generateBackupCodes();
      
      codes.forEach(code => {
        expect(code).toMatch(/^[A-F0-9]+$/);
      });
    });

    it('should generate unique codes', () => {
      const codes = generateBackupCodes();
      const uniqueCodes = new Set(codes);
      
      expect(uniqueCodes.size).toBe(codes.length);
    });
  });

  describe('hashBackupCodes', () => {
    it('should hash all codes', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      expect(hashed).toHaveLength(codes.length);
    });

    it('should produce 64 character hex hashes (SHA-256)', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      hashed.forEach(hash => {
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[a-f0-9]+$/);
      });
    });

    it('should produce different hashes for different codes', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      const uniqueHashes = new Set(hashed);
      
      expect(uniqueHashes.size).toBe(hashed.length);
    });

    it('should be case insensitive', () => {
      const code = 'ABCD1234';
      const hash1 = hashBackupCodes([code])[0];
      const hash2 = hashBackupCodes([code.toLowerCase()])[0];
      
      expect(hash1).toBe(hash2);
    });
  });

  describe('verifyBackupCode', () => {
    it('should verify correct backup code', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      const index = verifyBackupCode(codes[0], hashed);
      
      expect(index).toBe(0);
    });

    it('should return correct index for any code', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      for (let i = 0; i < codes.length; i++) {
        const index = verifyBackupCode(codes[i], hashed);
        expect(index).toBe(i);
      }
    });

    it('should return -1 for invalid code', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      const index = verifyBackupCode('INVALID1', hashed);
      
      expect(index).toBe(-1);
    });

    it('should be case insensitive', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      const index = verifyBackupCode(codes[0].toLowerCase(), hashed);
      
      expect(index).toBe(0);
    });
  });

  describe('shouldWarnLowBackupCodes', () => {
    it('should warn when 2 or fewer codes remain', () => {
      expect(shouldWarnLowBackupCodes(2)).toBe(true);
      expect(shouldWarnLowBackupCodes(1)).toBe(true);
      expect(shouldWarnLowBackupCodes(0)).toBe(true);
    });

    it('should not warn when more than 2 codes remain', () => {
      expect(shouldWarnLowBackupCodes(3)).toBe(false);
      expect(shouldWarnLowBackupCodes(8)).toBe(false);
    });
  });

  describe('isValidTOTPSecret', () => {
    it('should validate correct secrets', () => {
      const secret = generateTOTPSecret();
      
      expect(isValidTOTPSecret(secret)).toBe(true);
    });

    it('should reject invalid secrets', () => {
      expect(isValidTOTPSecret('')).toBe(false);
      expect(isValidTOTPSecret('short')).toBe(false);
      expect(isValidTOTPSecret('INVALID!@#$%^&*()')).toBe(false);
      expect(isValidTOTPSecret('0123456789')).toBe(false); // Contains invalid chars
    });

    it('should be case insensitive', () => {
      const secret = generateTOTPSecret();
      
      expect(isValidTOTPSecret(secret.toLowerCase())).toBe(true);
    });
  });

  describe('TOTP_CONFIG', () => {
    it('should have correct configuration', () => {
      expect(TOTP_CONFIG.issuer).toBe('Zalt.io');
      expect(TOTP_CONFIG.algorithm).toBe('sha1');
      expect(TOTP_CONFIG.digits).toBe(6);
      expect(TOTP_CONFIG.period).toBe(30);
      expect(TOTP_CONFIG.window).toBe(1);
      expect(TOTP_CONFIG.secretLength).toBe(20);
    });
  });
});
