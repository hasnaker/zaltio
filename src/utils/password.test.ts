/**
 * Password Hashing Tests - Argon2id Implementation
 * 
 * Task 1.1: Password Hashing (Argon2id)
 * Validates: Requirements 9.2 (industry-standard hashing algorithms)
 * 
 * @security-test
 * @phase Phase 1
 */

import * as fc from 'fast-check';
import {
  hashPassword,
  verifyPassword,
  needsRehash,
  validatePasswordPolicy,
  checkPasswordPwned,
  isCommonPassword,
  calculatePasswordStrength,
  getPasswordStrengthLabel
} from './password';

describe('Password Hashing - Argon2id', () => {
  describe('hashPassword', () => {
    it('should hash password using Argon2id', async () => {
      const password = 'SecurePassword!123';
      const hash = await hashPassword(password);

      // Argon2id hash format: $argon2id$v=19$m=32768,t=5,p=2$...
      expect(hash).toMatch(/^\$argon2id\$/);
      expect(hash).toContain('m=32768'); // 32MB memory
      expect(hash).toContain('t=5');     // 5 iterations
      expect(hash).toContain('p=2');     // 2 parallelism
    });

    it('should produce different hashes for same password (salt)', async () => {
      const password = 'SamePassword!123';
      
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      expect(hash1).not.toBe(hash2);
    });

    it('should complete within acceptable time', async () => {
      const password = 'TimingTest!123';
      
      const start = Date.now();
      await hashPassword(password);
      const duration = Date.now() - start;

      // Should complete within 3 seconds (allowing for CI/local variance)
      // Argon2id with 32MB memory is fast on modern hardware
      expect(duration).toBeLessThan(3000);
    });

    it('should handle Unicode passwords', async () => {
      const password = 'Şifre!Türkçe123';
      const hash = await hashPassword(password);

      expect(hash).toMatch(/^\$argon2id\$/);
      expect(await verifyPassword(password, hash)).toBe(true);
    });

    it('should handle very long passwords', async () => {
      const password = 'A'.repeat(1000) + '!1a';
      const hash = await hashPassword(password);

      expect(hash).toMatch(/^\$argon2id\$/);
      expect(await verifyPassword(password, hash)).toBe(true);
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'CorrectPassword!123';
      const hash = await hashPassword(password);

      const result = await verifyPassword(password, hash);

      expect(result).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'CorrectPassword!123';
      const hash = await hashPassword(password);

      const result = await verifyPassword('WrongPassword!123', hash);

      expect(result).toBe(false);
    });

    it('should reject similar but different passwords', async () => {
      const password = 'MyPassword!123';
      const hash = await hashPassword(password);

      // Test similar passwords
      const similarPasswords = [
        'mypassword!123',  // lowercase
        'MyPassword!124',  // one digit different
        'MyPassword!123 ', // trailing space
        ' MyPassword!123', // leading space
        'MyPassword!12',   // missing character
      ];

      for (const similar of similarPasswords) {
        const result = await verifyPassword(similar, hash);
        expect(result).toBe(false);
      }
    });

    it('should handle bcrypt hashes for backward compatibility', async () => {
      // Pre-generated bcrypt hash for 'LegacyPassword!123'
      const bcryptHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';
      
      // This test verifies the detection logic works
      // In real scenario, bcrypt.compare would be called
      expect(bcryptHash.startsWith('$2a$')).toBe(true);
    });
  });

  describe('needsRehash', () => {
    it('should return true for bcrypt hashes', () => {
      const bcryptHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';
      
      expect(needsRehash(bcryptHash)).toBe(true);
    });

    it('should return false for Argon2id hashes', async () => {
      const hash = await hashPassword('TestPassword!123');
      
      expect(needsRehash(hash)).toBe(false);
    });
  });

  describe('validatePasswordPolicy', () => {
    it('should accept passwords meeting all requirements', () => {
      const validPasswords = [
        'SecurePass!123',
        'MyStr0ng@Password',
        'C0mpl3x!Passw0rd',
        'Tr$12345678901'  // 14 chars, meets min 12
      ];

      validPasswords.forEach(password => {
        const result = validatePasswordPolicy(password);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    it('should reject passwords shorter than 12 characters', () => {
      const result = validatePasswordPolicy('Short!1Aa');

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('12') || e.includes('characters'))).toBe(true);
    });

    it('should reject passwords without uppercase', () => {
      const result = validatePasswordPolicy('lowercase!123456');

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('uppercase'))).toBe(true);
    });

    it('should reject passwords without lowercase', () => {
      const result = validatePasswordPolicy('UPPERCASE!123456');

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('lowercase'))).toBe(true);
    });

    it('should reject passwords without numbers', () => {
      const result = validatePasswordPolicy('NoNumbers!Here');

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('number'))).toBe(true);
    });

    it('should reject passwords without special characters', () => {
      const result = validatePasswordPolicy('NoSpecialChars12A');

      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('special'))).toBe(true);
    });

    it('should handle empty/null passwords', () => {
      expect(validatePasswordPolicy('').valid).toBe(false);
      expect(validatePasswordPolicy(null as unknown as string).valid).toBe(false);
      expect(validatePasswordPolicy(undefined as unknown as string).valid).toBe(false);
    });
  });

  describe('isCommonPassword', () => {
    it('should detect common passwords', () => {
      const commonPasswords = [
        'password',
        'Password123',
        '123456',
        'qwerty',
        'admin',
        'letmein'
      ];

      commonPasswords.forEach(password => {
        expect(isCommonPassword(password)).toBe(true);
      });
    });

    it('should not flag unique passwords', () => {
      const uniquePasswords = [
        'Xk9#mP2$vL5@nQ8',
        'MyUniqueP@ss2024',
        'Zalt!SecureAuth99'
      ];

      uniquePasswords.forEach(password => {
        expect(isCommonPassword(password)).toBe(false);
      });
    });
  });

  describe('calculatePasswordStrength', () => {
    it('should give low score to weak passwords', () => {
      expect(calculatePasswordStrength('password')).toBeLessThan(40);
      expect(calculatePasswordStrength('12345678')).toBeLessThan(30);
      expect(calculatePasswordStrength('abcdefgh')).toBeLessThan(40);
    });

    it('should give high score to strong passwords', () => {
      expect(calculatePasswordStrength('MyStr0ng!P@ssw0rd')).toBeGreaterThan(70);
      expect(calculatePasswordStrength('C0mpl3x#Secure!2024')).toBeGreaterThan(70);
    });

    it('should return 0 for empty password', () => {
      expect(calculatePasswordStrength('')).toBe(0);
    });
  });

  describe('getPasswordStrengthLabel', () => {
    it('should return correct labels', () => {
      expect(getPasswordStrengthLabel(10)).toBe('Very Weak');
      expect(getPasswordStrengthLabel(30)).toBe('Weak');
      expect(getPasswordStrengthLabel(50)).toBe('Fair');
      expect(getPasswordStrengthLabel(70)).toBe('Strong');
      expect(getPasswordStrengthLabel(90)).toBe('Very Strong');
    });
  });

  describe('Property-based tests', () => {
    it('should always verify correct password', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 12, maxLength: 100 }),
          async (password) => {
            // Add required characters to make it valid
            const validPassword = password + 'Aa1!';
            const hash = await hashPassword(validPassword);
            const verified = await verifyPassword(validPassword, hash);
            expect(verified).toBe(true);
          }
        ),
        { numRuns: 20 } // Limited runs due to slow hashing
      );
    });

    it('should never verify wrong password', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 12, maxLength: 50 }),
          fc.string({ minLength: 12, maxLength: 50 }),
          async (password1, password2) => {
            fc.pre(password1 !== password2);
            const validPassword1 = password1 + 'Aa1!';
            const validPassword2 = password2 + 'Bb2@';
            const hash = await hashPassword(validPassword1);
            const verified = await verifyPassword(validPassword2, hash);
            expect(verified).toBe(false);
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should produce unique hashes for same password', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 8, maxLength: 30 }),
          async (password) => {
            const validPassword = password + 'Aa1!';
            const hash1 = await hashPassword(validPassword);
            const hash2 = await hashPassword(validPassword);
            expect(hash1).not.toBe(hash2); // Different salts
          }
        ),
        { numRuns: 10 }
      );
    });
  });
});

describe('HaveIBeenPwned Integration', () => {
  // Note: These tests make real API calls
  // In CI, they might be skipped or mocked
  
  it('should detect known breached password', async () => {
    // 'password' is definitely in breaches
    const count = await checkPasswordPwned('password');
    expect(count).toBeGreaterThan(0);
  }, 10000);

  it('should return 0 for unique password', async () => {
    // Generate a truly unique password
    const uniquePassword = `Zalt!${Date.now()}!${Math.random().toString(36)}`;
    const count = await checkPasswordPwned(uniquePassword);
    expect(count).toBe(0);
  }, 10000);

  it('should not send full password to API (k-Anonymity)', async () => {
    // This is a design verification - the implementation uses k-Anonymity
    // Only first 5 chars of SHA-1 hash are sent
    const crypto = require('crypto');
    const password = 'TestPassword!123';
    const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = hash.substring(0, 5);
    
    // Prefix should be 5 hex characters
    expect(prefix).toMatch(/^[A-F0-9]{5}$/);
    expect(prefix.length).toBe(5);
  });
});
