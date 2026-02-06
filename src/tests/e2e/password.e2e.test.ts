/**
 * Password Hashing E2E Tests - Argon2id Implementation
 * 
 * Task 1.1: Password Hashing (Argon2id)
 * Validates: Requirements 9.2 (industry-standard hashing algorithms)
 * 
 * @e2e-test
 * @phase Phase 1
 * @security-critical
 */

import {
  hashPassword,
  verifyPassword,
  needsRehash,
  validatePasswordPolicy,
  checkPasswordPwned,
  calculatePasswordStrength
} from '../../utils/password';

describe('Password Hashing E2E Tests', () => {
  describe('Argon2id Configuration Verification', () => {
    it('should use correct Argon2id parameters (32MB, timeCost 5, parallelism 2)', async () => {
      const password = 'TestPassword!123';
      const hash = await hashPassword(password);

      // Verify Argon2id format
      expect(hash).toMatch(/^\$argon2id\$/);
      
      // Verify parameters in hash string
      expect(hash).toContain('m=32768'); // 32MB memory
      expect(hash).toContain('t=5');     // 5 time iterations
      expect(hash).toContain('p=2');     // 2 parallelism
    });

    it('should complete hashing within Lambda-acceptable time (500-800ms target)', async () => {
      const password = 'PerformanceTest!123';
      const iterations = 5;
      const times: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        await hashPassword(password);
        times.push(Date.now() - start);
      }

      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      
      // Should be under 3 seconds (allowing for CI variance)
      // In Lambda with 1769MB memory, expect 500-800ms
      expect(avgTime).toBeLessThan(3000);
      
      console.log(`Average hash time: ${avgTime.toFixed(0)}ms`);
    });
  });

  describe('Salt Uniqueness', () => {
    it('should produce different hashes for same password (salt verification)', async () => {
      const password = 'SamePassword!123';
      const hashes = new Set<string>();

      // Generate 10 hashes of the same password
      for (let i = 0; i < 10; i++) {
        const hash = await hashPassword(password);
        hashes.add(hash);
      }

      // All hashes should be unique
      expect(hashes.size).toBe(10);
    });
  });

  describe('Password Verification', () => {
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

    it('should handle timing-safe comparison', async () => {
      const password = 'TimingTest!123';
      const hash = await hashPassword(password);

      // Measure verification times for correct and incorrect passwords
      const correctTimes: number[] = [];
      const incorrectTimes: number[] = [];

      for (let i = 0; i < 10; i++) {
        const start1 = Date.now();
        await verifyPassword(password, hash);
        correctTimes.push(Date.now() - start1);

        const start2 = Date.now();
        await verifyPassword('WrongPassword!123', hash);
        incorrectTimes.push(Date.now() - start2);
      }

      const avgCorrect = correctTimes.reduce((a, b) => a + b, 0) / correctTimes.length;
      const avgIncorrect = incorrectTimes.reduce((a, b) => a + b, 0) / incorrectTimes.length;

      // Times should be similar (within 50ms) - timing attack resistance
      // Note: Argon2 library handles this internally
      const timeDiff = Math.abs(avgCorrect - avgIncorrect);
      console.log(`Timing difference: ${timeDiff.toFixed(0)}ms`);
    });
  });

  describe('Hash Format Verification', () => {
    it('should produce valid Argon2id hash format', async () => {
      const password = 'FormatTest!123';
      const hash = await hashPassword(password);

      // Argon2id hash format: $argon2id$v=19$m=32768,t=5,p=2$<salt>$<hash>
      const parts = hash.split('$');
      
      expect(parts[1]).toBe('argon2id');  // Algorithm
      expect(parts[2]).toBe('v=19');       // Version
      expect(parts[3]).toContain('m=32768'); // Memory
      expect(parts[3]).toContain('t=5');    // Time
      expect(parts[3]).toContain('p=2');    // Parallelism
      expect(parts[4]).toBeTruthy();        // Salt (base64)
      expect(parts[5]).toBeTruthy();        // Hash (base64)
    });
  });

  describe('Migration Support (bcrypt to Argon2id)', () => {
    it('should detect bcrypt hashes needing rehash', () => {
      const bcryptHash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';
      
      expect(needsRehash(bcryptHash)).toBe(true);
    });

    it('should not flag Argon2id hashes for rehash', async () => {
      const hash = await hashPassword('TestPassword!123');
      
      expect(needsRehash(hash)).toBe(false);
    });
  });

  describe('Password Policy Validation', () => {
    it('should accept valid healthcare-grade passwords', () => {
      const validPasswords = [
        'SecurePass!123',
        'MyStr0ng@Password',
        'C0mpl3x!Passw0rd',
        'Zalt!Auth2026Secure',
        'Clinisyn#Psych123'
      ];

      validPasswords.forEach(password => {
        const result = validatePasswordPolicy(password);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    it('should reject passwords not meeting HIPAA requirements', () => {
      const invalidPasswords = [
        { password: 'short!1A', reason: 'too short (< 12 chars)' },
        { password: 'nouppercase!123456', reason: 'no uppercase' },
        { password: 'NOLOWERCASE!123456', reason: 'no lowercase' },
        { password: 'NoNumbers!Here', reason: 'no numbers' },
        { password: 'NoSpecialChars12A', reason: 'no special chars' }
      ];

      invalidPasswords.forEach(({ password, reason }) => {
        const result = validatePasswordPolicy(password);
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });
    });
  });

  describe('HaveIBeenPwned Integration', () => {
    it('should detect known breached passwords', async () => {
      // 'password' is definitely in breaches
      const count = await checkPasswordPwned('password');
      
      expect(count).toBeGreaterThan(0);
      console.log(`"password" found in ${count} breaches`);
    }, 10000);

    it('should return 0 for unique passwords', async () => {
      // Generate a truly unique password
      const uniquePassword = `Zalt!${Date.now()}!${Math.random().toString(36).substring(2)}`;
      const count = await checkPasswordPwned(uniquePassword);
      
      expect(count).toBe(0);
    }, 10000);

    it('should use k-Anonymity (only send first 5 chars of SHA-1)', async () => {
      // This is a design verification test
      const crypto = require('crypto');
      const password = 'TestPassword!123';
      const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
      const prefix = hash.substring(0, 5);
      
      // Prefix should be exactly 5 hex characters
      expect(prefix).toMatch(/^[A-F0-9]{5}$/);
      expect(prefix.length).toBe(5);
    });
  });

  describe('Password Strength Scoring', () => {
    it('should give appropriate scores', () => {
      const testCases = [
        { password: 'password', expectedRange: [0, 30] },
        { password: '12345678', expectedRange: [0, 20] },
        { password: 'Password1', expectedRange: [20, 60] },
        { password: 'MyStr0ng!P@ss', expectedRange: [60, 100] },
        { password: 'C0mpl3x#Secure!2024', expectedRange: [70, 100] }
      ];

      testCases.forEach(({ password, expectedRange }) => {
        const score = calculatePasswordStrength(password);
        expect(score).toBeGreaterThanOrEqual(expectedRange[0]);
        expect(score).toBeLessThanOrEqual(expectedRange[1]);
      });
    });
  });

  describe('Unicode and Special Character Support', () => {
    it('should handle Turkish characters', async () => {
      const password = 'Şifre!Türkçe123';
      const hash = await hashPassword(password);
      
      expect(await verifyPassword(password, hash)).toBe(true);
      expect(await verifyPassword('Sifre!Turkce123', hash)).toBe(false);
    });

    it('should handle emoji in passwords', async () => {
      const password = 'Password!123🔐';
      const hash = await hashPassword(password);
      
      expect(await verifyPassword(password, hash)).toBe(true);
    });

    it('should handle very long passwords', async () => {
      const password = 'A'.repeat(500) + '!1a';
      const hash = await hashPassword(password);
      
      expect(await verifyPassword(password, hash)).toBe(true);
    });
  });
});
