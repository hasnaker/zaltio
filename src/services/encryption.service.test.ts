/**
 * Data Encryption Service - Property Tests
 * Feature: zalt-platform, Property 14: Data Encryption Completeness
 * Validates: Requirements 8.2, 9.2
 * 
 * Tests that sensitive data (passwords, tokens, PII) is encrypted using
 * approved algorithms both at rest in storage and in transit over networks.
 */

import * as fc from 'fast-check';
import {
  encryptData,
  decryptData,
  isSensitiveField,
  encryptSensitiveFields,
  decryptSensitiveFields,
  generateSecureToken,
  hashData,
  createHmacSignature,
  verifyHmacSignature,
  maskSensitiveData,
  EncryptedData
} from './encryption.service';
import { ENCRYPTION_CONFIG } from '../config/security.config';

describe('Data Encryption - Property Tests', () => {
  describe('Property 14: Data Encryption Completeness', () => {
    /**
     * Property: Round-trip encryption/decryption preserves data
     * For any plaintext string, encrypting then decrypting should return the original value
     */
    it('should preserve data through encryption/decryption round-trip', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 1000 }),
          async (plaintext) => {
            const encrypted = await encryptData(plaintext);
            const decrypted = await decryptData(encrypted);
            
            expect(decrypted).toBe(plaintext);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Encrypted data has correct structure
     * For any plaintext, the encrypted result should contain ciphertext, iv, authTag, and version
     */
    it('should produce encrypted data with correct structure', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 500 }),
          async (plaintext) => {
            const encrypted = await encryptData(plaintext);
            
            // Verify structure
            expect(encrypted).toHaveProperty('ciphertext');
            expect(encrypted).toHaveProperty('iv');
            expect(encrypted).toHaveProperty('authTag');
            expect(encrypted).toHaveProperty('version');
            
            // Verify types
            expect(typeof encrypted.ciphertext).toBe('string');
            expect(typeof encrypted.iv).toBe('string');
            expect(typeof encrypted.authTag).toBe('string');
            expect(typeof encrypted.version).toBe('number');
            
            // Verify non-empty
            expect(encrypted.ciphertext.length).toBeGreaterThan(0);
            expect(encrypted.iv.length).toBeGreaterThan(0);
            expect(encrypted.authTag.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Each encryption produces unique ciphertext
     * For the same plaintext, each encryption should produce different ciphertext (due to random IV)
     */
    it('should produce unique ciphertext for each encryption', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 200 }),
          async (plaintext) => {
            const encrypted1 = await encryptData(plaintext);
            const encrypted2 = await encryptData(plaintext);
            
            // Ciphertext should be different due to random IV
            expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
            expect(encrypted1.iv).not.toBe(encrypted2.iv);
            
            // But both should decrypt to the same value
            const decrypted1 = await decryptData(encrypted1);
            const decrypted2 = await decryptData(encrypted2);
            expect(decrypted1).toBe(decrypted2);
            expect(decrypted1).toBe(plaintext);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Sensitive fields are correctly identified
     * All fields in ENCRYPTION_CONFIG.sensitiveFields should be identified as sensitive
     */
    it('should correctly identify all sensitive fields', () => {
      for (const field of ENCRYPTION_CONFIG.sensitiveFields) {
        expect(isSensitiveField(field)).toBe(true);
      }
    });

    /**
     * Property: Non-sensitive fields are not encrypted
     */
    it('should not identify non-sensitive fields as sensitive', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }).filter(
            s => !(ENCRYPTION_CONFIG.sensitiveFields as readonly string[]).includes(s)
          ),
          (fieldName) => {
            expect(isSensitiveField(fieldName)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Sensitive fields in objects are encrypted
     */
    it('should encrypt sensitive fields in objects', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            id: fc.uuid(),
            email: fc.emailAddress(),
            password_hash: fc.string({ minLength: 10, maxLength: 100 }),
            refresh_token: fc.string({ minLength: 20, maxLength: 200 }),
            name: fc.string({ minLength: 1, maxLength: 50 })
          }),
          async (data) => {
            const encrypted = await encryptSensitiveFields(data);
            
            // Non-sensitive fields should remain unchanged
            expect(encrypted.id).toBe(data.id);
            expect(encrypted.email).toBe(data.email);
            expect(encrypted.name).toBe(data.name);
            
            // Sensitive fields should be encrypted (JSON string)
            if (data.password_hash) {
              expect(encrypted.password_hash).not.toBe(data.password_hash);
              const parsed = JSON.parse(encrypted.password_hash as string) as EncryptedData;
              expect(parsed).toHaveProperty('ciphertext');
            }
            
            if (data.refresh_token) {
              expect(encrypted.refresh_token).not.toBe(data.refresh_token);
              const parsed = JSON.parse(encrypted.refresh_token as string) as EncryptedData;
              expect(parsed).toHaveProperty('ciphertext');
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Encrypted fields can be decrypted back
     */
    it('should decrypt sensitive fields back to original values', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            id: fc.uuid(),
            password_hash: fc.string({ minLength: 10, maxLength: 100 }),
            refresh_token: fc.string({ minLength: 20, maxLength: 200 })
          }),
          async (data) => {
            const encrypted = await encryptSensitiveFields(data);
            const decrypted = await decryptSensitiveFields(encrypted);
            
            expect(decrypted.id).toBe(data.id);
            expect(decrypted.password_hash).toBe(data.password_hash);
            expect(decrypted.refresh_token).toBe(data.refresh_token);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Secure tokens have sufficient entropy
     */
    it('should generate secure tokens with sufficient length', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 16, max: 64 }),
          (length) => {
            const token = generateSecureToken(length);
            
            // Base64url encoding produces ~4/3 the length
            expect(token.length).toBeGreaterThanOrEqual(length);
            
            // Should only contain base64url characters
            expect(/^[A-Za-z0-9_-]+$/.test(token)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Generated tokens are unique
     */
    it('should generate unique tokens', () => {
      const tokens = new Set<string>();
      
      for (let i = 0; i < 100; i++) {
        const token = generateSecureToken(32);
        expect(tokens.has(token)).toBe(false);
        tokens.add(token);
      }
    });

    /**
     * Property: Hash function is deterministic
     */
    it('should produce consistent hashes for same input', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 500 }),
          (data) => {
            const hash1 = hashData(data);
            const hash2 = hashData(data);
            
            expect(hash1).toBe(hash2);
            expect(hash1.length).toBe(64); // SHA-256 produces 64 hex chars
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Different inputs produce different hashes
     */
    it('should produce different hashes for different inputs', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 200 }),
          fc.string({ minLength: 1, maxLength: 200 }),
          (data1, data2) => {
            fc.pre(data1 !== data2);
            
            const hash1 = hashData(data1);
            const hash2 = hashData(data2);
            
            expect(hash1).not.toBe(hash2);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: HMAC signatures can be verified
     */
    it('should verify valid HMAC signatures', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 500 }),
          async (data) => {
            const signature = await createHmacSignature(data);
            const isValid = await verifyHmacSignature(data, signature);
            
            expect(isValid).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: HMAC signatures reject tampered data
     */
    it('should reject HMAC signatures for tampered data', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 200 }),
          fc.string({ minLength: 1, maxLength: 200 }),
          async (data, tamperedData) => {
            fc.pre(data !== tamperedData);
            
            const signature = await createHmacSignature(data);
            const isValid = await verifyHmacSignature(tamperedData, signature);
            
            expect(isValid).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Sensitive data masking hides most characters
     */
    it('should mask sensitive data correctly', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 5, maxLength: 100 }),
          fc.integer({ min: 1, max: 4 }),
          (data, visibleChars) => {
            const masked = maskSensitiveData(data, visibleChars);
            
            // Should have same length
            expect(masked.length).toBe(data.length);
            
            // Should end with visible characters from original
            expect(masked.slice(-visibleChars)).toBe(data.slice(-visibleChars));
            
            // Rest should be asterisks
            const maskedPart = masked.slice(0, -visibleChars);
            expect(maskedPart).toBe('*'.repeat(data.length - visibleChars));
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Tampered ciphertext fails decryption
     */
    it('should fail decryption for tampered ciphertext', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 10, maxLength: 100 }),
          async (plaintext) => {
            const encrypted = await encryptData(plaintext);
            
            // Tamper with ciphertext
            const tamperedCiphertext = encrypted.ciphertext.slice(0, -4) + 'XXXX';
            const tampered: EncryptedData = {
              ...encrypted,
              ciphertext: tamperedCiphertext
            };
            
            await expect(decryptData(tampered)).rejects.toThrow();
          }
        ),
        { numRuns: 50 }
      );
    });

    /**
     * Property: Tampered auth tag fails decryption
     */
    it('should fail decryption for tampered auth tag', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 10, maxLength: 100 }),
          async (plaintext) => {
            const encrypted = await encryptData(plaintext);
            
            // Tamper with auth tag
            const tamperedAuthTag = encrypted.authTag.slice(0, -4) + 'XXXX';
            const tampered: EncryptedData = {
              ...encrypted,
              authTag: tamperedAuthTag
            };
            
            await expect(decryptData(tampered)).rejects.toThrow();
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
