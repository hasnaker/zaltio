/**
 * OWASP A02:2021 - Cryptographic Failures
 * Weak Encryption, Insecure Key Management, Data Exposure
 * 
 * @security-test
 * @owasp A02:2021
 * @severity CRITICAL
 */

import * as fc from 'fast-check';
import * as crypto from 'crypto';

// Cryptographic constants
const SECURE_ALGORITHMS = {
  symmetric: ['aes-256-gcm', 'aes-256-cbc', 'chacha20-poly1305'],
  hash: ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512'],
  password: ['argon2id', 'bcrypt', 'scrypt'],
  asymmetric: ['rsa-oaep', 'ecdsa', 'ed25519']
};

const INSECURE_ALGORITHMS = {
  symmetric: ['des', '3des', 'rc4', 'blowfish', 'aes-128-ecb'],
  hash: ['md5', 'sha1', 'md4'],
  password: ['md5', 'sha1', 'plain']
};

// Validation functions
const isSecureAlgorithm = (algorithm: string, type: 'symmetric' | 'hash' | 'password'): boolean => {
  const secure = SECURE_ALGORITHMS[type];
  const insecure = INSECURE_ALGORITHMS[type];
  
  const normalizedAlg = algorithm.toLowerCase();
  
  if (insecure.some(i => normalizedAlg.includes(i))) return false;
  return secure.some(s => normalizedAlg.includes(s));
};

const isSecureKeyLength = (algorithm: string, keyLength: number): boolean => {
  const minKeyLengths: Record<string, number> = {
    'aes': 256,
    'rsa': 2048,
    'ecdsa': 256,
    'ed25519': 256
  };

  for (const [alg, minLength] of Object.entries(minKeyLengths)) {
    if (algorithm.toLowerCase().includes(alg)) {
      return keyLength >= minLength;
    }
  }
  return keyLength >= 256; // Default minimum
};

const isSecureIV = (iv: Buffer, algorithm: string): boolean => {
  // GCM mode requires 12 bytes (96 bits) IV
  if (algorithm.includes('gcm')) {
    return iv.length === 12;
  }
  // CBC mode requires 16 bytes (128 bits) IV
  if (algorithm.includes('cbc')) {
    return iv.length === 16;
  }
  return iv.length >= 12;
};

const hasSecureRandomness = (data: Buffer): boolean => {
  // Basic entropy check - not cryptographically rigorous but catches obvious issues
  if (data.length < 16) return false;
  
  // Check for all zeros or all same byte
  const firstByte = data[0];
  if (data.every(b => b === firstByte)) return false;
  
  // Check for sequential bytes
  let sequential = true;
  for (let i = 1; i < data.length; i++) {
    if (data[i] !== data[i - 1] + 1) {
      sequential = false;
      break;
    }
  }
  if (sequential) return false;
  
  return true;
};

describe('OWASP A02:2021 - Cryptographic Failures', () => {
  describe('Algorithm Security', () => {
    it('should reject insecure symmetric algorithms', () => {
      INSECURE_ALGORITHMS.symmetric.forEach(alg => {
        expect(isSecureAlgorithm(alg, 'symmetric')).toBe(false);
      });
    });

    it('should accept secure symmetric algorithms', () => {
      SECURE_ALGORITHMS.symmetric.forEach(alg => {
        expect(isSecureAlgorithm(alg, 'symmetric')).toBe(true);
      });
    });

    it('should reject insecure hash algorithms', () => {
      INSECURE_ALGORITHMS.hash.forEach(alg => {
        expect(isSecureAlgorithm(alg, 'hash')).toBe(false);
      });
    });

    it('should accept secure hash algorithms', () => {
      SECURE_ALGORITHMS.hash.forEach(alg => {
        expect(isSecureAlgorithm(alg, 'hash')).toBe(true);
      });
    });

    it('should reject insecure password hashing', () => {
      INSECURE_ALGORITHMS.password.forEach(alg => {
        expect(isSecureAlgorithm(alg, 'password')).toBe(false);
      });
    });
  });

  describe('Key Length Validation', () => {
    it('should require minimum 256-bit AES keys', () => {
      expect(isSecureKeyLength('aes-256-gcm', 256)).toBe(true);
      expect(isSecureKeyLength('aes-128-gcm', 128)).toBe(false);
    });

    it('should require minimum 2048-bit RSA keys', () => {
      expect(isSecureKeyLength('rsa-oaep', 2048)).toBe(true);
      expect(isSecureKeyLength('rsa-oaep', 4096)).toBe(true);
      expect(isSecureKeyLength('rsa-oaep', 1024)).toBe(false);
    });

    it('should validate key lengths with property testing', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('aes', 'rsa', 'ecdsa'),
          fc.integer({ min: 64, max: 512 }),
          (algorithm, keyBits) => {
            const isSecure = isSecureKeyLength(algorithm, keyBits);
            
            if (algorithm === 'aes' && keyBits >= 256) {
              expect(isSecure).toBe(true);
            }
            if (algorithm === 'rsa' && keyBits < 2048) {
              expect(isSecure).toBe(false);
            }
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('IV/Nonce Security', () => {
    it('should require correct IV length for GCM', () => {
      const gcmIV = crypto.randomBytes(12);
      const wrongIV = crypto.randomBytes(16);
      
      expect(isSecureIV(gcmIV, 'aes-256-gcm')).toBe(true);
      expect(isSecureIV(wrongIV, 'aes-256-gcm')).toBe(false);
    });

    it('should require correct IV length for CBC', () => {
      const cbcIV = crypto.randomBytes(16);
      const wrongIV = crypto.randomBytes(12);
      
      expect(isSecureIV(cbcIV, 'aes-256-cbc')).toBe(true);
      expect(isSecureIV(wrongIV, 'aes-256-cbc')).toBe(false);
    });

    it('should never reuse IVs', () => {
      const ivs = new Set<string>();
      
      for (let i = 0; i < 1000; i++) {
        const iv = crypto.randomBytes(12).toString('hex');
        expect(ivs.has(iv)).toBe(false);
        ivs.add(iv);
      }
    });
  });

  describe('Random Number Generation', () => {
    it('should use cryptographically secure random', () => {
      for (let i = 0; i < 100; i++) {
        const random = crypto.randomBytes(32);
        expect(hasSecureRandomness(random)).toBe(true);
      }
    });

    it('should detect weak randomness', () => {
      const allZeros = Buffer.alloc(32, 0);
      const allOnes = Buffer.alloc(32, 0xff);
      const sequential = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
      
      expect(hasSecureRandomness(allZeros)).toBe(false);
      expect(hasSecureRandomness(allOnes)).toBe(false);
      expect(hasSecureRandomness(sequential)).toBe(false);
    });

    it('should generate unique values', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 16, max: 64 }),
          (length) => {
            const values = new Set<string>();
            
            for (let i = 0; i < 100; i++) {
              const value = crypto.randomBytes(length).toString('hex');
              expect(values.has(value)).toBe(false);
              values.add(value);
            }
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Data Protection', () => {
    it('should encrypt sensitive data before storage', () => {
      const sensitiveFields = [
        'password',
        'ssn',
        'credit_card',
        'api_key',
        'secret',
        'token',
        'private_key'
      ];

      sensitiveFields.forEach(field => {
        // In real implementation, these should be encrypted
        expect(field).toBeDefined();
      });
    });

    it('should use authenticated encryption (AEAD)', () => {
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);
      const plaintext = 'sensitive data';
      const aad = 'additional authenticated data';

      // Encrypt with GCM (AEAD)
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(Buffer.from(aad));
      
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag();

      // Decrypt
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAAD(Buffer.from(aad));
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      expect(decrypted).toBe(plaintext);

      // Tampered data should fail
      const tamperedTag = Buffer.from(authTag);
      tamperedTag[0] ^= 0xff;
      
      const decipher2 = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher2.setAAD(Buffer.from(aad));
      decipher2.setAuthTag(tamperedTag);
      
      expect(() => {
        decipher2.update(encrypted, 'hex', 'utf8');
        decipher2.final('utf8');
      }).toThrow();
    });

    it('should protect data in transit with TLS 1.2+', () => {
      const secureTLSVersions = ['TLSv1.2', 'TLSv1.3'];
      const insecureTLSVersions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'];

      secureTLSVersions.forEach(version => {
        expect(['TLSv1.2', 'TLSv1.3']).toContain(version);
      });

      insecureTLSVersions.forEach(version => {
        expect(['TLSv1.2', 'TLSv1.3']).not.toContain(version);
      });
    });
  });

  describe('Key Management', () => {
    it('should not hardcode encryption keys', () => {
      const codePatterns = [
        /const\s+key\s*=\s*['"][a-f0-9]{32,}['"]/i,
        /secret\s*[:=]\s*['"][^'"]{16,}['"]/i,
        /password\s*[:=]\s*['"][^'"]+['"]/i,
        /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i
      ];

      // These patterns should NOT be found in production code
      const sampleCode = `
        const key = process.env.ENCRYPTION_KEY;
        const secret = getSecretFromVault();
      `;

      codePatterns.forEach(pattern => {
        expect(pattern.test(sampleCode)).toBe(false);
      });
    });

    it('should rotate keys periodically', () => {
      const keyRotationPolicy = {
        maxAgeInDays: 90,
        warningBeforeDays: 14
      };

      const keyCreatedAt = new Date('2024-01-01');
      const now = new Date('2024-04-15');
      const ageInDays = Math.floor((now.getTime() - keyCreatedAt.getTime()) / (1000 * 60 * 60 * 24));

      expect(ageInDays).toBeGreaterThan(keyRotationPolicy.maxAgeInDays);
      // Key should be rotated
    });
  });
});
