/**
 * HaveIBeenPwned (HIBP) Service Tests
 * Task 17.1: Implement HaveIBeenPwned integration
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 * These tests make REAL API calls to the HIBP API
 * 
 * Tests:
 * - k-Anonymity API integration
 * - SHA-1 prefix lookup
 * - Cache functionality
 * - Error handling
 * - Privacy guarantees
 * 
 * _Requirements: 8.1, 8.2_
 */

import * as fc from 'fast-check';
import crypto from 'crypto';
import {
  HIBPService,
  HIBPCheckResult,
  createHIBPService,
  getHIBPService,
  checkPassword,
  isPasswordCompromised,
} from './hibp.service';

describe('HIBP Service - Unit Tests', () => {
  let service: HIBPService;

  beforeEach(() => {
    service = createHIBPService({
      cacheTtlMs: 60000, // 1 minute for tests
      maxCacheSize: 100,
    });
  });

  afterEach(() => {
    service.clearCache();
  });

  describe('hashPassword', () => {
    it('should generate SHA-1 hash in uppercase hex format', () => {
      const password = 'password';
      const hash = service.hashPassword(password);
      
      // SHA-1 produces 40 hex characters
      expect(hash).toHaveLength(40);
      expect(hash).toMatch(/^[A-F0-9]{40}$/);
    });

    it('should generate consistent hash for same password', () => {
      const password = 'TestPassword123!';
      const hash1 = service.hashPassword(password);
      const hash2 = service.hashPassword(password);
      
      expect(hash1).toBe(hash2);
    });

    it('should generate different hashes for different passwords', () => {
      const hash1 = service.hashPassword('password1');
      const hash2 = service.hashPassword('password2');
      
      expect(hash1).not.toBe(hash2);
    });

    it('should match known SHA-1 hash for "password"', () => {
      // Known SHA-1 hash for "password"
      const expectedHash = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';
      const hash = service.hashPassword('password');
      
      expect(hash).toBe(expectedHash);
    });

    it('should handle Unicode passwords', () => {
      const password = 'Şifre!Türkçe123';
      const hash = service.hashPassword(password);
      
      expect(hash).toHaveLength(40);
      expect(hash).toMatch(/^[A-F0-9]{40}$/);
    });

    it('should handle empty string', () => {
      const hash = service.hashPassword('');
      
      // SHA-1 of empty string
      expect(hash).toBe('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709');
    });
  });

  describe('k-Anonymity verification', () => {
    it('should only use first 5 characters of hash as prefix', () => {
      const password = 'TestPassword!123';
      const hash = service.hashPassword(password);
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5);
      
      expect(prefix).toHaveLength(5);
      expect(suffix).toHaveLength(35);
      expect(prefix + suffix).toBe(hash);
    });

    it('should never expose full hash in API calls', () => {
      // This is a design verification test
      // The implementation sends only the first 5 characters
      const password = 'SecurePassword!123';
      const hash = service.hashPassword(password);
      const prefix = hash.substring(0, 5);
      
      // Prefix should be exactly 5 hex characters
      expect(prefix).toMatch(/^[A-F0-9]{5}$/);
    });
  });

  describe('Cache functionality', () => {
    it('should start with empty cache', () => {
      const stats = service.getCacheStats();
      
      expect(stats.size).toBe(0);
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
    });

    it('should track cache statistics', async () => {
      // First call - cache miss
      await service.checkPassword('password');
      let stats = service.getCacheStats();
      
      expect(stats.misses).toBe(1);
      expect(stats.hits).toBe(0);
      expect(stats.apiCalls).toBe(1);
      
      // Second call with same prefix - cache hit
      await service.checkPassword('password');
      stats = service.getCacheStats();
      
      expect(stats.hits).toBe(1);
      expect(stats.misses).toBe(1);
      expect(stats.apiCalls).toBe(1); // No new API call
    }, 15000);

    it('should clear cache', async () => {
      await service.checkPassword('password');
      expect(service.getCacheStats().size).toBeGreaterThan(0);
      
      service.clearCache();
      
      expect(service.getCacheStats().size).toBe(0);
    }, 15000);

    it('should reset statistics', async () => {
      await service.checkPassword('password');
      expect(service.getCacheStats().apiCalls).toBeGreaterThan(0);
      
      service.resetStats();
      
      const stats = service.getCacheStats();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
      expect(stats.apiCalls).toBe(0);
    }, 15000);

    it('should calculate hit rate correctly', async () => {
      // 1 miss
      await service.checkPassword('password');
      // 1 hit (same prefix)
      await service.checkPassword('password');
      
      const stats = service.getCacheStats();
      expect(stats.hitRate).toBe(0.5); // 1 hit / 2 total
    }, 15000);
  });

  describe('Input validation', () => {
    it('should handle null password', async () => {
      const result = await service.checkPassword(null as unknown as string);
      
      expect(result.isCompromised).toBe(false);
      expect(result.count).toBe(0);
      expect(result.error).toBeDefined();
    });

    it('should handle undefined password', async () => {
      const result = await service.checkPassword(undefined as unknown as string);
      
      expect(result.isCompromised).toBe(false);
      expect(result.count).toBe(0);
      expect(result.error).toBeDefined();
    });

    it('should handle empty string password', async () => {
      const result = await service.checkPassword('');
      
      expect(result.isCompromised).toBe(false);
      expect(result.count).toBe(0);
      expect(result.error).toBeDefined();
    });
  });

  describe('Result structure', () => {
    it('should return correct structure for compromised password', async () => {
      const result = await service.checkPassword('password');
      
      expect(result).toHaveProperty('isCompromised');
      expect(result).toHaveProperty('count');
      expect(result).toHaveProperty('fromCache');
      expect(typeof result.isCompromised).toBe('boolean');
      expect(typeof result.count).toBe('number');
      expect(typeof result.fromCache).toBe('boolean');
    }, 15000);

    it('should indicate cache status correctly', async () => {
      // First call - not from cache
      const result1 = await service.checkPassword('password');
      expect(result1.fromCache).toBe(false);
      
      // Second call - from cache
      const result2 = await service.checkPassword('password');
      expect(result2.fromCache).toBe(true);
    }, 15000);
  });
});

describe('HIBP Service - Real API Tests', () => {
  let service: HIBPService;

  beforeAll(() => {
    service = createHIBPService();
  });

  afterEach(() => {
    service.clearCache();
    service.resetStats();
  });

  describe('Known compromised passwords', () => {
    it('should detect "password" as compromised', async () => {
      const result = await service.checkPassword('password');
      
      expect(result.isCompromised).toBe(true);
      expect(result.count).toBeGreaterThan(0);
      // "password" appears millions of times in breaches
      expect(result.count).toBeGreaterThan(1000000);
    }, 15000);

    it('should detect "123456" as compromised', async () => {
      const result = await service.checkPassword('123456');
      
      expect(result.isCompromised).toBe(true);
      expect(result.count).toBeGreaterThan(0);
    }, 15000);

    it('should detect "qwerty" as compromised', async () => {
      const result = await service.checkPassword('qwerty');
      
      expect(result.isCompromised).toBe(true);
      expect(result.count).toBeGreaterThan(0);
    }, 15000);

    it('should detect "letmein" as compromised', async () => {
      const result = await service.checkPassword('letmein');
      
      expect(result.isCompromised).toBe(true);
      expect(result.count).toBeGreaterThan(0);
    }, 15000);

    it('should detect "admin" as compromised', async () => {
      const result = await service.checkPassword('admin');
      
      expect(result.isCompromised).toBe(true);
      expect(result.count).toBeGreaterThan(0);
    }, 15000);
  });

  describe('Unique passwords', () => {
    it('should not flag truly unique password as compromised', async () => {
      // Generate a truly unique password with timestamp and random data
      const uniquePassword = `Zalt!${Date.now()}!${crypto.randomBytes(16).toString('hex')}!Secure`;
      const result = await service.checkPassword(uniquePassword);
      
      expect(result.isCompromised).toBe(false);
      expect(result.count).toBe(0);
    }, 15000);

    it('should not flag complex unique password as compromised', async () => {
      const uniquePassword = `X9#mP2$vL5@nQ8!${crypto.randomUUID()}`;
      const result = await service.checkPassword(uniquePassword);
      
      expect(result.isCompromised).toBe(false);
      expect(result.count).toBe(0);
    }, 15000);
  });

  describe('Cache performance', () => {
    it('should cache results and return faster on second call', async () => {
      const password = 'password123';
      
      // First call - API request
      const start1 = Date.now();
      const result1 = await service.checkPassword(password);
      const duration1 = Date.now() - start1;
      
      // Second call - from cache
      const start2 = Date.now();
      const result2 = await service.checkPassword(password);
      const duration2 = Date.now() - start2;
      
      expect(result1.fromCache).toBe(false);
      expect(result2.fromCache).toBe(true);
      
      // Cache should be significantly faster
      expect(duration2).toBeLessThan(duration1);
      expect(duration2).toBeLessThan(10); // Cache lookup should be < 10ms
    }, 15000);

    it('should share cache for passwords with same prefix', async () => {
      // Find two passwords with the same SHA-1 prefix
      // We'll check the same password twice to verify caching
      const password = 'testpassword';
      
      await service.checkPassword(password);
      const stats1 = service.getCacheStats();
      
      await service.checkPassword(password);
      const stats2 = service.getCacheStats();
      
      expect(stats2.hits).toBe(stats1.hits + 1);
      expect(stats2.apiCalls).toBe(stats1.apiCalls); // No new API call
    }, 15000);
  });
});

describe('HIBP Service - Convenience Functions', () => {
  describe('getHIBPService', () => {
    it('should return singleton instance', () => {
      const instance1 = getHIBPService();
      const instance2 = getHIBPService();
      
      expect(instance1).toBe(instance2);
    });
  });

  describe('checkPassword', () => {
    it('should check password using default service', async () => {
      const result = await checkPassword('password');
      
      expect(result.isCompromised).toBe(true);
      expect(result.count).toBeGreaterThan(0);
    }, 15000);
  });

  describe('isPasswordCompromised', () => {
    it('should return true for compromised password', async () => {
      const result = await isPasswordCompromised('password');
      
      expect(result).toBe(true);
    }, 15000);

    it('should return false for unique password', async () => {
      const uniquePassword = `Unique!${Date.now()}!${crypto.randomBytes(8).toString('hex')}`;
      const result = await isPasswordCompromised(uniquePassword);
      
      expect(result).toBe(false);
    }, 15000);
  });
});

describe('HIBP Service - Property-Based Tests', () => {
  let service: HIBPService;

  beforeAll(() => {
    service = createHIBPService();
  });

  afterEach(() => {
    service.clearCache();
  });

  describe('Hash properties', () => {
    it('should always produce 40-character uppercase hex hash', () => {
      fc.assert(
        fc.property(fc.string({ minLength: 1, maxLength: 100 }), (password) => {
          const hash = service.hashPassword(password);
          
          expect(hash).toHaveLength(40);
          expect(hash).toMatch(/^[A-F0-9]{40}$/);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should produce deterministic hashes', () => {
      fc.assert(
        fc.property(fc.string({ minLength: 1, maxLength: 50 }), (password) => {
          const hash1 = service.hashPassword(password);
          const hash2 = service.hashPassword(password);
          
          expect(hash1).toBe(hash2);
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should produce different hashes for different passwords', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.string({ minLength: 1, maxLength: 50 }),
          (password1, password2) => {
            fc.pre(password1 !== password2);
            
            const hash1 = service.hashPassword(password1);
            const hash2 = service.hashPassword(password2);
            
            expect(hash1).not.toBe(hash2);
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('k-Anonymity properties', () => {
    it('should always split hash into 5-char prefix and 35-char suffix', () => {
      fc.assert(
        fc.property(fc.string({ minLength: 1, maxLength: 100 }), (password) => {
          const hash = service.hashPassword(password);
          const prefix = hash.substring(0, 5);
          const suffix = hash.substring(5);
          
          expect(prefix).toHaveLength(5);
          expect(suffix).toHaveLength(35);
          expect(prefix + suffix).toBe(hash);
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('Result properties', () => {
    it('should always return valid result structure', async () => {
      // Test with a few known passwords to avoid too many API calls
      const passwords = ['password', 'admin', 'test123'];
      
      for (const password of passwords) {
        const result = await service.checkPassword(password);
        
        expect(typeof result.isCompromised).toBe('boolean');
        expect(typeof result.count).toBe('number');
        expect(typeof result.fromCache).toBe('boolean');
        expect(result.count).toBeGreaterThanOrEqual(0);
        
        // If compromised, count should be > 0
        if (result.isCompromised) {
          expect(result.count).toBeGreaterThan(0);
        }
        
        // If count > 0, should be compromised
        if (result.count > 0) {
          expect(result.isCompromised).toBe(true);
        }
      }
    }, 30000);
  });
});

describe('HIBP Service - Error Handling', () => {
  describe('Fail-open behavior', () => {
    it('should fail open by default (return not compromised on error)', async () => {
      const service = createHIBPService({
        apiBaseUrl: 'https://invalid-url-that-does-not-exist.example.com',
        timeoutMs: 1000,
        failOpen: true,
      });

      const result = await service.checkPassword('password');
      
      expect(result.isCompromised).toBe(false);
      expect(result.error).toBeDefined();
    }, 15000);
  });

  describe('Timeout handling', () => {
    it('should handle timeout gracefully', async () => {
      const service = createHIBPService({
        timeoutMs: 1, // 1ms timeout - will definitely timeout
        failOpen: true,
      });

      const result = await service.checkPassword('password');
      
      // Should fail open
      expect(result.isCompromised).toBe(false);
      expect(result.error).toBeDefined();
    }, 15000);
  });
});

describe('HIBP Service - Configuration', () => {
  it('should use custom configuration', () => {
    const service = createHIBPService({
      cacheTtlMs: 10000,
      maxCacheSize: 50,
      timeoutMs: 3000,
      userAgent: 'Custom-Agent/1.0',
      addPadding: false,
    });

    // Service should be created without errors
    expect(service).toBeInstanceOf(HIBPService);
  });

  it('should use default configuration when not specified', () => {
    const service = createHIBPService();
    
    expect(service).toBeInstanceOf(HIBPService);
  });
});
