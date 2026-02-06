/**
 * Storage Adapters Property Tests
 * @zalt/core
 * 
 * Property 1: Token Storage Round-Trip
 * For any valid token string, storing it via TokenStorage and then retrieving it
 * SHALL return the exact same string.
 * 
 * Validates: Requirements 1.7, 7.4
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as fc from 'fast-check';
import { MemoryStorage, BrowserStorage, SessionStorage, CookieStorage, STORAGE_KEYS } from '../storage';
import type { TokenStorage } from '../types';

// ============================================================================
// Property Test: Token Storage Round-Trip
// ============================================================================

describe('Property 1: Token Storage Round-Trip', () => {
  /**
   * Feature: zalt-sdk-packages, Property 1: Token Storage Round-Trip
   * For any valid token string, storing and retrieving SHALL return the same value
   */

  describe('MemoryStorage', () => {
    let storage: MemoryStorage;

    beforeEach(() => {
      storage = new MemoryStorage();
    });

    it('should round-trip any string value', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }),
          fc.string({ minLength: 1 }),
          (key, value) => {
            storage.set(key, value);
            const retrieved = storage.get(key);
            return retrieved === value;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should round-trip JWT-like tokens', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.base64String({ minLength: 10, maxLength: 100 }),
            fc.base64String({ minLength: 10, maxLength: 200 }),
            fc.base64String({ minLength: 10, maxLength: 100 })
          ),
          ([header, payload, signature]) => {
            const token = `${header}.${payload}.${signature}`;
            storage.set(STORAGE_KEYS.ACCESS_TOKEN, token);
            const retrieved = storage.get(STORAGE_KEYS.ACCESS_TOKEN);
            return retrieved === token;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should return null for non-existent keys', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }),
          (key) => {
            const retrieved = storage.get(key);
            return retrieved === null;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should remove values correctly', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }),
          fc.string({ minLength: 1 }),
          (key, value) => {
            storage.set(key, value);
            storage.remove(key);
            const retrieved = storage.get(key);
            return retrieved === null;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle overwriting values', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }),
          fc.string({ minLength: 1 }),
          fc.string({ minLength: 1 }),
          (key, value1, value2) => {
            storage.set(key, value1);
            storage.set(key, value2);
            const retrieved = storage.get(key);
            return retrieved === value2;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should clear all values', () => {
      fc.assert(
        fc.property(
          fc.array(fc.tuple(fc.string({ minLength: 1 }), fc.string({ minLength: 1 })), { minLength: 1, maxLength: 10 }),
          (pairs) => {
            // Store all pairs
            for (const [key, value] of pairs) {
              storage.set(key, value);
            }
            
            // Clear storage
            storage.clear();
            
            // All keys should return null
            return pairs.every(([key]) => storage.get(key) === null);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Storage Interface Compliance', () => {
    const storageImplementations: Array<{ name: string; create: () => TokenStorage }> = [
      { name: 'MemoryStorage', create: () => new MemoryStorage() },
      // BrowserStorage and SessionStorage require DOM - tested separately in browser
    ];

    for (const { name, create } of storageImplementations) {
      describe(name, () => {
        it('should implement TokenStorage interface correctly', () => {
          const storage = create();
          
          fc.assert(
            fc.property(
              fc.string({ minLength: 1, maxLength: 50 }),
              fc.string({ minLength: 1, maxLength: 500 }),
              (key, value) => {
                // Set should not throw
                storage.set(key, value);
                
                // Get should return the value
                const retrieved = storage.get(key);
                if (retrieved !== value) return false;
                
                // Remove should not throw
                storage.remove(key);
                
                // Get after remove should return null
                const afterRemove = storage.get(key);
                return afterRemove === null;
              }
            ),
            { numRuns: 100 }
          );
        });
      });
    }
  });
});

// ============================================================================
// Unit Tests for Edge Cases
// ============================================================================

describe('Storage Edge Cases', () => {
  describe('MemoryStorage', () => {
    it('should handle empty string values', () => {
      const storage = new MemoryStorage();
      storage.set('key', '');
      expect(storage.get('key')).toBe('');
    });

    it('should handle special characters in keys', () => {
      const storage = new MemoryStorage();
      const specialKey = 'key-with_special.chars:and/slashes';
      storage.set(specialKey, 'value');
      expect(storage.get(specialKey)).toBe('value');
    });

    it('should handle unicode values', () => {
      const storage = new MemoryStorage();
      const unicodeValue = '日本語テスト 🔐 émojis';
      storage.set('unicode', unicodeValue);
      expect(storage.get('unicode')).toBe(unicodeValue);
    });

    it('should handle very long values', () => {
      const storage = new MemoryStorage();
      const longValue = 'a'.repeat(10000);
      storage.set('long', longValue);
      expect(storage.get('long')).toBe(longValue);
    });
  });

  describe('CookieStorage', () => {
    it('should create with default options', () => {
      const storage = new CookieStorage();
      expect(storage).toBeDefined();
    });

    it('should create with custom options', () => {
      const storage = new CookieStorage({
        prefix: 'custom_',
        secure: true,
        sameSite: 'strict',
        path: '/app',
        maxAge: 3600,
      });
      expect(storage).toBeDefined();
    });
  });
});
