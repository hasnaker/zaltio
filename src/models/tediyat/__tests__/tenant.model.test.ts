/**
 * Tediyat Tenant Model Tests
 * Property-based tests for slug generation and tenant model
 * 
 * Feature: tediyat-integration
 * Property 3: Slug Generation Consistency
 * Validates: Requirements 1.6, 9.2
 */

import * as fc from 'fast-check';
import {
  generateSlug,
  isValidSlug,
  generateTenantId,
  Tenant,
  TenantStatus
} from '../tenant.model';

describe('Tediyat Tenant Model', () => {
  describe('generateTenantId', () => {
    it('should generate unique tenant IDs with ten_ prefix', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        const id = generateTenantId();
        expect(id).toMatch(/^ten_[a-z0-9]+$/);
        expect(ids.has(id)).toBe(false);
        ids.add(id);
      }
    });
  });

  describe('generateSlug', () => {
    /**
     * Property 3: Slug Generation Consistency
     * For any company name, the slugify function should produce a valid URL-safe slug,
     * and the same input should always produce the same output (deterministic).
     * 
     * Validates: Requirements 1.6, 9.2
     */
    it('should be deterministic - same input always produces same output', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          (name) => {
            const slug1 = generateSlug(name);
            const slug2 = generateSlug(name);
            return slug1 === slug2;
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property 3: Slug Generation Consistency
     * Slugs should only contain lowercase letters, numbers, and hyphens
     */
    it('should produce URL-safe slugs (only lowercase, numbers, hyphens)', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          (name) => {
            const slug = generateSlug(name);
            // Empty slugs are valid for empty/whitespace-only input
            if (slug === '') return true;
            // Check URL-safe characters only
            return /^[a-z0-9-]+$/.test(slug);
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property 3: Slug Generation Consistency
     * Slugs should not have consecutive hyphens
     */
    it('should not produce consecutive hyphens', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          (name) => {
            const slug = generateSlug(name);
            return !slug.includes('--');
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property 3: Slug Generation Consistency
     * Slugs should not start or end with hyphens
     */
    it('should not start or end with hyphens', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 100 }),
          (name) => {
            const slug = generateSlug(name);
            if (slug === '') return true;
            return !slug.startsWith('-') && !slug.endsWith('-');
          }
        ),
        { numRuns: 100 }
      );
    });

    // Turkish character support tests
    describe('Turkish character support', () => {
      it('should convert Turkish characters correctly', () => {
        const testCases = [
          { input: 'ABC Şirketi', expected: 'abc-sirketi' },
          { input: 'Özel Muhasebe', expected: 'ozel-muhasebe' },
          { input: 'Güneş İnşaat', expected: 'gunes-insaat' },
          { input: 'Çelik Üretim', expected: 'celik-uretim' },
          { input: 'TÜRK ŞİRKETİ', expected: 'turk-sirketi' },
          { input: 'İstanbul Ticaret', expected: 'istanbul-ticaret' },
          { input: 'Müşteri Hizmetleri', expected: 'musteri-hizmetleri' }
        ];

        for (const { input, expected } of testCases) {
          expect(generateSlug(input)).toBe(expected);
        }
      });

      /**
       * Property test for Turkish characters
       * All Turkish characters should be converted to ASCII equivalents
       */
      it('should convert all Turkish characters to ASCII', () => {
        const turkishChars = 'çÇğĞıİöÖşŞüÜ';
        
        fc.assert(
          fc.property(
            fc.stringOf(fc.constantFrom(...turkishChars.split('')), { minLength: 1, maxLength: 20 }),
            (turkishString) => {
              const slug = generateSlug(turkishString);
              // Should not contain any Turkish characters
              return !/[çÇğĞıİöÖşŞüÜ]/.test(slug);
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    // Edge cases
    describe('edge cases', () => {
      it('should handle empty string', () => {
        expect(generateSlug('')).toBe('');
      });

      it('should handle whitespace only', () => {
        expect(generateSlug('   ')).toBe('');
      });

      it('should handle special characters only', () => {
        expect(generateSlug('!@#$%^&*()')).toBe('');
      });

      it('should handle numbers', () => {
        expect(generateSlug('Company 123')).toBe('company-123');
      });

      it('should handle multiple spaces', () => {
        expect(generateSlug('ABC    DEF')).toBe('abc-def');
      });
    });
  });

  describe('isValidSlug', () => {
    it('should accept valid slugs', () => {
      const validSlugs = [
        'abc-company',
        'my-business-123',
        'a1b2c3',
        'test',
        'abc'
      ];

      for (const slug of validSlugs) {
        expect(isValidSlug(slug)).toBe(true);
      }
    });

    it('should reject invalid slugs', () => {
      const invalidSlugs = [
        '-abc',           // starts with hyphen
        'abc-',           // ends with hyphen
        'ABC',            // uppercase
        'abc--def',       // consecutive hyphens
        'ab',             // too short
        'a',              // too short
        'abc def',        // contains space
        'abc_def',        // contains underscore
        'abc.def'         // contains dot
      ];

      for (const slug of invalidSlugs) {
        expect(isValidSlug(slug)).toBe(false);
      }
    });

    /**
     * Property: Valid slugs generated by generateSlug should pass isValidSlug
     * (when the input produces a non-empty slug of sufficient length)
     */
    it('should validate slugs generated by generateSlug', () => {
      fc.assert(
        fc.property(
          // Generate strings that will produce valid slugs
          fc.stringOf(
            fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789 '.split('')),
            { minLength: 5, maxLength: 50 }
          ).filter(s => s.trim().length >= 3),
          (name) => {
            const slug = generateSlug(name);
            // Only test if slug is long enough
            if (slug.length >= 3) {
              return isValidSlug(slug);
            }
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
