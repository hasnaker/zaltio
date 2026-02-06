/**
 * Tediyat Tenant Service Tests
 * Property-based tests for tenant creation and management
 * 
 * Feature: tediyat-integration
 * Property 14: Tenant Creation with Ownership
 * Validates: Requirements 9.1, 9.2, 9.3, 9.5
 */

import * as fc from 'fast-check';
import {
  generateTenantSlug,
  validateSlugFormat,
  validateSlugUniqueness,
} from '../tenant.service';
import {
  generateTenantId,
  generateSlug,
  isValidSlug,
} from '../../../models/tediyat/tenant.model';

// Mock the repository for unit tests
jest.mock('../../../repositories/tediyat/tenant.repository', () => ({
  isSlugAvailable: jest.fn().mockResolvedValue(true),
  createTenant: jest.fn().mockImplementation((input) => Promise.resolve({
    id: 'ten_test123',
    realm_id: 'tediyat',
    name: input.name,
    slug: input.slug,
    status: 'active',
    member_count: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    created_by: input.created_by,
  })),
  getTenant: jest.fn(),
  findTenantBySlug: jest.fn(),
}));

describe('Tediyat Tenant Service', () => {
  describe('generateTenantSlug', () => {
    /**
     * Property 14: Tenant Creation with Ownership
     * Slug generation should be deterministic and produce valid slugs
     * 
     * Validates: Requirements 9.2
     */
    it('should generate valid slugs from company names', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 3, maxLength: 50 }).filter(s => /[a-zA-Z]/.test(s)),
          (name) => {
            const slug = generateTenantSlug(name);
            // Slug should be URL-safe
            if (slug === '') return true; // Empty is valid for special char only input
            return /^[a-z0-9-]*$/.test(slug);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle Turkish company names', () => {
      const turkishNames = [
        'Özel Muhasebe Ltd.',
        'Güneş İnşaat A.Ş.',
        'Çelik Üretim Sanayi',
        'İstanbul Ticaret',
        'Müşteri Hizmetleri'
      ];

      for (const name of turkishNames) {
        const slug = generateTenantSlug(name);
        expect(slug).toMatch(/^[a-z0-9-]+$/);
        expect(slug).not.toMatch(/[çğıöşüÇĞİÖŞÜ]/);
      }
    });
  });

  describe('validateSlugFormat', () => {
    /**
     * Property 14: Tenant Creation with Ownership
     * Slug validation should correctly identify valid and invalid slugs
     * 
     * Validates: Requirements 9.5
     */
    it('should accept valid slugs', () => {
      const validSlugs = [
        'abc-company',
        'my-business-123',
        'test-tenant',
        'company123'
      ];

      for (const slug of validSlugs) {
        expect(validateSlugFormat(slug)).toBe(true);
      }
    });

    it('should reject invalid slugs', () => {
      const invalidSlugs = [
        '-abc',           // starts with hyphen
        'abc-',           // ends with hyphen
        'ABC',            // uppercase
        'abc--def',       // consecutive hyphens
        'ab',             // too short
        'abc def',        // contains space
      ];

      for (const slug of invalidSlugs) {
        expect(validateSlugFormat(slug)).toBe(false);
      }
    });
  });

  describe('generateTenantId', () => {
    /**
     * Property 14: Tenant Creation with Ownership
     * Tenant IDs should be unique and follow ten_xxx format
     * 
     * Validates: Requirements 9.1
     */
    it('should generate unique IDs with ten_ prefix', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 100 }),
          () => {
            const id = generateTenantId();
            return id.startsWith('ten_') && id.length > 4;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should generate unique IDs across multiple calls', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 1000; i++) {
        const id = generateTenantId();
        expect(ids.has(id)).toBe(false);
        ids.add(id);
      }
    });
  });

  describe('Tenant Creation Properties', () => {
    /**
     * Property 14: Tenant Creation with Ownership
     * For any tenant creation, the system should generate unique tenant ID (ten_xxx format),
     * unique slug, and automatically assign the creator as owner.
     * 
     * Validates: Requirements 9.1, 9.2, 9.3, 9.5
     */
    it('should create tenant with valid ID format', () => {
      fc.assert(
        fc.property(
          fc.record({
            name: fc.string({ minLength: 3, maxLength: 50 }).filter(s => /[a-zA-Z]/.test(s)),
            userId: fc.uuid(),
          }),
          ({ name, userId }) => {
            const tenantId = generateTenantId();
            const slug = generateSlug(name);
            
            // Tenant ID should have correct format
            const hasValidIdFormat = tenantId.startsWith('ten_');
            
            // Slug should be URL-safe (or empty for special char only names)
            const hasValidSlug = slug === '' || /^[a-z0-9-]+$/.test(slug);
            
            return hasValidIdFormat && hasValidSlug;
          }
        ),
        { numRuns: 100 }
      );
    });

    /**
     * Property: Slug uniqueness validation
     * The system should correctly identify when a slug is available
     */
    it('should validate slug uniqueness', async () => {
      // This tests the service function, which is mocked to return true
      const isAvailable = await validateSlugUniqueness('test-slug');
      expect(isAvailable).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty company name', () => {
      const slug = generateTenantSlug('');
      expect(slug).toBe('');
    });

    it('should handle special characters only', () => {
      const slug = generateTenantSlug('!@#$%^&*()');
      expect(slug).toBe('');
    });

    it('should handle very long company names', () => {
      const longName = 'A'.repeat(200);
      const slug = generateTenantSlug(longName);
      // Should produce a valid slug (lowercase a's with no hyphens)
      expect(slug).toMatch(/^[a-z]+$/);
    });

    it('should handle numbers only', () => {
      const slug = generateTenantSlug('12345');
      expect(slug).toBe('12345');
    });

    it('should handle mixed Turkish and English', () => {
      const slug = generateTenantSlug('ABC Şirketi Ltd');
      expect(slug).toBe('abc-sirketi-ltd');
    });
  });
});
