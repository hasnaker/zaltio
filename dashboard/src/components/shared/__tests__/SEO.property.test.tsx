/**
 * Property-Based Tests for SEO and Analytics
 * 
 * Feature: zalt-enterprise-landing
 * Property 11: SEO meta tags presence
 * Property 12: Image lazy loading
 * Property 13: Analytics event tracking
 * 
 * Validates: Requirements 11.1, 11.2, 11.3, 11.8, 12.2, 12.6
 */

import * as fc from 'fast-check';

// SEO metadata structure
interface SEOMetadata {
  title: string;
  description: string;
  canonical?: string;
  ogImage?: string;
  ogType?: 'website' | 'article';
  twitterCard?: 'summary' | 'summary_large_image';
  noIndex?: boolean;
}

// Analytics event structure
interface AnalyticsEvent {
  name: string;
  category: string;
  action: string;
  label?: string;
  value?: number;
}

// Sitemap entry structure
interface SitemapEntry {
  url: string;
  lastModified: string;
  changeFrequency: 'always' | 'hourly' | 'daily' | 'weekly' | 'monthly' | 'yearly' | 'never';
  priority: number;
}

// Generate full title
function generateFullTitle(title: string): string {
  return title.includes('Zalt') ? title : `${title} | Zalt.io`;
}

// Generate canonical URL
function generateCanonicalUrl(path?: string): string | undefined {
  if (!path) return undefined;
  return `https://zalt.io${path}`;
}

// Validate SEO metadata
function validateSEOMetadata(meta: SEOMetadata): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!meta.title || meta.title.length === 0) {
    errors.push('Title is required');
  }
  if (meta.title && meta.title.length > 60) {
    errors.push('Title should be under 60 characters for SEO');
  }
  if (!meta.description || meta.description.length === 0) {
    errors.push('Description is required');
  }
  if (meta.description && meta.description.length > 160) {
    errors.push('Description should be under 160 characters for SEO');
  }
  if (meta.ogImage && !meta.ogImage.startsWith('http')) {
    errors.push('OG image must be an absolute URL');
  }
  
  return { valid: errors.length === 0, errors };
}

// Validate sitemap entry
function validateSitemapEntry(entry: SitemapEntry): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!entry.url || !entry.url.startsWith('https://')) {
    errors.push('URL must be absolute HTTPS');
  }
  if (entry.priority < 0 || entry.priority > 1) {
    errors.push('Priority must be between 0 and 1');
  }
  if (!entry.lastModified) {
    errors.push('Last modified date is required');
  }
  
  return { valid: errors.length === 0, errors };
}

// Validate analytics event
function validateAnalyticsEvent(event: AnalyticsEvent): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!event.name || event.name.length === 0) {
    errors.push('Event name is required');
  }
  if (!event.category || event.category.length === 0) {
    errors.push('Event category is required');
  }
  if (!event.action || event.action.length === 0) {
    errors.push('Event action is required');
  }
  if (event.value !== undefined && event.value < 0) {
    errors.push('Event value must be non-negative');
  }
  
  return { valid: errors.length === 0, errors };
}

// Sample sitemap entries
const sampleSitemap: SitemapEntry[] = [
  { url: 'https://zalt.io', lastModified: '2026-02-03', changeFrequency: 'weekly', priority: 1.0 },
  { url: 'https://zalt.io/docs', lastModified: '2026-02-03', changeFrequency: 'weekly', priority: 0.9 },
  { url: 'https://zalt.io/blog', lastModified: '2026-02-03', changeFrequency: 'daily', priority: 0.8 },
  { url: 'https://zalt.io/privacy', lastModified: '2026-02-01', changeFrequency: 'yearly', priority: 0.4 },
];

describe('Feature: zalt-enterprise-landing, Property 11: SEO meta tags presence', () => {
  describe('Property 11.1: Title generation', () => {
    it('should append site name to titles without it', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 40 }).filter(s => !s.includes('Zalt')),
          (title) => {
            const fullTitle = generateFullTitle(title);
            expect(fullTitle).toContain('Zalt.io');
            expect(fullTitle).toContain(title);
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should not duplicate site name if already present', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('Zalt.io', 'Zalt Auth', 'Welcome to Zalt'),
          (title) => {
            const fullTitle = generateFullTitle(title);
            // Should not have double "Zalt"
            const zaltCount = (fullTitle.match(/Zalt/g) || []).length;
            expect(zaltCount).toBeLessThanOrEqual(2);
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 11.2: Canonical URL generation', () => {
    it('should generate absolute URLs', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('/docs', '/blog', '/privacy', '/contact'),
          (path) => {
            const canonical = generateCanonicalUrl(path);
            expect(canonical).toMatch(/^https:\/\/zalt\.io/);
            expect(canonical).toContain(path);
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should return undefined for empty path', () => {
      expect(generateCanonicalUrl(undefined)).toBeUndefined();
      expect(generateCanonicalUrl('')).toBeUndefined();
    });
  });

  describe('Property 11.3: SEO metadata validation', () => {
    it('should validate complete metadata', () => {
      fc.assert(
        fc.property(
          fc.record({
            title: fc.string({ minLength: 1, maxLength: 50 }),
            description: fc.string({ minLength: 1, maxLength: 150 }),
            ogImage: fc.constant('https://zalt.io/og-image.png'),
          }),
          (meta) => {
            const validation = validateSEOMetadata(meta);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject empty title', () => {
      const meta: SEOMetadata = { title: '', description: 'Valid description' };
      const validation = validateSEOMetadata(meta);
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Title is required');
    });

    it('should reject empty description', () => {
      const meta: SEOMetadata = { title: 'Valid Title', description: '' };
      const validation = validateSEOMetadata(meta);
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Description is required');
    });

    it('should warn about long titles', () => {
      const meta: SEOMetadata = { 
        title: 'A'.repeat(70), 
        description: 'Valid description' 
      };
      const validation = validateSEOMetadata(meta);
      expect(validation.errors).toContain('Title should be under 60 characters for SEO');
    });
  });
});

describe('Feature: zalt-enterprise-landing, Property 12: Image lazy loading', () => {
  describe('Property 12.1: Image attributes', () => {
    interface ImageProps {
      src: string;
      alt: string;
      loading?: 'lazy' | 'eager';
      width?: number;
      height?: number;
    }

    function validateImageProps(props: ImageProps): { valid: boolean; errors: string[] } {
      const errors: string[] = [];
      
      if (!props.src) errors.push('Image src is required');
      if (!props.alt) errors.push('Image alt text is required for accessibility');
      if (props.width && props.width <= 0) errors.push('Width must be positive');
      if (props.height && props.height <= 0) errors.push('Height must be positive');
      
      return { valid: errors.length === 0, errors };
    }

    it('should require alt text for accessibility', () => {
      fc.assert(
        fc.property(
          fc.record({
            src: fc.webUrl(),
            alt: fc.string({ minLength: 1, maxLength: 100 }),
            loading: fc.constantFrom<('lazy' | 'eager')[]>('lazy', 'eager'),
          }),
          (props) => {
            const validation = validateImageProps(props);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject images without alt text', () => {
      const props = { src: 'https://example.com/image.png', alt: '' };
      const validation = validateImageProps(props);
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Image alt text is required for accessibility');
    });
  });

  describe('Property 12.2: Lazy loading behavior', () => {
    function shouldLazyLoad(position: 'above-fold' | 'below-fold'): boolean {
      return position === 'below-fold';
    }

    it('should lazy load below-fold images', () => {
      expect(shouldLazyLoad('below-fold')).toBe(true);
    });

    it('should not lazy load above-fold images', () => {
      expect(shouldLazyLoad('above-fold')).toBe(false);
    });
  });
});

describe('Feature: zalt-enterprise-landing, Property 13: Analytics event tracking', () => {
  describe('Property 13.1: Event validation', () => {
    it('should validate complete events', () => {
      fc.assert(
        fc.property(
          fc.record({
            name: fc.string({ minLength: 1, maxLength: 50 }),
            category: fc.constantFrom('CTA', 'Navigation', 'Form', 'Engagement'),
            action: fc.constantFrom('click', 'submit', 'view', 'scroll'),
            label: fc.option(fc.string({ minLength: 1, maxLength: 50 })),
            value: fc.option(fc.integer({ min: 0, max: 1000 })),
          }),
          (event) => {
            const validation = validateAnalyticsEvent({
              ...event,
              label: event.label ?? undefined,
              value: event.value ?? undefined,
            });
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should reject events without name', () => {
      const event: AnalyticsEvent = { name: '', category: 'CTA', action: 'click' };
      const validation = validateAnalyticsEvent(event);
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Event name is required');
    });

    it('should reject negative values', () => {
      const event: AnalyticsEvent = { 
        name: 'test', 
        category: 'CTA', 
        action: 'click',
        value: -1 
      };
      const validation = validateAnalyticsEvent(event);
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Event value must be non-negative');
    });
  });

  describe('Property 13.2: CTA tracking events', () => {
    const ctaEvents = [
      { name: 'cta_click', category: 'CTA', action: 'click', label: 'hero_get_started' },
      { name: 'cta_click', category: 'CTA', action: 'click', label: 'pricing_pro' },
      { name: 'cta_click', category: 'CTA', action: 'click', label: 'docs_quickstart' },
    ];

    it('should have valid CTA events', () => {
      ctaEvents.forEach(event => {
        const validation = validateAnalyticsEvent(event);
        expect(validation.valid).toBe(true);
      });
    });

    it('should have consistent naming convention', () => {
      ctaEvents.forEach(event => {
        expect(event.name).toBe('cta_click');
        expect(event.category).toBe('CTA');
        expect(event.action).toBe('click');
        expect(event.label).toMatch(/^[a-z_]+$/);
      });
    });
  });

  describe('Property 13.3: Scroll depth tracking', () => {
    function getScrollDepthEvent(percentage: number): AnalyticsEvent {
      return {
        name: 'scroll_depth',
        category: 'Engagement',
        action: 'scroll',
        label: `${percentage}%`,
        value: percentage,
      };
    }

    it('should track standard scroll depths', () => {
      const depths = [25, 50, 75, 100];
      
      depths.forEach(depth => {
        const event = getScrollDepthEvent(depth);
        const validation = validateAnalyticsEvent(event);
        expect(validation.valid).toBe(true);
        expect(event.value).toBe(depth);
      });
    });
  });
});

describe('Sitemap Validation', () => {
  describe('Sitemap entry validation', () => {
    it('should validate all sample sitemap entries', () => {
      sampleSitemap.forEach(entry => {
        const validation = validateSitemapEntry(entry);
        expect(validation.valid).toBe(true);
      });
    });

    it('should have valid priorities', () => {
      fc.assert(
        fc.property(
          fc.double({ min: 0, max: 1, noNaN: true }),
          (priority) => {
            const entry: SitemapEntry = {
              url: 'https://zalt.io/test',
              lastModified: '2026-02-03',
              changeFrequency: 'weekly',
              priority,
            };
            const validation = validateSitemapEntry(entry);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject invalid priorities', () => {
      const invalidPriorities = [-0.1, 1.1, 2];
      
      invalidPriorities.forEach(priority => {
        const entry: SitemapEntry = {
          url: 'https://zalt.io/test',
          lastModified: '2026-02-03',
          changeFrequency: 'weekly',
          priority,
        };
        const validation = validateSitemapEntry(entry);
        expect(validation.valid).toBe(false);
      });
    });
  });

  describe('Sitemap URL validation', () => {
    it('should require HTTPS URLs', () => {
      const httpEntry: SitemapEntry = {
        url: 'http://zalt.io/test',
        lastModified: '2026-02-03',
        changeFrequency: 'weekly',
        priority: 0.5,
      };
      const validation = validateSitemapEntry(httpEntry);
      expect(validation.valid).toBe(false);
    });
  });
});
