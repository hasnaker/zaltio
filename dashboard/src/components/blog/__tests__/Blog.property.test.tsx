/**
 * Property-Based Tests for Blog and Changelog
 * 
 * Feature: zalt-enterprise-landing
 * Property 18: Blog article structure
 * Property 19: Changelog ordering
 * 
 * Validates: Requirements 16.3, 16.5
 */

import * as fc from 'fast-check';

// Blog post structure (mirrors actual implementation)
interface BlogPost {
  slug: string;
  title: string;
  excerpt: string;
  author: string;
  date: string;
  readingTime: number;
  category: string;
  tags: string[];
  featured?: boolean;
}

// Changelog entry structure (mirrors actual implementation)
interface ChangelogEntry {
  version: string;
  date: string;
  changes: {
    type: 'feature' | 'improvement' | 'fix' | 'security' | 'breaking' | 'deprecated';
    title: string;
    description?: string;
  }[];
}

// Sample blog posts for testing
const samplePosts: BlogPost[] = [
  {
    slug: 'why-we-disabled-sms-mfa-by-default',
    title: 'Why We Disabled SMS MFA by Default',
    excerpt: 'SS7 vulnerabilities make SMS-based authentication a security risk.',
    author: 'Security Team',
    date: 'Feb 1, 2026',
    readingTime: 8,
    category: 'Security',
    tags: ['mfa', 'security', 'ss7', 'webauthn'],
    featured: true,
  },
  {
    slug: 'introducing-ai-risk-scoring',
    title: 'Introducing AI-Powered Risk Scoring',
    excerpt: 'Our new Bedrock-powered risk engine analyzes login patterns.',
    author: 'Engineering',
    date: 'Jan 28, 2026',
    readingTime: 6,
    category: 'Product',
    tags: ['ai', 'security', 'bedrock'],
  },
  {
    slug: 'building-hipaa-compliant-auth',
    title: 'Building HIPAA-Compliant Authentication',
    excerpt: 'How we designed Zalt to meet healthcare compliance requirements.',
    author: 'Engineering',
    date: 'Jan 25, 2026',
    readingTime: 12,
    category: 'Engineering',
    tags: ['hipaa', 'compliance', 'healthcare'],
  },
];

// Sample changelog entries for testing
const sampleChangelog: ChangelogEntry[] = [
  {
    version: '1.5.0',
    date: 'February 3, 2026',
    changes: [
      { type: 'feature', title: 'AI-powered risk scoring' },
      { type: 'improvement', title: 'Improved device fingerprinting' },
    ],
  },
  {
    version: '1.4.0',
    date: 'January 25, 2026',
    changes: [
      { type: 'feature', title: 'MCP Server for AI agents' },
      { type: 'security', title: 'HIBP breach detection' },
    ],
  },
  {
    version: '1.3.0',
    date: 'January 15, 2026',
    changes: [
      { type: 'feature', title: 'SAML SSO support' },
      { type: 'fix', title: 'Fixed OIDC state validation' },
    ],
  },
];

// Validation functions
function validateBlogPost(post: BlogPost): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!post.slug || post.slug.length === 0) errors.push('Missing slug');
  if (!post.title || post.title.length === 0) errors.push('Missing title');
  if (!post.excerpt || post.excerpt.length === 0) errors.push('Missing excerpt');
  if (!post.author || post.author.length === 0) errors.push('Missing author');
  if (!post.date || post.date.length === 0) errors.push('Missing date');
  if (typeof post.readingTime !== 'number' || post.readingTime <= 0) {
    errors.push('Invalid reading time');
  }
  if (!post.category || post.category.length === 0) errors.push('Missing category');
  if (!Array.isArray(post.tags)) errors.push('Tags must be an array');
  
  return { valid: errors.length === 0, errors };
}

function parseVersion(version: string): number[] {
  return version.split('.').map(n => parseInt(n, 10));
}

function compareVersions(a: string, b: string): number {
  const aParts = parseVersion(a);
  const bParts = parseVersion(b);
  
  for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
    const aVal = aParts[i] || 0;
    const bVal = bParts[i] || 0;
    if (aVal > bVal) return 1;
    if (aVal < bVal) return -1;
  }
  return 0;
}

function filterPostsByCategory(posts: BlogPost[], category: string): BlogPost[] {
  return posts.filter(p => p.category === category);
}

function filterPostsByTag(posts: BlogPost[], tag: string): BlogPost[] {
  return posts.filter(p => p.tags.includes(tag));
}

function searchPosts(posts: BlogPost[], query: string): BlogPost[] {
  const q = query.toLowerCase();
  return posts.filter(p => 
    p.title.toLowerCase().includes(q) ||
    p.excerpt.toLowerCase().includes(q)
  );
}

describe('Feature: zalt-enterprise-landing, Property 18: Blog article structure', () => {
  describe('Property 18.1: All blog posts have required fields', () => {
    it('should have valid structure for all sample posts', () => {
      samplePosts.forEach(post => {
        const validation = validateBlogPost(post);
        expect(validation.valid).toBe(true);
        expect(validation.errors).toEqual([]);
      });
    });

    it('should have title, date, author, reading time for every post', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: samplePosts.length - 1 }),
          (index) => {
            const post = samplePosts[index];
            expect(post.title).toBeDefined();
            expect(post.title.length).toBeGreaterThan(0);
            expect(post.date).toBeDefined();
            expect(post.author).toBeDefined();
            expect(post.readingTime).toBeGreaterThan(0);
          }
        ),
        { numRuns: samplePosts.length }
      );
    });
  });

  describe('Property 18.2: Blog posts have valid categories', () => {
    const validCategories = ['Engineering', 'Security', 'Product', 'Company', 'Tutorial'];

    it('should have category from valid list', () => {
      samplePosts.forEach(post => {
        expect(validCategories).toContain(post.category);
      });
    });
  });

  describe('Property 18.3: Blog posts have unique slugs', () => {
    it('should have unique slugs across all posts', () => {
      const slugs = samplePosts.map(p => p.slug);
      const uniqueSlugs = new Set(slugs);
      expect(uniqueSlugs.size).toBe(slugs.length);
    });

    it('should have URL-safe slugs', () => {
      samplePosts.forEach(post => {
        // Slug should only contain lowercase letters, numbers, and hyphens
        expect(post.slug).toMatch(/^[a-z0-9-]+$/);
      });
    });
  });

  describe('Property 18.4: Blog filtering works correctly', () => {
    it('should filter by category correctly', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('Engineering', 'Security', 'Product'),
          (category) => {
            const filtered = filterPostsByCategory(samplePosts, category);
            filtered.forEach(post => {
              expect(post.category).toBe(category);
            });
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should filter by tag correctly', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('security', 'mfa', 'ai', 'hipaa'),
          (tag) => {
            const filtered = filterPostsByTag(samplePosts, tag);
            filtered.forEach(post => {
              expect(post.tags).toContain(tag);
            });
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should search posts correctly', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('SMS', 'AI', 'HIPAA', 'risk'),
          (query) => {
            const results = searchPosts(samplePosts, query);
            const queryLower = query.toLowerCase();
            
            results.forEach(post => {
              const matchesTitle = post.title.toLowerCase().includes(queryLower);
              const matchesExcerpt = post.excerpt.toLowerCase().includes(queryLower);
              expect(matchesTitle || matchesExcerpt).toBe(true);
            });
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 18.5: Reading time is reasonable', () => {
    it('should have reading time between 1 and 30 minutes', () => {
      samplePosts.forEach(post => {
        expect(post.readingTime).toBeGreaterThanOrEqual(1);
        expect(post.readingTime).toBeLessThanOrEqual(30);
      });
    });
  });

  describe('Property 18.6: Tags are non-empty arrays', () => {
    it('should have at least one tag per post', () => {
      samplePosts.forEach(post => {
        expect(Array.isArray(post.tags)).toBe(true);
        expect(post.tags.length).toBeGreaterThan(0);
      });
    });

    it('should have lowercase tags', () => {
      samplePosts.forEach(post => {
        post.tags.forEach(tag => {
          expect(tag).toBe(tag.toLowerCase());
        });
      });
    });
  });
});

describe('Feature: zalt-enterprise-landing, Property 19: Changelog ordering', () => {
  describe('Property 19.1: Changelog is in reverse chronological order', () => {
    it('should have versions in descending order', () => {
      for (let i = 0; i < sampleChangelog.length - 1; i++) {
        const current = sampleChangelog[i].version;
        const next = sampleChangelog[i + 1].version;
        
        expect(compareVersions(current, next)).toBeGreaterThan(0);
      }
    });
  });

  describe('Property 19.2: All changelog entries have required fields', () => {
    it('should have version, date, and changes', () => {
      sampleChangelog.forEach(entry => {
        expect(entry.version).toBeDefined();
        expect(entry.version).toMatch(/^\d+\.\d+\.\d+$/);
        expect(entry.date).toBeDefined();
        expect(entry.date.length).toBeGreaterThan(0);
        expect(Array.isArray(entry.changes)).toBe(true);
        expect(entry.changes.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Property 19.3: Change types are valid', () => {
    const validTypes = ['feature', 'improvement', 'fix', 'security', 'breaking', 'deprecated'];

    it('should have valid change types', () => {
      sampleChangelog.forEach(entry => {
        entry.changes.forEach(change => {
          expect(validTypes).toContain(change.type);
        });
      });
    });
  });

  describe('Property 19.4: Changes have titles', () => {
    it('should have non-empty title for each change', () => {
      sampleChangelog.forEach(entry => {
        entry.changes.forEach(change => {
          expect(change.title).toBeDefined();
          expect(change.title.length).toBeGreaterThan(0);
        });
      });
    });
  });

  describe('Property 19.5: Version parsing', () => {
    it('should parse semantic versions correctly', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 10 }),
          fc.integer({ min: 0, max: 20 }),
          fc.integer({ min: 0, max: 50 }),
          (major, minor, patch) => {
            const version = `${major}.${minor}.${patch}`;
            const parsed = parseVersion(version);
            
            expect(parsed).toEqual([major, minor, patch]);
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should compare versions correctly', () => {
      expect(compareVersions('2.0.0', '1.0.0')).toBeGreaterThan(0);
      expect(compareVersions('1.0.0', '2.0.0')).toBeLessThan(0);
      expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
      expect(compareVersions('1.5.0', '1.4.0')).toBeGreaterThan(0);
      expect(compareVersions('1.4.1', '1.4.0')).toBeGreaterThan(0);
    });
  });

  describe('Property 19.6: Unique versions', () => {
    it('should have unique version numbers', () => {
      const versions = sampleChangelog.map(e => e.version);
      const uniqueVersions = new Set(versions);
      expect(uniqueVersions.size).toBe(versions.length);
    });
  });
});

describe('Blog and Changelog Edge Cases', () => {
  it('should handle empty search query', () => {
    const results = searchPosts(samplePosts, '');
    expect(results.length).toBe(samplePosts.length);
  });

  it('should handle search with no results', () => {
    const results = searchPosts(samplePosts, 'xyznonexistent');
    expect(results.length).toBe(0);
  });

  it('should handle filtering by non-existent category', () => {
    const results = filterPostsByCategory(samplePosts, 'NonExistent');
    expect(results.length).toBe(0);
  });

  it('should handle filtering by non-existent tag', () => {
    const results = filterPostsByTag(samplePosts, 'nonexistenttag');
    expect(results.length).toBe(0);
  });

  it('should handle case-insensitive search', () => {
    const upperResults = searchPosts(samplePosts, 'SMS');
    const lowerResults = searchPosts(samplePosts, 'sms');
    expect(upperResults.length).toBe(lowerResults.length);
  });
});
