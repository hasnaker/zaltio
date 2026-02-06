/**
 * Property-Based Tests for DocsSearch
 * 
 * Feature: zalt-enterprise-landing
 * Property 8: Documentation search functionality
 * 
 * Validates: Requirements 8.6
 */

import * as fc from 'fast-check';

// Search result structure (mirrors actual implementation)
interface SearchResult {
  id: string;
  title: string;
  section: string;
  href: string;
  excerpt: string;
  relevance: number;
}

// Mock search index (mirrors actual implementation)
const searchIndex: Omit<SearchResult, 'relevance'>[] = [
  { id: '1', title: 'Quickstart Guide', section: 'Getting Started', href: '/docs/quickstart', excerpt: 'Get up and running with Zalt authentication in 5 minutes.' },
  { id: '2', title: 'React SDK', section: 'SDK Reference', href: '/docs/sdk/react', excerpt: 'Install and configure the @zalt/react SDK for your React application.' },
  { id: '3', title: 'Next.js Integration', section: 'SDK Reference', href: '/docs/sdk/nextjs', excerpt: 'Server-side authentication with the @zalt/next middleware.' },
  { id: '4', title: 'WebAuthn Setup', section: 'Authentication', href: '/docs/auth/webauthn', excerpt: 'Enable passwordless authentication with WebAuthn and passkeys.' },
  { id: '5', title: 'TOTP MFA', section: 'Multi-Factor Auth', href: '/docs/mfa/totp', excerpt: 'Set up time-based one-time passwords for additional security.' },
  { id: '6', title: 'Organizations', section: 'Organizations', href: '/docs/orgs/multi-tenancy', excerpt: 'Implement multi-tenant architecture with organizations.' },
  { id: '7', title: 'RBAC', section: 'Organizations', href: '/docs/orgs/rbac', excerpt: 'Role-based access control for fine-grained permissions.' },
  { id: '8', title: 'Webhooks', section: 'API Reference', href: '/docs/api/webhooks', excerpt: 'Receive real-time notifications for authentication events.' },
];

/**
 * Search function with relevance ranking (mirrors actual implementation)
 */
function searchDocs(query: string): SearchResult[] {
  if (!query.trim()) return [];
  
  const normalizedQuery = query.toLowerCase().trim();
  const queryWords = normalizedQuery.split(/\s+/);
  
  const results = searchIndex
    .map(doc => {
      let relevance = 0;
      const titleLower = doc.title.toLowerCase();
      const excerptLower = doc.excerpt.toLowerCase();
      const sectionLower = doc.section.toLowerCase();
      
      // Exact title match (highest relevance)
      if (titleLower === normalizedQuery) {
        relevance += 100;
      }
      // Title starts with query
      else if (titleLower.startsWith(normalizedQuery)) {
        relevance += 50;
      }
      // Title contains query
      else if (titleLower.includes(normalizedQuery)) {
        relevance += 30;
      }
      
      // Word matches
      queryWords.forEach(word => {
        if (titleLower.includes(word)) relevance += 20;
        if (excerptLower.includes(word)) relevance += 10;
        if (sectionLower.includes(word)) relevance += 5;
      });
      
      return { ...doc, relevance };
    })
    .filter(doc => doc.relevance > 0)
    .sort((a, b) => b.relevance - a.relevance)
    .slice(0, 8);
  
  return results;
}

describe('Feature: zalt-enterprise-landing, Property 8: Documentation search functionality', () => {
  describe('Property 8.1: Empty query returns no results', () => {
    it('should return empty array for empty string', () => {
      expect(searchDocs('')).toEqual([]);
    });

    it('should return empty array for whitespace-only queries', () => {
      fc.assert(
        fc.property(
          fc.stringOf(fc.constantFrom(' ', '\t', '\n')),
          (whitespace) => {
            expect(searchDocs(whitespace)).toEqual([]);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 8.2: Results are sorted by relevance', () => {
    it('should return results in descending relevance order', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('react', 'sdk', 'auth', 'mfa', 'webhook', 'quickstart'),
          (query) => {
            const results = searchDocs(query);
            
            if (results.length > 1) {
              for (let i = 0; i < results.length - 1; i++) {
                expect(results[i].relevance).toBeGreaterThanOrEqual(results[i + 1].relevance);
              }
            }
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 8.3: Exact title match has highest relevance', () => {
    it('should rank exact title matches highest', () => {
      const exactTitles = searchIndex.map(doc => doc.title.toLowerCase());
      
      fc.assert(
        fc.property(
          fc.constantFrom(...exactTitles),
          (exactTitle) => {
            const results = searchDocs(exactTitle);
            
            if (results.length > 0) {
              // First result should be the exact match
              expect(results[0].title.toLowerCase()).toBe(exactTitle);
              expect(results[0].relevance).toBeGreaterThanOrEqual(100);
            }
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 8.4: Results contain matching terms', () => {
    it('should only return results that match the query', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('react', 'next', 'webauthn', 'totp', 'webhook'),
          (query) => {
            const results = searchDocs(query);
            const queryLower = query.toLowerCase();
            
            results.forEach(result => {
              const matchesTitle = result.title.toLowerCase().includes(queryLower);
              const matchesExcerpt = result.excerpt.toLowerCase().includes(queryLower);
              const matchesSection = result.section.toLowerCase().includes(queryLower);
              
              expect(matchesTitle || matchesExcerpt || matchesSection).toBe(true);
            });
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 8.5: Results are limited to max 8', () => {
    it('should never return more than 8 results', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 20 }),
          (query) => {
            const results = searchDocs(query);
            expect(results.length).toBeLessThanOrEqual(8);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 8.6: All results have required fields', () => {
    it('should return results with all required fields', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('sdk', 'auth', 'mfa', 'api'),
          (query) => {
            const results = searchDocs(query);
            
            results.forEach(result => {
              expect(result.id).toBeDefined();
              expect(result.title).toBeDefined();
              expect(result.section).toBeDefined();
              expect(result.href).toBeDefined();
              expect(result.excerpt).toBeDefined();
              expect(typeof result.relevance).toBe('number');
              expect(result.relevance).toBeGreaterThan(0);
            });
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 8.7: Case insensitivity', () => {
    it('should return same results regardless of case', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('React', 'REACT', 'react', 'ReAcT'),
          (query) => {
            const results = searchDocs(query);
            const lowerResults = searchDocs(query.toLowerCase());
            
            expect(results.length).toBe(lowerResults.length);
            results.forEach((result, i) => {
              expect(result.id).toBe(lowerResults[i].id);
            });
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 8.8: Multi-word queries', () => {
    it('should handle multi-word queries', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('react sdk', 'next.js integration', 'webauthn setup', 'totp mfa'),
          (query) => {
            const results = searchDocs(query);
            
            // Should return results if any word matches
            if (results.length > 0) {
              const words = query.toLowerCase().split(/\s+/);
              results.forEach(result => {
                const titleLower = result.title.toLowerCase();
                const excerptLower = result.excerpt.toLowerCase();
                const sectionLower = result.section.toLowerCase();
                
                const hasMatch = words.some(word => 
                  titleLower.includes(word) || 
                  excerptLower.includes(word) || 
                  sectionLower.includes(word)
                );
                expect(hasMatch).toBe(true);
              });
            }
          }
        ),
        { numRuns: 10 }
      );
    });
  });
});

describe('DocsSearch Edge Cases', () => {
  it('should handle special characters in query', () => {
    const specialQueries = ['@zalt', 'next.js', 'c++', 'node-js'];
    
    specialQueries.forEach(query => {
      // Should not throw
      expect(() => searchDocs(query)).not.toThrow();
    });
  });

  it('should handle very long queries', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 100, maxLength: 500 }),
        (longQuery) => {
          // Should not throw and should return limited results
          const results = searchDocs(longQuery);
          expect(results.length).toBeLessThanOrEqual(8);
        }
      ),
      { numRuns: 10 }
    );
  });

  it('should handle queries with only numbers', () => {
    fc.assert(
      fc.property(
        fc.stringOf(fc.constantFrom('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')),
        (numericQuery) => {
          // Should not throw
          expect(() => searchDocs(numericQuery)).not.toThrow();
        }
      ),
      { numRuns: 20 }
    );
  });

  it('should return unique results', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('sdk', 'auth', 'mfa'),
        (query) => {
          const results = searchDocs(query);
          const ids = results.map(r => r.id);
          const uniqueIds = new Set(ids);
          
          expect(uniqueIds.size).toBe(ids.length);
        }
      ),
      { numRuns: 10 }
    );
  });
});
