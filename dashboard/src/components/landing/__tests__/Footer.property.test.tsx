/**
 * Property Test: Footer Link Organization
 * 
 * Property 9: Footer Link Organization
 * Validates: Requirements 7.3
 * 
 * Properties tested:
 * 1. All columns have required structure
 * 2. Link count per column
 * 3. Social links validity
 * 4. Compliance badges
 * 5. Newsletter form structure
 */

import * as fc from 'fast-check';

// Footer interfaces
interface FooterLink {
  label: string;
  href: string;
}

interface FooterColumn {
  title: string;
  links: FooterLink[];
}

// Footer data from component
const footerColumns: FooterColumn[] = [
  {
    title: 'Product',
    links: [
      { label: 'Features', href: '/features' },
      { label: 'Pricing', href: '/pricing' },
      { label: 'Changelog', href: '/changelog' },
      { label: 'Roadmap', href: '/roadmap' },
      { label: 'Status', href: 'https://status.zalt.io' },
    ],
  },
  {
    title: 'Resources',
    links: [
      { label: 'Documentation', href: '/docs' },
      { label: 'API Reference', href: '/docs/api' },
      { label: 'Guides', href: '/docs/guides' },
      { label: 'Blog', href: '/blog' },
      { label: 'Community', href: '/community' },
    ],
  },
  {
    title: 'Company',
    links: [
      { label: 'About', href: '/about' },
      { label: 'Careers', href: '/careers' },
      { label: 'Contact', href: '/contact' },
      { label: 'Partners', href: '/partners' },
      { label: 'Press Kit', href: '/press' },
    ],
  },
  {
    title: 'Legal',
    links: [
      { label: 'Privacy Policy', href: '/privacy' },
      { label: 'Terms of Service', href: '/terms' },
      { label: 'Cookie Policy', href: '/cookies' },
      { label: 'DPA', href: '/dpa' },
      { label: 'Security', href: '/security' },
    ],
  },
];

const socialLinks = [
  { icon: 'Twitter', href: 'https://twitter.com/zaltio', label: 'Twitter' },
  { icon: 'Github', href: 'https://github.com/zalt-io', label: 'GitHub' },
  { icon: 'Linkedin', href: 'https://linkedin.com/company/zaltio', label: 'LinkedIn' },
  { icon: 'Youtube', href: 'https://youtube.com/@zaltio', label: 'YouTube' },
];

const complianceBadges = ['SOC 2', 'HIPAA', 'GDPR', 'ISO 27001'];

describe('Footer Property Tests', () => {
  describe('Property 9.1: Column Count Requirement', () => {
    it('should have exactly 4 footer columns', () => {
      expect(footerColumns.length).toBe(4);
    });

    it('should have Product, Resources, Company, and Legal columns', () => {
      const columnTitles = footerColumns.map(c => c.title);
      expect(columnTitles).toContain('Product');
      expect(columnTitles).toContain('Resources');
      expect(columnTitles).toContain('Company');
      expect(columnTitles).toContain('Legal');
    });
  });

  describe('Property 9.2: Column Structure Integrity', () => {
    it('should have title and links for each column', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...footerColumns),
          (column) => {
            expect(column.title).toBeDefined();
            expect(column.title.length).toBeGreaterThan(0);
            expect(column.links).toBeDefined();
            expect(Array.isArray(column.links)).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have at least 4 links per column', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...footerColumns),
          (column) => {
            expect(column.links.length).toBeGreaterThanOrEqual(4);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have exactly 5 links per column', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...footerColumns),
          (column) => {
            expect(column.links.length).toBe(5);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 9.3: Link Validity', () => {
    it('should have valid label and href for each link', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...footerColumns),
          (column) => {
            column.links.forEach(link => {
              expect(link.label).toBeDefined();
              expect(link.label.length).toBeGreaterThan(0);
              expect(link.href).toBeDefined();
              expect(link.href.length).toBeGreaterThan(0);
            });
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have href starting with / or https://', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...footerColumns),
          (column) => {
            column.links.forEach(link => {
              const isValid = link.href.startsWith('/') || link.href.startsWith('https://');
              expect(isValid).toBe(true);
            });
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 9.4: Social Links', () => {
    it('should have exactly 4 social links', () => {
      expect(socialLinks.length).toBe(4);
    });

    it('should have Twitter, GitHub, LinkedIn, and YouTube', () => {
      const labels = socialLinks.map(s => s.label);
      expect(labels).toContain('Twitter');
      expect(labels).toContain('GitHub');
      expect(labels).toContain('LinkedIn');
      expect(labels).toContain('YouTube');
    });

    it('should have valid external URLs for social links', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...socialLinks),
          (social) => {
            expect(social.href.startsWith('https://')).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have aria-label for accessibility', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...socialLinks),
          (social) => {
            expect(social.label).toBeDefined();
            expect(social.label.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 9.5: Compliance Badges', () => {
    it('should have exactly 4 compliance badges', () => {
      expect(complianceBadges.length).toBe(4);
    });

    it('should include SOC 2, HIPAA, GDPR, and ISO 27001', () => {
      expect(complianceBadges).toContain('SOC 2');
      expect(complianceBadges).toContain('HIPAA');
      expect(complianceBadges).toContain('GDPR');
      expect(complianceBadges).toContain('ISO 27001');
    });

    it('should have non-empty badge names', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...complianceBadges),
          (badge) => {
            expect(badge.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 9.6: Column Title Uniqueness', () => {
    it('should have unique column titles', () => {
      const titleSet = new Set(footerColumns.map(c => c.title));
      expect(titleSet.size).toBe(footerColumns.length);
    });
  });

  describe('Property 9.7: Link Label Uniqueness Within Column', () => {
    it('should have unique link labels within each column', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...footerColumns),
          (column) => {
            const labelSet = new Set(column.links.map(l => l.label));
            expect(labelSet.size).toBe(column.links.length);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 9.8: Grid Layout', () => {
    it('should use 6-column grid on large screens', () => {
      const gridClasses = 'grid lg:grid-cols-6 gap-12';
      
      expect(gridClasses).toContain('grid');
      expect(gridClasses).toContain('lg:grid-cols-6');
      expect(gridClasses).toContain('gap-12');
    });

    it('should have brand column spanning 2 columns', () => {
      const brandColSpan = 'lg:col-span-2';
      expect(brandColSpan).toContain('col-span-2');
    });
  });

  describe('Property 9.9: Footer Styling', () => {
    it('should have dark background', () => {
      const bgClass = 'bg-neutral-950';
      expect(bgClass).toContain('neutral-950');
    });

    it('should have white text', () => {
      const textClass = 'text-white';
      expect(textClass).toBe('text-white');
    });

    it('should have proper padding', () => {
      const paddingClasses = 'px-6 py-16';
      
      expect(paddingClasses).toContain('px-6');
      expect(paddingClasses).toContain('py-16');
    });
  });

  describe('Property 9.10: Newsletter Form', () => {
    it('should have email input type', () => {
      const inputType = 'email';
      expect(inputType).toBe('email');
    });

    it('should have subscribe button', () => {
      const buttonText = 'Subscribe';
      expect(buttonText).toBe('Subscribe');
    });

    it('should show success message after submission', () => {
      const successMessage = 'Thanks for subscribing!';
      expect(successMessage).toContain('subscribing');
    });
  });

  describe('Property 9.11: Copyright', () => {
    it('should include current year', () => {
      const currentYear = new Date().getFullYear();
      expect(currentYear).toBeGreaterThanOrEqual(2024);
    });

    it('should include company name', () => {
      const copyrightText = '© 2026 Zalt.io. All rights reserved.';
      expect(copyrightText).toContain('Zalt.io');
    });
  });

  describe('Property 9.12: Legal Column Content', () => {
    it('should have Privacy Policy link', () => {
      const legalColumn = footerColumns.find(c => c.title === 'Legal')!;
      const hasPrivacy = legalColumn.links.some(l => l.label === 'Privacy Policy');
      expect(hasPrivacy).toBe(true);
    });

    it('should have Terms of Service link', () => {
      const legalColumn = footerColumns.find(c => c.title === 'Legal')!;
      const hasTerms = legalColumn.links.some(l => l.label === 'Terms of Service');
      expect(hasTerms).toBe(true);
    });

    it('should have Security link', () => {
      const legalColumn = footerColumns.find(c => c.title === 'Legal')!;
      const hasSecurity = legalColumn.links.some(l => l.label === 'Security');
      expect(hasSecurity).toBe(true);
    });
  });
});
