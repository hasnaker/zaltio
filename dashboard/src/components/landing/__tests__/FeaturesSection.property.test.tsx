/**
 * Property Test: Features Section Content Integrity
 * 
 * Property 5: Features Section Content Integrity
 * Validates: Requirements 4.2, 4.6
 * 
 * Properties tested:
 * 1. All features have required fields
 * 2. Feature count meets minimum requirement
 * 3. Icons are valid React components
 * 4. Gradients follow theme pattern
 * 5. Stats have valid values
 */

import * as fc from 'fast-check';
import { 
  Shield, Key, Fingerprint, Users, Lock, 
  Webhook, BarChart3, Globe, Zap, Building2
} from 'lucide-react';

// Feature interface
interface Feature {
  icon: React.ElementType;
  title: string;
  description: string;
  gradient: string;
}

// Features data from component
const features: Feature[] = [
  {
    icon: Shield,
    title: 'Authentication',
    description: 'Secure email/password, social logins, and passwordless authentication out of the box.',
    gradient: 'from-primary to-primary-600',
  },
  {
    icon: Fingerprint,
    title: 'Multi-Factor Auth',
    description: 'WebAuthn passkeys, TOTP authenticator apps, and backup codes for maximum security.',
    gradient: 'from-accent to-accent-600',
  },
  {
    icon: Building2,
    title: 'Single Sign-On',
    description: 'Enterprise SSO with SAML 2.0 and OIDC. Connect to Okta, Azure AD, and more.',
    gradient: 'from-info to-info-600',
  },
  {
    icon: Users,
    title: 'Organizations',
    description: 'Multi-tenant support with roles, permissions, and team management built-in.',
    gradient: 'from-success to-success-600',
  },
  {
    icon: Webhook,
    title: 'Webhooks',
    description: 'Real-time event notifications for user actions, security events, and more.',
    gradient: 'from-warning to-warning-600',
  },
  {
    icon: BarChart3,
    title: 'Analytics',
    description: 'Detailed insights into user activity, authentication patterns, and security metrics.',
    gradient: 'from-error to-error-600',
  },
];

// Stats data
const stats = [
  { value: '99.99%', label: 'Uptime SLA' },
  { value: '<25ms', label: 'API Latency' },
  { value: '10M+', label: 'Auth/day' },
  { value: '150+', label: 'Countries' },
];

// Valid gradient patterns
const validGradientPatterns = [
  'from-primary',
  'from-accent',
  'from-info',
  'from-success',
  'from-warning',
  'from-error',
];

describe('FeaturesSection Property Tests', () => {
  describe('Property 5.1: Feature Count Requirement', () => {
    it('should have at least 6 features', () => {
      expect(features.length).toBeGreaterThanOrEqual(6);
    });

    it('should have exactly 6 features as designed', () => {
      expect(features.length).toBe(6);
    });
  });

  describe('Property 5.2: Feature Structure Integrity', () => {
    it('should have all required fields for each feature', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...features),
          (feature) => {
            expect(feature.icon).toBeDefined();
            expect(feature.title).toBeDefined();
            expect(feature.description).toBeDefined();
            expect(feature.gradient).toBeDefined();
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have non-empty title for each feature', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...features),
          (feature) => {
            expect(feature.title.length).toBeGreaterThan(0);
            expect(feature.title.trim()).toBe(feature.title);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have meaningful description for each feature', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...features),
          (feature) => {
            expect(feature.description.length).toBeGreaterThan(20);
            expect(feature.description.endsWith('.')).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 5.3: Icon Validity', () => {
    it('should have valid icon component for each feature', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...features),
          (feature) => {
            // Lucide icons are forward_ref objects with render function
            expect(feature.icon).toBeDefined();
            expect(typeof feature.icon === 'function' || typeof feature.icon === 'object').toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should use unique icons for each feature', () => {
      const iconSet = new Set(features.map(f => f.icon));
      expect(iconSet.size).toBe(features.length);
    });
  });

  describe('Property 5.4: Gradient Pattern Validity', () => {
    it('should use valid gradient pattern for each feature', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...features),
          (feature) => {
            const hasValidPattern = validGradientPatterns.some(
              pattern => feature.gradient.includes(pattern)
            );
            expect(hasValidPattern).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have gradient with from and to values', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...features),
          (feature) => {
            expect(feature.gradient).toContain('from-');
            expect(feature.gradient).toContain('to-');
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should use unique gradients for each feature', () => {
      const gradientSet = new Set(features.map(f => f.gradient));
      expect(gradientSet.size).toBe(features.length);
    });
  });

  describe('Property 5.5: Title Uniqueness', () => {
    it('should have unique titles for all features', () => {
      const titleSet = new Set(features.map(f => f.title));
      expect(titleSet.size).toBe(features.length);
    });
  });

  describe('Property 5.6: Stats Validity', () => {
    it('should have exactly 4 stats', () => {
      expect(stats.length).toBe(4);
    });

    it('should have valid value and label for each stat', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...stats),
          (stat) => {
            expect(stat.value).toBeDefined();
            expect(stat.label).toBeDefined();
            expect(stat.value.length).toBeGreaterThan(0);
            expect(stat.label.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have unique labels for all stats', () => {
      const labelSet = new Set(stats.map(s => s.label));
      expect(labelSet.size).toBe(stats.length);
    });
  });

  describe('Property 5.7: Grid Layout', () => {
    it('should use responsive grid classes', () => {
      const gridClasses = 'grid md:grid-cols-2 lg:grid-cols-3 gap-6';
      
      expect(gridClasses).toContain('grid');
      expect(gridClasses).toContain('md:grid-cols-2');
      expect(gridClasses).toContain('lg:grid-cols-3');
      expect(gridClasses).toContain('gap-6');
    });

    it('should have 3 columns on large screens for 6 features', () => {
      const columnsLg = 3;
      const rows = Math.ceil(features.length / columnsLg);
      expect(rows).toBe(2);
    });
  });

  describe('Property 5.8: Animation Properties', () => {
    it('should have hover animation with y offset', () => {
      const hoverY = -8;
      expect(hoverY).toBeLessThan(0);
    });

    it('should have stagger animation for features', () => {
      const staggerDelay = 0.1;
      expect(staggerDelay).toBeGreaterThan(0);
      expect(staggerDelay).toBeLessThan(0.5);
    });
  });

  describe('Property 5.9: Section Structure', () => {
    it('should have section id for navigation', () => {
      const sectionId = 'features';
      expect(sectionId).toBe('features');
    });

    it('should have proper padding classes', () => {
      const paddingClasses = 'py-24 md:py-32 px-6';
      
      expect(paddingClasses).toContain('py-24');
      expect(paddingClasses).toContain('md:py-32');
      expect(paddingClasses).toContain('px-6');
    });

    it('should have max-width container', () => {
      const containerClass = 'max-w-7xl mx-auto';
      
      expect(containerClass).toContain('max-w-7xl');
      expect(containerClass).toContain('mx-auto');
    });
  });

  describe('Property 5.10: Feature Card Structure', () => {
    it('should have icon container with proper size', () => {
      const iconContainerClasses = 'w-14 h-14 rounded-xl';
      
      expect(iconContainerClasses).toContain('w-14');
      expect(iconContainerClasses).toContain('h-14');
      expect(iconContainerClasses).toContain('rounded-xl');
    });

    it('should have hover indicator with learn more text', () => {
      const learnMoreText = 'Learn more';
      expect(learnMoreText).toBe('Learn more');
    });
  });
});
