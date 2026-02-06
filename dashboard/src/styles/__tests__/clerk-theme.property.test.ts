/**
 * Property Tests for Clerk Theme Token Consistency
 * 
 * Validates:
 * - Theme token structure and completeness
 * - Color palette consistency
 * - Gradient definitions
 * - Typography scale
 * - Spacing scale
 * - Shadow definitions
 */

import * as fc from 'fast-check';
import { clerkTheme, ClerkTheme, cssVariables, tailwindClasses } from '../clerk-theme';

describe('Clerk Theme Token Consistency', () => {
  describe('Property 1: Theme Structure Completeness', () => {
    it('should have all required top-level keys', () => {
      const requiredKeys: (keyof ClerkTheme)[] = [
        'colors',
        'gradients',
        'typography',
        'spacing',
        'borderRadius',
        'shadows',
      ];

      requiredKeys.forEach(key => {
        expect(clerkTheme).toHaveProperty(key);
        expect(clerkTheme[key]).toBeDefined();
        expect(typeof clerkTheme[key]).toBe('object');
      });
    });

    it('should have colors with all required palettes', () => {
      const requiredColorPalettes = ['primary', 'accent', 'neutral'];
      const requiredSemanticColors = ['success', 'warning', 'error', 'info'];

      requiredColorPalettes.forEach(palette => {
        expect(clerkTheme.colors).toHaveProperty(palette);
        expect(typeof clerkTheme.colors[palette as keyof typeof clerkTheme.colors]).toBe('object');
      });

      requiredSemanticColors.forEach(color => {
        expect(clerkTheme.colors).toHaveProperty(color);
        expect(typeof clerkTheme.colors[color as keyof typeof clerkTheme.colors]).toBe('string');
      });
    });
  });

  describe('Property 2: Color Value Format', () => {
    const hexColorRegex = /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/;

    it('should have valid hex colors for primary palette', () => {
      Object.entries(clerkTheme.colors.primary).forEach(([key, value]) => {
        const isValid = hexColorRegex.test(value) || key === 'DEFAULT';
        expect(isValid).toBe(true);
      });
    });

    it('should have valid hex colors for accent palette', () => {
      Object.entries(clerkTheme.colors.accent).forEach(([key, value]) => {
        const isValid = hexColorRegex.test(value) || key === 'DEFAULT';
        expect(isValid).toBe(true);
      });
    });

    it('should have valid hex colors for neutral palette', () => {
      Object.entries(clerkTheme.colors.neutral).forEach(([key, value]) => {
        expect(hexColorRegex.test(value)).toBe(true);
      });
    });

    it('should have valid hex colors for semantic colors', () => {
      const semanticColors = ['success', 'warning', 'error', 'info'] as const;
      semanticColors.forEach(color => {
        const value = clerkTheme.colors[color];
        expect(hexColorRegex.test(value)).toBe(true);
      });
    });
  });

  describe('Property 3: Color Palette Scale', () => {
    it('should have consistent shade scale for primary colors', () => {
      const expectedShades = ['50', '100', '200', '300', '400', '500', '600', '700', '800', '900'];
      const primaryKeys = Object.keys(clerkTheme.colors.primary).filter(k => k !== 'DEFAULT');
      
      expectedShades.forEach(shade => {
        expect(primaryKeys).toContain(shade);
      });
    });

    it('should have consistent shade scale for neutral colors', () => {
      const expectedShades = ['50', '100', '200', '300', '400', '500', '600', '700', '800', '900', '950'];
      const neutralKeys = Object.keys(clerkTheme.colors.neutral);
      
      expectedShades.forEach(shade => {
        expect(neutralKeys).toContain(shade);
      });
    });
  });

  describe('Property 4: Gradient Definitions', () => {
    const gradientRegex = /^(linear-gradient|radial-gradient)\(/;

    it('should have valid gradient syntax for all gradients', () => {
      Object.entries(clerkTheme.gradients).forEach(([key, value]) => {
        expect(gradientRegex.test(value)).toBe(true);
      });
    });

    it('should have required gradient types', () => {
      const requiredGradients = [
        'primary',
        'primaryHover',
        'text',
        'card',
        'border',
        'mesh',
        'hero',
        'dark',
      ];

      requiredGradients.forEach(gradient => {
        expect(clerkTheme.gradients).toHaveProperty(gradient);
      });
    });
  });

  describe('Property 5: Typography Scale', () => {
    it('should have font family definitions', () => {
      expect(clerkTheme.typography.fontFamily).toHaveProperty('sans');
      expect(clerkTheme.typography.fontFamily).toHaveProperty('mono');
      expect(typeof clerkTheme.typography.fontFamily.sans).toBe('string');
      expect(typeof clerkTheme.typography.fontFamily.mono).toBe('string');
    });

    it('should have consistent font size scale', () => {
      const expectedSizes = ['xs', 'sm', 'base', 'lg', 'xl', '2xl', '3xl', '4xl', '5xl', '6xl'];
      
      expectedSizes.forEach(size => {
        expect(clerkTheme.typography.fontSize).toHaveProperty(size);
        expect(clerkTheme.typography.fontSize[size]).toMatch(/^\d+(\.\d+)?rem$/);
      });
    });

    it('should have font weight definitions', () => {
      const expectedWeights = ['normal', 'medium', 'semibold', 'bold'];
      
      expectedWeights.forEach(weight => {
        expect(clerkTheme.typography.fontWeight).toHaveProperty(weight);
        expect(typeof clerkTheme.typography.fontWeight[weight]).toBe('number');
        expect(clerkTheme.typography.fontWeight[weight]).toBeGreaterThanOrEqual(100);
        expect(clerkTheme.typography.fontWeight[weight]).toBeLessThanOrEqual(900);
      });
    });

    it('should have line height definitions', () => {
      const expectedLineHeights = ['none', 'tight', 'normal', 'relaxed'];
      
      expectedLineHeights.forEach(lh => {
        expect(clerkTheme.typography.lineHeight).toHaveProperty(lh);
        expect(typeof clerkTheme.typography.lineHeight[lh]).toBe('number');
      });
    });
  });

  describe('Property 6: Spacing Scale', () => {
    it('should have base spacing values', () => {
      const baseSpacings = ['0', '1', '2', '4', '8', '16'];
      
      baseSpacings.forEach(space => {
        expect(clerkTheme.spacing).toHaveProperty(space);
      });
    });

    it('should have valid rem values for spacing', () => {
      Object.entries(clerkTheme.spacing).forEach(([key, value]) => {
        if (key !== '0' && key !== 'px') {
          const isValid = value.endsWith('rem') || value === '0';
          expect(isValid).toBe(true);
        }
      });
    });

    it('should have increasing spacing values', () => {
      const numericKeys = Object.keys(clerkTheme.spacing)
        .filter(k => !isNaN(Number(k)) && k !== '0')
        .map(Number)
        .sort((a, b) => a - b);

      for (let i = 1; i < numericKeys.length; i++) {
        const prevValue = parseFloat(clerkTheme.spacing[numericKeys[i - 1].toString()]);
        const currValue = parseFloat(clerkTheme.spacing[numericKeys[i].toString()]);
        expect(currValue).toBeGreaterThan(prevValue);
      }
    });
  });

  describe('Property 7: Border Radius Scale', () => {
    it('should have required border radius values', () => {
      const requiredRadii = ['none', 'sm', 'DEFAULT', 'md', 'lg', 'xl', 'full'];
      
      requiredRadii.forEach(radius => {
        expect(clerkTheme.borderRadius).toHaveProperty(radius);
      });
    });

    it('should have valid rem or px values', () => {
      Object.entries(clerkTheme.borderRadius).forEach(([key, value]) => {
        const isValid = value === '0' || value.endsWith('rem') || value.endsWith('px');
        expect(isValid).toBe(true);
      });
    });
  });

  describe('Property 8: Shadow Definitions', () => {
    it('should have standard shadow levels', () => {
      const standardShadows = ['sm', 'DEFAULT', 'md', 'lg', 'xl', '2xl', 'none'];
      
      standardShadows.forEach(shadow => {
        expect(clerkTheme.shadows).toHaveProperty(shadow);
      });
    });

    it('should have glow effect shadows', () => {
      const glowShadows = ['glow', 'glowMd', 'glowLg'];
      
      glowShadows.forEach(shadow => {
        expect(clerkTheme.shadows).toHaveProperty(shadow);
        expect(clerkTheme.shadows[shadow]).toContain('rgba');
      });
    });

    it('should have card hover shadows', () => {
      expect(clerkTheme.shadows).toHaveProperty('cardHover');
      expect(clerkTheme.shadows.cardHover).toContain('rgba');
    });

    it('should have focus ring shadows', () => {
      expect(clerkTheme.shadows).toHaveProperty('focus');
      expect(clerkTheme.shadows.focus).toContain('rgba');
    });
  });

  describe('Property 9: CSS Variables Export', () => {
    it('should export CSS variables with correct format', () => {
      Object.entries(cssVariables).forEach(([key, value]) => {
        expect(key.startsWith('--')).toBe(true);
        expect(value).toBeDefined();
        expect(typeof value).toBe('string');
      });
    });

    it('should include primary color variables', () => {
      expect(cssVariables).toHaveProperty('--color-primary');
      expect(cssVariables['--color-primary']).toBe(clerkTheme.colors.primary.DEFAULT);
    });

    it('should include gradient variables', () => {
      expect(cssVariables).toHaveProperty('--gradient-primary');
      expect(cssVariables['--gradient-primary']).toBe(clerkTheme.gradients.primary);
    });
  });

  describe('Property 10: Tailwind Classes Export', () => {
    it('should export gradient text class', () => {
      expect(tailwindClasses).toHaveProperty('gradientText');
      expect(tailwindClasses.gradientText).toContain('bg-gradient');
      expect(tailwindClasses.gradientText).toContain('text-transparent');
    });

    it('should export card classes', () => {
      expect(tailwindClasses).toHaveProperty('card');
      expect(tailwindClasses).toHaveProperty('cardHover');
    });

    it('should export button classes', () => {
      expect(tailwindClasses).toHaveProperty('buttonPrimary');
      expect(tailwindClasses).toHaveProperty('buttonSecondary');
      expect(tailwindClasses).toHaveProperty('buttonOutline');
    });

    it('should export focus ring class', () => {
      expect(tailwindClasses).toHaveProperty('focusRing');
      expect(tailwindClasses.focusRing).toContain('focus:');
    });
  });

  describe('Property 11: Primary Color Consistency', () => {
    it('should use #6C47FF as primary DEFAULT', () => {
      expect(clerkTheme.colors.primary.DEFAULT).toBe('#6C47FF');
    });

    it('should use #00D4FF as accent DEFAULT', () => {
      expect(clerkTheme.colors.accent.DEFAULT).toBe('#00D4FF');
    });

    it('should have primary color in gradients', () => {
      expect(clerkTheme.gradients.primary).toContain('#6C47FF');
      expect(clerkTheme.gradients.text).toContain('#6C47FF');
    });

    it('should have primary color in glow shadows', () => {
      expect(clerkTheme.shadows.glow).toContain('108, 71, 255'); // RGB of #6C47FF
    });
  });

  describe('Property 12: Arbitrary Theme Values (fast-check)', () => {
    it('should have valid color values for any palette shade', () => {
      const hexRegex = /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/;
      
      fc.assert(
        fc.property(
          fc.constantFrom(...Object.keys(clerkTheme.colors.primary).filter(k => k !== 'DEFAULT')),
          (shade) => {
            const value = clerkTheme.colors.primary[shade];
            return hexRegex.test(value);
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should have valid spacing values for any numeric key', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...Object.keys(clerkTheme.spacing).filter(k => !isNaN(Number(k)) && k !== '0')),
          (key) => {
            const value = clerkTheme.spacing[key];
            return value.endsWith('rem');
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should have consistent gradient structure', () => {
      const gradientRegex = /^(linear-gradient|radial-gradient)\(/;
      
      fc.assert(
        fc.property(
          fc.constantFrom(...Object.keys(clerkTheme.gradients)),
          (gradientKey) => {
            const value = clerkTheme.gradients[gradientKey];
            return gradientRegex.test(value);
          }
        ),
        { numRuns: 15 }
      );
    });
  });
});
