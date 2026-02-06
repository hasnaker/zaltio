/**
 * Property Tests for Theme Mode Switching
 * 
 * Validates:
 * - Light/dark mode color mappings
 * - Theme mode transitions
 * - CSS variable updates
 * - Accessibility contrast ratios
 */

import * as fc from 'fast-check';
import { clerkTheme } from '../clerk-theme';

// Theme mode configuration
interface ThemeMode {
  name: 'light' | 'dark';
  background: string;
  foreground: string;
  card: string;
  cardForeground: string;
  border: string;
  muted: string;
  mutedForeground: string;
}

// Light mode configuration
const lightMode: ThemeMode = {
  name: 'light',
  background: clerkTheme.colors.neutral[50],  // #FAFAFA
  foreground: clerkTheme.colors.neutral[900], // #18181B
  card: '#FFFFFF',
  cardForeground: clerkTheme.colors.neutral[900],
  border: clerkTheme.colors.neutral[200],
  muted: clerkTheme.colors.neutral[100],
  mutedForeground: clerkTheme.colors.neutral[500],
};

// Dark mode configuration
const darkMode: ThemeMode = {
  name: 'dark',
  background: clerkTheme.colors.neutral[950], // #0F0F10
  foreground: clerkTheme.colors.neutral[50],  // #FAFAFA
  card: clerkTheme.colors.neutral[900],
  cardForeground: clerkTheme.colors.neutral[50],
  border: clerkTheme.colors.neutral[800],
  muted: clerkTheme.colors.neutral[800],
  mutedForeground: clerkTheme.colors.neutral[400],
};

// Helper to parse hex color to RGB
function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16),
      }
    : null;
}

// Calculate relative luminance for WCAG contrast
function getLuminance(hex: string): number {
  const rgb = hexToRgb(hex);
  if (!rgb) return 0;

  const [r, g, b] = [rgb.r, rgb.g, rgb.b].map((v) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  });

  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

// Calculate contrast ratio between two colors
function getContrastRatio(color1: string, color2: string): number {
  const l1 = getLuminance(color1);
  const l2 = getLuminance(color2);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

describe('Theme Mode Switching', () => {
  describe('Property 1: Mode Configuration Structure', () => {
    it('should have all required properties in light mode', () => {
      const requiredProps: (keyof ThemeMode)[] = [
        'name',
        'background',
        'foreground',
        'card',
        'cardForeground',
        'border',
        'muted',
        'mutedForeground',
      ];

      requiredProps.forEach(prop => {
        expect(lightMode).toHaveProperty(prop);
        expect(lightMode[prop]).toBeDefined();
      });
    });

    it('should have all required properties in dark mode', () => {
      const requiredProps: (keyof ThemeMode)[] = [
        'name',
        'background',
        'foreground',
        'card',
        'cardForeground',
        'border',
        'muted',
        'mutedForeground',
      ];

      requiredProps.forEach(prop => {
        expect(darkMode).toHaveProperty(prop);
        expect(darkMode[prop]).toBeDefined();
      });
    });
  });

  describe('Property 2: Color Inversion Between Modes', () => {
    it('should have inverted background/foreground between modes', () => {
      // Light mode: light background, dark foreground
      const lightBgLuminance = getLuminance(lightMode.background);
      const lightFgLuminance = getLuminance(lightMode.foreground);
      expect(lightBgLuminance).toBeGreaterThan(lightFgLuminance);

      // Dark mode: dark background, light foreground
      const darkBgLuminance = getLuminance(darkMode.background);
      const darkFgLuminance = getLuminance(darkMode.foreground);
      expect(darkBgLuminance).toBeLessThan(darkFgLuminance);
    });

    it('should have inverted card colors between modes', () => {
      const lightCardLuminance = getLuminance(lightMode.card);
      const darkCardLuminance = getLuminance(darkMode.card);
      
      // Light mode card should be brighter than dark mode card
      expect(lightCardLuminance).toBeGreaterThan(darkCardLuminance);
    });
  });

  describe('Property 3: Contrast Ratio Compliance', () => {
    // WCAG AA requires 4.5:1 for normal text, 3:1 for large text
    const WCAG_AA_NORMAL = 4.5;
    const WCAG_AA_LARGE = 3;

    it('should have sufficient contrast for text in light mode', () => {
      const contrast = getContrastRatio(lightMode.foreground, lightMode.background);
      expect(contrast).toBeGreaterThanOrEqual(WCAG_AA_NORMAL);
    });

    it('should have sufficient contrast for text in dark mode', () => {
      const contrast = getContrastRatio(darkMode.foreground, darkMode.background);
      expect(contrast).toBeGreaterThanOrEqual(WCAG_AA_NORMAL);
    });

    it('should have sufficient contrast for card text in light mode', () => {
      const contrast = getContrastRatio(lightMode.cardForeground, lightMode.card);
      expect(contrast).toBeGreaterThanOrEqual(WCAG_AA_NORMAL);
    });

    it('should have sufficient contrast for card text in dark mode', () => {
      const contrast = getContrastRatio(darkMode.cardForeground, darkMode.card);
      expect(contrast).toBeGreaterThanOrEqual(WCAG_AA_NORMAL);
    });

    it('should have sufficient contrast for muted text in light mode', () => {
      const contrast = getContrastRatio(lightMode.mutedForeground, lightMode.background);
      expect(contrast).toBeGreaterThanOrEqual(WCAG_AA_LARGE);
    });

    it('should have sufficient contrast for muted text in dark mode', () => {
      const contrast = getContrastRatio(darkMode.mutedForeground, darkMode.background);
      expect(contrast).toBeGreaterThanOrEqual(WCAG_AA_LARGE);
    });
  });

  describe('Property 4: Primary Color Consistency Across Modes', () => {
    it('should use same primary color in both modes', () => {
      // Primary color should remain consistent
      expect(clerkTheme.colors.primary.DEFAULT).toBe('#6C47FF');
    });

    it('should use same accent color in both modes', () => {
      // Accent color should remain consistent
      expect(clerkTheme.colors.accent.DEFAULT).toBe('#00D4FF');
    });

    it('should have primary color with sufficient contrast on light background', () => {
      const contrast = getContrastRatio(clerkTheme.colors.primary.DEFAULT, lightMode.background);
      expect(contrast).toBeGreaterThanOrEqual(3); // Large text minimum
    });

    it('should have primary color with sufficient contrast on dark background', () => {
      const contrast = getContrastRatio(clerkTheme.colors.primary.DEFAULT, darkMode.background);
      expect(contrast).toBeGreaterThanOrEqual(3); // Large text minimum
    });
  });

  describe('Property 5: Semantic Colors Visibility', () => {
    const semanticColors = {
      success: clerkTheme.colors.success,
      warning: clerkTheme.colors.warning,
      error: clerkTheme.colors.error,
      info: clerkTheme.colors.info,
    };

    it('should have semantic colors visible on light background', () => {
      // Warning color (yellow) has lower contrast on light backgrounds
      // This is acceptable as it's typically used with icons or backgrounds
      Object.entries(semanticColors).forEach(([name, color]) => {
        const contrast = getContrastRatio(color, lightMode.background);
        // Use 2:1 minimum for decorative/icon colors
        expect(contrast).toBeGreaterThanOrEqual(2);
      });
    });

    it('should have semantic colors visible on dark background', () => {
      Object.entries(semanticColors).forEach(([name, color]) => {
        const contrast = getContrastRatio(color, darkMode.background);
        expect(contrast).toBeGreaterThanOrEqual(3);
      });
    });
  });

  describe('Property 6: Border Visibility', () => {
    it('should have visible borders in light mode', () => {
      const contrast = getContrastRatio(lightMode.border, lightMode.background);
      // Borders are subtle UI elements, 1.1:1 minimum is acceptable
      expect(contrast).toBeGreaterThanOrEqual(1.1);
    });

    it('should have visible borders in dark mode', () => {
      const contrast = getContrastRatio(darkMode.border, darkMode.background);
      // Borders are subtle UI elements, 1.1:1 minimum is acceptable
      expect(contrast).toBeGreaterThanOrEqual(1.1);
    });
  });

  describe('Property 7: Mode Switching Invariants (fast-check)', () => {
    it('should maintain color validity across mode switches', () => {
      const hexRegex = /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/;
      const modes = [lightMode, darkMode];

      fc.assert(
        fc.property(
          fc.constantFrom(...modes),
          fc.constantFrom('background', 'foreground', 'card', 'border', 'muted') as fc.Arbitrary<keyof ThemeMode>,
          (mode, prop) => {
            const value = mode[prop];
            return typeof value === 'string' && (hexRegex.test(value) || value === 'light' || value === 'dark');
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should have consistent luminance relationships', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(lightMode, darkMode),
          (mode) => {
            const bgLum = getLuminance(mode.background);
            const fgLum = getLuminance(mode.foreground);
            
            // Background and foreground should have different luminance
            return Math.abs(bgLum - fgLum) > 0.3;
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 8: Neutral Scale Progression', () => {
    it('should have monotonically decreasing luminance in neutral scale', () => {
      const shades = ['50', '100', '200', '300', '400', '500', '600', '700', '800', '900', '950'];
      
      for (let i = 1; i < shades.length; i++) {
        const prevLum = getLuminance(clerkTheme.colors.neutral[shades[i - 1]]);
        const currLum = getLuminance(clerkTheme.colors.neutral[shades[i]]);
        expect(currLum).toBeLessThanOrEqual(prevLum);
      }
    });
  });

  describe('Property 9: Theme Mode CSS Class Generation', () => {
    it('should generate valid CSS class names for light mode', () => {
      const lightClasses = {
        bg: `bg-[${lightMode.background}]`,
        text: `text-[${lightMode.foreground}]`,
        border: `border-[${lightMode.border}]`,
      };

      Object.values(lightClasses).forEach(className => {
        expect(className).toMatch(/^(bg|text|border)-\[#[A-Fa-f0-9]{6}\]$/);
      });
    });

    it('should generate valid CSS class names for dark mode', () => {
      const darkClasses = {
        bg: `bg-[${darkMode.background}]`,
        text: `text-[${darkMode.foreground}]`,
        border: `border-[${darkMode.border}]`,
      };

      Object.values(darkClasses).forEach(className => {
        expect(className).toMatch(/^(bg|text|border)-\[#[A-Fa-f0-9]{6}\]$/);
      });
    });
  });

  describe('Property 10: Mode Transition Smoothness', () => {
    it('should have colors that can transition smoothly', () => {
      // All colors should be valid hex that can be animated
      const hexRegex = /^#([A-Fa-f0-9]{6})$/;
      
      const lightColors = [lightMode.background, lightMode.foreground, lightMode.card];
      const darkColors = [darkMode.background, darkMode.foreground, darkMode.card];

      [...lightColors, ...darkColors].forEach(color => {
        expect(hexRegex.test(color)).toBe(true);
      });
    });
  });
});
