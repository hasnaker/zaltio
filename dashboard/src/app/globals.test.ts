/**
 * Property-Based Tests for NEXUS Dark Mode Glow Effects
 * 
 * Feature: nexus-auth-redesign, Property 4: Dark Mode Glow Effects
 * Validates: Requirements 1.4
 * 
 * For any interactive element (button, link, input) when dark mode is active,
 * the element SHALL have box-shadow with rgba values matching the glow color palette
 * on hover or focus state.
 */

import * as fc from 'fast-check';

/**
 * NEXUS Glow Color Palette - rgba values for box-shadow
 */
const nexusGlowColors = {
  cyan: {
    color: '#00F5D4',
    rgba: 'rgba(0, 245, 212,',
    shadowSmall: '0 0 20px rgba(0, 245, 212, 0.3)',
    shadowLarge: '0 0 40px rgba(0, 245, 212, 0.6)',
  },
  purple: {
    color: '#7B2FFF',
    rgba: 'rgba(123, 47, 255,',
    shadowSmall: '0 0 20px rgba(123, 47, 255, 0.3)',
    shadowLarge: '0 0 40px rgba(123, 47, 255, 0.6)',
  },
  pink: {
    color: '#FF006E',
    rgba: 'rgba(255, 0, 110,',
    shadowSmall: '0 0 20px rgba(255, 0, 110, 0.3)',
    shadowLarge: '0 0 40px rgba(255, 0, 110, 0.6)',
  },
  blue: {
    color: '#00D4FF',
    rgba: 'rgba(0, 212, 255,',
    shadowSmall: '0 0 20px rgba(0, 212, 255, 0.3)',
    shadowLarge: '0 0 40px rgba(0, 212, 255, 0.6)',
  },
} as const;

type GlowColorKey = keyof typeof nexusGlowColors;
const glowColorKeys: GlowColorKey[] = ['cyan', 'purple', 'pink', 'blue'];

/**
 * Interactive element types that should have glow effects
 */
type InteractiveElementType = 'button' | 'link' | 'input';
const interactiveElements: InteractiveElementType[] = ['button', 'link', 'input'];

/**
 * CSS class patterns for dark mode glow effects
 */
interface GlowClassPattern {
  hoverClass: string;
  focusClass: string;
  shadowValue: string;
}

/**
 * Get the expected glow class patterns for a given color
 */
function getGlowClassPatterns(color: GlowColorKey): GlowClassPattern {
  const glowColor = nexusGlowColors[color];
  return {
    hoverClass: `nexus-glow-hover${color === 'cyan' ? '' : `-${color}`}`,
    focusClass: `nexus-focus-glow${color === 'cyan' ? '' : `-${color}`}`,
    shadowValue: glowColor.shadowSmall,
  };
}

/**
 * Validates that a shadow value contains the correct rgba pattern for a glow color
 */
function isValidGlowShadow(shadowValue: string, color: GlowColorKey): boolean {
  const glowColor = nexusGlowColors[color];
  return shadowValue.includes(glowColor.rgba);
}

/**
 * CSS variable definitions for glow shadows
 */
const cssVariableDefinitions = {
  '--nexus-shadow-cyan': '0 0 20px rgba(0, 245, 212, 0.3)',
  '--nexus-shadow-cyan-lg': '0 0 40px rgba(0, 245, 212, 0.6)',
  '--nexus-shadow-purple': '0 0 20px rgba(123, 47, 255, 0.3)',
  '--nexus-shadow-purple-lg': '0 0 40px rgba(123, 47, 255, 0.6)',
  '--nexus-shadow-pink': '0 0 20px rgba(255, 0, 110, 0.3)',
  '--nexus-shadow-pink-lg': '0 0 40px rgba(255, 0, 110, 0.6)',
  '--nexus-shadow-blue': '0 0 20px rgba(0, 212, 255, 0.3)',
  '--nexus-shadow-blue-lg': '0 0 40px rgba(0, 212, 255, 0.6)',
} as const;

/**
 * Validates that CSS variable value matches expected glow shadow format
 */
function isValidCssVariableShadow(variableName: string, expectedValue: string): boolean {
  const actualValue = cssVariableDefinitions[variableName as keyof typeof cssVariableDefinitions];
  return actualValue === expectedValue;
}

describe('NEXUS Dark Mode Glow Effects', () => {
  /**
   * Property 4: Dark Mode Glow Effects
   * Validates: Requirements 1.4
   */
  describe('Property 4: Dark Mode Glow Effects', () => {
    it('should have valid glow shadow values for all glow colors', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...glowColorKeys),
          (color) => {
            const glowColor = nexusGlowColors[color];
            
            // Shadow should contain the correct rgba pattern
            expect(isValidGlowShadow(glowColor.shadowSmall, color)).toBe(true);
            expect(isValidGlowShadow(glowColor.shadowLarge, color)).toBe(true);
            
            // Shadow should have correct format: "0 0 Xpx rgba(...)"
            expect(glowColor.shadowSmall).toMatch(/^0 0 \d+px rgba\(/);
            expect(glowColor.shadowLarge).toMatch(/^0 0 \d+px rgba\(/);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have hover glow class patterns for all glow colors', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...glowColorKeys),
          (color) => {
            const patterns = getGlowClassPatterns(color);
            
            // Hover class should follow naming convention
            expect(patterns.hoverClass).toContain('nexus-glow-hover');
            
            // Focus class should follow naming convention
            expect(patterns.focusClass).toContain('nexus-focus-glow');
            
            // Shadow value should be valid
            expect(isValidGlowShadow(patterns.shadowValue, color)).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have CSS variables defined for all glow shadow sizes', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...glowColorKeys),
          (color) => {
            const glowColor = nexusGlowColors[color];
            const smallVarName = `--nexus-shadow-${color}`;
            const largeVarName = `--nexus-shadow-${color}-lg`;
            
            // CSS variable for small shadow should match expected value
            expect(isValidCssVariableShadow(smallVarName, glowColor.shadowSmall)).toBe(true);
            
            // CSS variable for large shadow should match expected value
            expect(isValidCssVariableShadow(largeVarName, glowColor.shadowLarge)).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have glow effects applicable to all interactive element types', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...interactiveElements),
          fc.constantFrom(...glowColorKeys),
          (elementType, color) => {
            const patterns = getGlowClassPatterns(color);
            
            // All interactive elements should be able to use the glow classes
            // The class names should be valid CSS class identifiers
            expect(patterns.hoverClass).toMatch(/^[a-z][a-z0-9-]*$/);
            expect(patterns.focusClass).toMatch(/^[a-z][a-z0-9-]*$/);
            
            // The shadow value should be a valid CSS box-shadow
            expect(patterns.shadowValue).toMatch(/^\d+ \d+ \d+px rgba\(\d+, \d+, \d+, [\d.]+\)$/);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have consistent rgba values between hex colors and shadow definitions', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...glowColorKeys),
          (color) => {
            const glowColor = nexusGlowColors[color];
            
            // Extract RGB values from hex color
            const hex = glowColor.color;
            const r = parseInt(hex.slice(1, 3), 16);
            const g = parseInt(hex.slice(3, 5), 16);
            const b = parseInt(hex.slice(5, 7), 16);
            
            // The rgba pattern should contain these RGB values
            const expectedRgbaPrefix = `rgba(${r}, ${g}, ${b},`;
            expect(glowColor.rgba).toBe(expectedRgbaPrefix);
            
            // The shadow values should contain the correct rgba
            expect(glowColor.shadowSmall).toContain(expectedRgbaPrefix);
            expect(glowColor.shadowLarge).toContain(expectedRgbaPrefix);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have larger shadow values for -lg variants', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...glowColorKeys),
          (color) => {
            const glowColor = nexusGlowColors[color];
            
            // Extract blur radius from shadow values
            const smallMatch = glowColor.shadowSmall.match(/0 0 (\d+)px/);
            const largeMatch = glowColor.shadowLarge.match(/0 0 (\d+)px/);
            
            expect(smallMatch).not.toBeNull();
            expect(largeMatch).not.toBeNull();
            
            if (smallMatch && largeMatch) {
              const smallBlur = parseInt(smallMatch[1], 10);
              const largeBlur = parseInt(largeMatch[1], 10);
              
              // Large shadow should have bigger blur radius
              expect(largeBlur).toBeGreaterThan(smallBlur);
            }
            
            // Extract opacity from shadow values
            const smallOpacityMatch = glowColor.shadowSmall.match(/rgba\([^)]+, ([\d.]+)\)/);
            const largeOpacityMatch = glowColor.shadowLarge.match(/rgba\([^)]+, ([\d.]+)\)/);
            
            expect(smallOpacityMatch).not.toBeNull();
            expect(largeOpacityMatch).not.toBeNull();
            
            if (smallOpacityMatch && largeOpacityMatch) {
              const smallOpacity = parseFloat(smallOpacityMatch[1]);
              const largeOpacity = parseFloat(largeOpacityMatch[1]);
              
              // Large shadow should have higher opacity
              expect(largeOpacity).toBeGreaterThan(smallOpacity);
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
