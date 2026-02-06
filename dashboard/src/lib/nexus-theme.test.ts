/**
 * Property-Based Tests for NEXUS Theme Color Configuration
 * 
 * Feature: nexus-auth-redesign, Property 1: Theme Color Configuration Correctness
 * Validates: Requirements 1.1
 * 
 * For any NEXUS theme configuration object, all color values SHALL be valid hex codes
 * matching the specified palette: cosmic black (#0A0E1A), nebula blue (#1A1F35),
 * bioluminescent cyan (#00F5D4), quantum purple (#7B2FFF), and plasma pink (#FF006E).
 */

import * as fc from 'fast-check';
import { 
  nexusTheme, 
  isValidHexColor, 
  getAllColorValues,
  isValidFontFamily,
  fontFamilyContains,
  getAllTypographyValues,
} from './nexus-theme';

describe('NEXUS Theme Color Configuration', () => {
  /**
   * Property 1: Theme Color Configuration Correctness
   * Validates: Requirements 1.1
   * 
   * For any color in the NEXUS theme, it should be a valid hex color code.
   */
  describe('Property 1: All theme colors are valid hex codes', () => {
    const allColors = getAllColorValues(nexusTheme.colors);
    
    it('should have all colors as valid hex codes', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...allColors),
          (colorEntry) => {
            const { path, value } = colorEntry;
            const isValid = isValidHexColor(value);
            if (!isValid) {
              throw new Error(`Color at path "${path}" with value "${value}" is not a valid hex code`);
            }
            return isValid;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should contain the required cosmic black color (#0A0E1A)', () => {
      expect(nexusTheme.colors.cosmic.black).toBe('#0A0E1A');
      expect(nexusTheme.requiredColors.cosmicBlack).toBe('#0A0E1A');
    });

    it('should contain the required nebula blue color (#1A1F35)', () => {
      expect(nexusTheme.colors.cosmic.nebula).toBe('#1A1F35');
      expect(nexusTheme.requiredColors.nebulaBlue).toBe('#1A1F35');
    });

    it('should contain the required bioluminescent cyan color (#00F5D4)', () => {
      expect(nexusTheme.colors.glow.cyan).toBe('#00F5D4');
      expect(nexusTheme.requiredColors.bioluminescentCyan).toBe('#00F5D4');
    });

    it('should contain the required quantum purple color (#7B2FFF)', () => {
      expect(nexusTheme.colors.glow.purple).toBe('#7B2FFF');
      expect(nexusTheme.requiredColors.quantumPurple).toBe('#7B2FFF');
    });

    it('should contain the required plasma pink color (#FF006E)', () => {
      expect(nexusTheme.colors.glow.pink).toBe('#FF006E');
      expect(nexusTheme.requiredColors.plasmaPink).toBe('#FF006E');
    });
  });

  describe('Property 1: Color value format validation', () => {
    it('should validate hex color format for any generated color-like string', () => {
      fc.assert(
        fc.property(
          fc.hexaString({ minLength: 6, maxLength: 6 }),
          (hexString) => {
            const colorWithHash = `#${hexString}`;
            return isValidHexColor(colorWithHash) === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject invalid hex color formats', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.string({ minLength: 1, maxLength: 5 }), // Too short
            fc.string({ minLength: 8, maxLength: 20 }), // Too long
            fc.constant('invalid'),
            fc.constant('#GGG000'), // Invalid hex chars
            fc.constant('00F5D4'), // Missing hash
          ),
          (invalidColor) => {
            return isValidHexColor(invalidColor) === false;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Theme structure validation', () => {
    it('should have all required color categories', () => {
      expect(nexusTheme.colors).toHaveProperty('cosmic');
      expect(nexusTheme.colors).toHaveProperty('glow');
      expect(nexusTheme.colors).toHaveProperty('semantic');
      expect(nexusTheme.colors).toHaveProperty('text');
    });

    it('should have all cosmic colors defined', () => {
      expect(nexusTheme.colors.cosmic).toHaveProperty('black');
      expect(nexusTheme.colors.cosmic).toHaveProperty('deep');
      expect(nexusTheme.colors.cosmic).toHaveProperty('nebula');
      expect(nexusTheme.colors.cosmic).toHaveProperty('void');
    });

    it('should have all glow colors defined', () => {
      expect(nexusTheme.colors.glow).toHaveProperty('cyan');
      expect(nexusTheme.colors.glow).toHaveProperty('purple');
      expect(nexusTheme.colors.glow).toHaveProperty('pink');
      expect(nexusTheme.colors.glow).toHaveProperty('blue');
    });

    it('should have all semantic colors defined', () => {
      expect(nexusTheme.colors.semantic).toHaveProperty('success');
      expect(nexusTheme.colors.semantic).toHaveProperty('warning');
      expect(nexusTheme.colors.semantic).toHaveProperty('error');
    });
  });
});


/**
 * Property-Based Tests for NEXUS Theme Typography Configuration
 * 
 * Feature: nexus-auth-redesign, Property 2: Typography Configuration Correctness
 * Validates: Requirements 1.3
 * 
 * For any rendered heading element, the computed font-family SHALL include "Space Grotesk",
 * and for any rendered body text element, the computed font-family SHALL include "Inter".
 */
describe('NEXUS Theme Typography Configuration', () => {
  /**
   * Property 2: Typography Configuration Correctness
   * Validates: Requirements 1.3
   * 
   * For any typography configuration in the NEXUS theme, the font family values
   * should be valid and match the required fonts (Space Grotesk for headings, Inter for body).
   */
  describe('Property 2: All typography fonts are correctly configured', () => {
    const allTypography = getAllTypographyValues();

    it('should have all typography font families as valid non-empty strings', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...allTypography),
          (typographyEntry) => {
            const { type, fontName } = typographyEntry;
            const isValid = isValidFontFamily(fontName);
            if (!isValid) {
              throw new Error(`Typography "${type}" with font "${fontName}" is not a valid font family`);
            }
            return isValid;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have heading font family containing "Space Grotesk"', () => {
      fc.assert(
        fc.property(
          fc.constant(nexusTheme.typography.fontFamily.heading),
          (headingFont) => {
            const containsSpaceGrotesk = fontFamilyContains(headingFont, 'Space Grotesk');
            if (!containsSpaceGrotesk) {
              throw new Error(`Heading font "${headingFont}" does not contain "Space Grotesk"`);
            }
            return containsSpaceGrotesk;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have body font family containing "Inter"', () => {
      fc.assert(
        fc.property(
          fc.constant(nexusTheme.typography.fontFamily.body),
          (bodyFont) => {
            const containsInter = fontFamilyContains(bodyFont, 'Inter');
            if (!containsInter) {
              throw new Error(`Body font "${bodyFont}" does not contain "Inter"`);
            }
            return containsInter;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should contain the required heading font (Space Grotesk)', () => {
      expect(nexusTheme.typography.fontFamily.heading).toBe('Space Grotesk');
      expect(nexusTheme.requiredTypography.headingFont).toBe('Space Grotesk');
    });

    it('should contain the required body font (Inter)', () => {
      expect(nexusTheme.typography.fontFamily.body).toBe('Inter');
      expect(nexusTheme.requiredTypography.bodyFont).toBe('Inter');
    });

    it('should have mono font family containing "JetBrains Mono"', () => {
      expect(nexusTheme.typography.fontFamily.mono).toBe('JetBrains Mono');
    });
  });

  describe('Property 2: Typography CSS variable configuration', () => {
    it('should have correct CSS variable names for all font families', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('heading', 'body', 'mono') as fc.Arbitrary<'heading' | 'body' | 'mono'>,
          (fontType) => {
            const cssVar = nexusTheme.typography.cssVariables[fontType];
            const isValidCssVar = cssVar.startsWith('--font-') && cssVar.length > 7;
            if (!isValidCssVar) {
              throw new Error(`CSS variable "${cssVar}" for "${fontType}" is not valid`);
            }
            return isValidCssVar;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have correct Tailwind class names for all font families', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('heading', 'body', 'mono') as fc.Arbitrary<'heading' | 'body' | 'mono'>,
          (fontType) => {
            const tailwindClass = nexusTheme.typography.tailwindClasses[fontType];
            const isValidClass = tailwindClass.startsWith('font-') && tailwindClass.length > 5;
            if (!isValidClass) {
              throw new Error(`Tailwind class "${tailwindClass}" for "${fontType}" is not valid`);
            }
            return isValidClass;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Typography structure validation', () => {
    it('should have all required typography categories', () => {
      expect(nexusTheme.typography).toHaveProperty('fontFamily');
      expect(nexusTheme.typography).toHaveProperty('cssVariables');
      expect(nexusTheme.typography).toHaveProperty('tailwindClasses');
    });

    it('should have all font family types defined', () => {
      expect(nexusTheme.typography.fontFamily).toHaveProperty('heading');
      expect(nexusTheme.typography.fontFamily).toHaveProperty('body');
      expect(nexusTheme.typography.fontFamily).toHaveProperty('mono');
    });

    it('should have all CSS variables defined', () => {
      expect(nexusTheme.typography.cssVariables).toHaveProperty('heading');
      expect(nexusTheme.typography.cssVariables).toHaveProperty('body');
      expect(nexusTheme.typography.cssVariables).toHaveProperty('mono');
    });

    it('should have all Tailwind classes defined', () => {
      expect(nexusTheme.typography.tailwindClasses).toHaveProperty('heading');
      expect(nexusTheme.typography.tailwindClasses).toHaveProperty('body');
      expect(nexusTheme.typography.tailwindClasses).toHaveProperty('mono');
    });
  });
});
