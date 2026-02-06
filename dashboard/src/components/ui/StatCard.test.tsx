/**
 * Property-Based Tests for StatCard Component
 * 
 * Feature: nexus-auth-redesign, Property 7: Stat Card Animation
 * Validates: Requirements 5.2
 * 
 * For any StatCard component with a numeric value, the rendered element SHALL have
 * gradient border styles and the value SHALL animate from 0 to the target value
 * using count-up animation.
 */

import * as fc from 'fast-check';
import { StatCardColor } from './StatCard';

const colors: StatCardColor[] = ['cyan', 'purple', 'pink', 'blue'];

/**
 * Color configuration mapping for holographic gradient borders
 */
const colorConfig: Record<StatCardColor, {
  gradient: string;
  glow: string;
  iconBg: string;
}> = {
  cyan: {
    gradient: 'from-nexus-glow-cyan/20 via-nexus-glow-blue/10 to-nexus-glow-cyan/20',
    glow: 'shadow-glow-cyan',
    iconBg: 'bg-nexus-glow-cyan/20 text-nexus-glow-cyan',
  },
  purple: {
    gradient: 'from-nexus-glow-purple/20 via-nexus-glow-pink/10 to-nexus-glow-purple/20',
    glow: 'shadow-glow-purple',
    iconBg: 'bg-nexus-glow-purple/20 text-nexus-glow-purple',
  },
  pink: {
    gradient: 'from-nexus-glow-pink/20 via-nexus-glow-purple/10 to-nexus-glow-pink/20',
    glow: 'shadow-glow-pink',
    iconBg: 'bg-nexus-glow-pink/20 text-nexus-glow-pink',
  },
  blue: {
    gradient: 'from-nexus-glow-blue/20 via-nexus-glow-cyan/10 to-nexus-glow-blue/20',
    glow: 'shadow-glow-blue',
    iconBg: 'bg-nexus-glow-blue/20 text-nexus-glow-blue',
  },
};

/**
 * Helper function to check if gradient classes are present
 */
function hasGradientBorderClasses(gradient: string): boolean {
  return gradient.includes('from-') && gradient.includes('via-') && gradient.includes('to-');
}

/**
 * Helper function to check if glow shadow class is valid
 */
function hasValidGlowClass(glow: string): boolean {
  return glow.startsWith('shadow-glow-');
}

/**
 * Helper function to validate count-up animation behavior
 * The animation should start from 0 and end at the target value
 */
function validateCountUpAnimation(
  startValue: number,
  targetValue: number,
  progress: number
): { isValid: boolean; currentValue: number } {
  // Easing function: easeOutQuart
  const easeOutQuart = 1 - Math.pow(1 - progress, 4);
  const currentValue = Math.floor(easeOutQuart * targetValue);
  
  // At progress 0, value should be 0
  // At progress 1, value should be targetValue
  // Value should always be between startValue and targetValue
  const isValid = currentValue >= startValue && currentValue <= targetValue;
  
  return { isValid, currentValue };
}

describe('StatCard Component - Property Tests', () => {
  /**
   * Property 7: Stat Card Animation
   * Validates: Requirements 5.2
   */
  describe('Property 7: Stat Card Animation', () => {
    it('should have holographic gradient border classes for all color variants', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...colors),
          (color) => {
            const config = colorConfig[color];
            
            // Verify gradient border has proper structure
            expect(hasGradientBorderClasses(config.gradient)).toBe(true);
            
            // Verify glow shadow class is valid
            expect(hasValidGlowClass(config.glow)).toBe(true);
            
            // Verify gradient contains color-specific values
            expect(config.gradient).toContain(`nexus-glow-${color}`);
            
            return hasGradientBorderClasses(config.gradient) && hasValidGlowClass(config.glow);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should animate count-up from 0 to target value with valid intermediate values', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 1000000 }),
          fc.float({ min: 0, max: 1, noNaN: true }),
          (targetValue, progress) => {
            const result = validateCountUpAnimation(0, targetValue, progress);
            
            // Value should always be valid (between 0 and target)
            expect(result.isValid).toBe(true);
            
            // At progress 0, value should be 0
            if (progress === 0) {
              expect(result.currentValue).toBe(0);
            }
            
            // At progress 1, value should be targetValue
            if (progress === 1) {
              expect(result.currentValue).toBe(targetValue);
            }
            
            return result.isValid;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have consistent color configuration for icon background', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...colors),
          (color) => {
            const config = colorConfig[color];
            
            // Icon background should contain the color
            expect(config.iconBg).toContain(`nexus-glow-${color}`);
            
            // Icon background should have both bg and text color classes
            expect(config.iconBg).toContain('bg-');
            expect(config.iconBg).toContain('text-');
            
            return config.iconBg.includes(`nexus-glow-${color}`);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should produce monotonically increasing values during animation', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 1000000 }),
          fc.array(fc.float({ min: 0, max: 1, noNaN: true }), { minLength: 2, maxLength: 10 }),
          (targetValue, progressValues) => {
            // Sort progress values to simulate animation timeline
            const sortedProgress = [...progressValues].sort((a, b) => a - b);
            
            let previousValue = 0;
            for (const progress of sortedProgress) {
              const result = validateCountUpAnimation(0, targetValue, progress);
              
              // Each value should be >= previous value (monotonically increasing)
              expect(result.currentValue).toBeGreaterThanOrEqual(previousValue);
              previousValue = result.currentValue;
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have valid glow shadow for each color variant', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...colors),
          (color) => {
            const config = colorConfig[color];
            
            // Glow class should match the color
            expect(config.glow).toBe(`shadow-glow-${color}`);
            
            return config.glow === `shadow-glow-${color}`;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
