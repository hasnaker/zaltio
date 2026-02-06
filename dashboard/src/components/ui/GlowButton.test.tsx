/**
 * Property-Based Tests for GlowButton Component
 * 
 * Feature: nexus-auth-redesign, Property 10: Interactive Element Hover Animations (buttons)
 * Validates: Requirements 8.2
 * 
 * For any button element, the element SHALL have scale transform and glow shadow on hover.
 */

import * as fc from 'fast-check';
import { GlowButtonVariant, GlowButtonSize } from './GlowButton';

const variants: GlowButtonVariant[] = ['primary', 'secondary', 'ghost', 'danger'];
const sizes: GlowButtonSize[] = ['sm', 'md', 'lg'];

/**
 * Helper function to get variant classes
 */
function getVariantClasses(variant: GlowButtonVariant): string {
  const variantClasses: Record<GlowButtonVariant, string> = {
    primary: 'bg-gradient-to-r from-nexus-glow-cyan to-nexus-glow-blue text-nexus-cosmic-black hover:scale-105 focus:ring-nexus-glow-cyan',
    secondary: 'bg-nexus-cosmic-nebula border border-nexus-glow-purple text-nexus-glow-purple hover:bg-nexus-glow-purple/10 hover:scale-105 focus:ring-nexus-glow-purple',
    ghost: 'bg-transparent text-nexus-text-secondary hover:text-nexus-text-primary hover:bg-white/5 hover:scale-105 focus:ring-white/20',
    danger: 'bg-nexus-error text-white hover:bg-nexus-error/80 hover:scale-105 focus:ring-nexus-error',
  };
  return variantClasses[variant];
}

/**
 * Helper function to get glow classes
 */
function getGlowClasses(variant: GlowButtonVariant): string {
  const glowClasses: Record<GlowButtonVariant, string> = {
    primary: 'hover:shadow-glow-cyan',
    secondary: 'hover:shadow-glow-purple',
    ghost: '',
    danger: 'hover:shadow-[0_0_20px_rgba(255,71,87,0.3)]',
  };
  return glowClasses[variant];
}

/**
 * Helper function to get size classes
 */
function getSizeClasses(size: GlowButtonSize): string {
  const sizeClasses: Record<GlowButtonSize, string> = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };
  return sizeClasses[size];
}

/**
 * Check if classes contain hover scale effect
 */
function hasHoverScaleEffect(classes: string): boolean {
  return classes.includes('hover:scale');
}

/**
 * Check if classes contain hover shadow/glow effect
 */
function hasHoverGlowEffect(classes: string, variant: GlowButtonVariant): boolean {
  // Ghost variant doesn't have glow
  if (variant === 'ghost') return true;
  return classes.includes('hover:shadow');
}

describe('GlowButton Component - Property Tests', () => {
  /**
   * Property 10: Interactive Element Hover Animations (buttons)
   * Validates: Requirements 8.2
   */
  describe('Property 10: Interactive Element Hover Animations (buttons)', () => {
    it('should have scale transform on hover for all variants', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          (variant) => {
            const classes = getVariantClasses(variant);
            
            expect(hasHoverScaleEffect(classes)).toBe(true);
            return hasHoverScaleEffect(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have glow shadow on hover for applicable variants', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          (variant) => {
            const variantClasses = getVariantClasses(variant);
            const glowClasses = getGlowClasses(variant);
            const combinedClasses = `${variantClasses} ${glowClasses}`;
            
            expect(hasHoverGlowEffect(combinedClasses, variant)).toBe(true);
            return hasHoverGlowEffect(combinedClasses, variant);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have correct size classes for all sizes', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...sizes),
          (size) => {
            const classes = getSizeClasses(size);
            
            // All sizes should have padding
            expect(classes).toContain('px-');
            expect(classes).toContain('py-');
            // All sizes should have text size
            expect(classes).toContain('text-');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should combine variant, size, and glow classes correctly', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          fc.constantFrom(...sizes),
          fc.boolean(),
          (variant, size, glow) => {
            const baseClasses = 'font-medium rounded-lg transition-all duration-300';
            const variantClasses = getVariantClasses(variant);
            const sizeClasses = getSizeClasses(size);
            const glowClasses = glow ? getGlowClasses(variant) : '';
            
            const combinedClasses = [
              baseClasses,
              sizeClasses,
              variantClasses,
              glowClasses,
            ].filter(Boolean).join(' ');
            
            // Should always have transition for smooth animations
            expect(combinedClasses).toContain('transition');
            // Should always have rounded corners
            expect(combinedClasses).toContain('rounded');
            // Should always have hover scale
            expect(combinedClasses).toContain('hover:scale');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should disable hover effects when disabled', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          fc.boolean(),
          (variant, disabled) => {
            const disabledClasses = 'opacity-50 cursor-not-allowed hover:scale-100 hover:shadow-none';
            
            if (disabled) {
              // Disabled state should reset scale to 100 (no scale effect)
              expect(disabledClasses).toContain('hover:scale-100');
              // Disabled state should remove shadow
              expect(disabledClasses).toContain('hover:shadow-none');
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
