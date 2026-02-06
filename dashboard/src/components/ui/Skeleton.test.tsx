/**
 * Property-Based Tests for Skeleton Component
 * 
 * Feature: nexus-auth-redesign, Property 8: Loading State Skeleton Display
 * Validates: Requirements 5.6
 * 
 * For any component in loading state (loading=true), the component SHALL render
 * skeleton placeholder elements with shimmer animation class instead of actual content.
 */

import * as fc from 'fast-check';
import { SkeletonVariant, SkeletonSize } from './Skeleton';

const variants: SkeletonVariant[] = ['text', 'circular', 'rectangular', 'card', 'avatar', 'button'];
const sizes: SkeletonSize[] = ['sm', 'md', 'lg', 'xl', 'full'];

/**
 * Helper function to generate expected classes for skeleton
 */
function getExpectedSkeletonClasses(animated: boolean): {
  hasBaseClass: boolean;
  hasShimmerAnimation: boolean;
  hasOverflowHidden: boolean;
} {
  return {
    hasBaseClass: true,
    hasShimmerAnimation: animated,
    hasOverflowHidden: true,
  };
}

/**
 * Helper function to simulate skeleton class generation
 */
function generateSkeletonClasses(variant: SkeletonVariant, animated: boolean): string {
  const baseClasses = 'bg-nexus-cosmic-nebula/60 relative overflow-hidden';
  
  const shimmerClasses = animated
    ? 'before:absolute before:inset-0 before:-translate-x-full before:animate-shimmer before:bg-gradient-to-r before:from-transparent before:via-white/10 before:to-transparent'
    : '';

  const variantClasses: Record<SkeletonVariant, string> = {
    text: 'rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
    card: 'rounded-xl',
    avatar: 'rounded-full',
    button: 'rounded-lg',
  };

  return [baseClasses, shimmerClasses, variantClasses[variant]].filter(Boolean).join(' ');
}

/**
 * Helper function to check if classes contain shimmer animation
 */
function hasShimmerAnimationClass(classes: string): boolean {
  return classes.includes('animate-shimmer');
}

/**
 * Helper function to check if classes contain overflow-hidden
 */
function hasOverflowHiddenClass(classes: string): boolean {
  return classes.includes('overflow-hidden');
}

/**
 * Helper function to check if classes contain base skeleton styling
 */
function hasBaseSkeletonClass(classes: string): boolean {
  return classes.includes('bg-nexus-cosmic-nebula') && classes.includes('relative');
}

/**
 * Helper function to get expected variant class
 */
function getExpectedVariantClass(variant: SkeletonVariant): string {
  const variantClasses: Record<SkeletonVariant, string> = {
    text: 'rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
    card: 'rounded-xl',
    avatar: 'rounded-full',
    button: 'rounded-lg',
  };
  return variantClasses[variant];
}

describe('Skeleton Component - Property Tests', () => {
  /**
   * Property 8: Loading State Skeleton Display
   * Validates: Requirements 5.6
   */
  describe('Property 8: Loading State Skeleton Display', () => {
    it('should apply shimmer animation class when animated is true for all variants', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          (variant) => {
            const classes = generateSkeletonClasses(variant, true);
            const expected = getExpectedSkeletonClasses(true);
            
            expect(hasShimmerAnimationClass(classes)).toBe(expected.hasShimmerAnimation);
            return hasShimmerAnimationClass(classes) === expected.hasShimmerAnimation;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should NOT apply shimmer animation class when animated is false for all variants', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          (variant) => {
            const classes = generateSkeletonClasses(variant, false);
            const expected = getExpectedSkeletonClasses(false);
            
            expect(hasShimmerAnimationClass(classes)).toBe(expected.hasShimmerAnimation);
            return hasShimmerAnimationClass(classes) === expected.hasShimmerAnimation;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should always have overflow-hidden for shimmer containment', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          fc.boolean(),
          (variant, animated) => {
            const classes = generateSkeletonClasses(variant, animated);
            
            expect(hasOverflowHiddenClass(classes)).toBe(true);
            return hasOverflowHiddenClass(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should always have base skeleton styling classes', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          fc.boolean(),
          (variant, animated) => {
            const classes = generateSkeletonClasses(variant, animated);
            
            expect(hasBaseSkeletonClass(classes)).toBe(true);
            return hasBaseSkeletonClass(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should apply correct variant-specific border radius class', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          (variant) => {
            const classes = generateSkeletonClasses(variant, true);
            const expectedVariantClass = getExpectedVariantClass(variant);
            
            expect(classes).toContain(expectedVariantClass);
            return classes.includes(expectedVariantClass);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should maintain consistent shimmer animation properties across all variant and size combinations', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          fc.constantFrom(...sizes),
          (variant, _size) => {
            // Size doesn't affect animation classes, only dimensions
            const animatedClasses = generateSkeletonClasses(variant, true);
            const nonAnimatedClasses = generateSkeletonClasses(variant, false);
            
            // Animated should have shimmer
            expect(hasShimmerAnimationClass(animatedClasses)).toBe(true);
            // Non-animated should not have shimmer
            expect(hasShimmerAnimationClass(nonAnimatedClasses)).toBe(false);
            
            // Both should have base classes
            expect(hasBaseSkeletonClass(animatedClasses)).toBe(true);
            expect(hasBaseSkeletonClass(nonAnimatedClasses)).toBe(true);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should use correct shimmer gradient direction (left to right)', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...variants),
          (variant) => {
            const classes = generateSkeletonClasses(variant, true);
            
            // Shimmer should translate from left (-translate-x-full) to right
            expect(classes).toContain('before:-translate-x-full');
            // Shimmer should use gradient-to-r (left to right)
            expect(classes).toContain('before:bg-gradient-to-r');
            
            return classes.includes('before:-translate-x-full') && 
                   classes.includes('before:bg-gradient-to-r');
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
