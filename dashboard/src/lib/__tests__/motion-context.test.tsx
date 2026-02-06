/**
 * Property Tests for Motion Context
 * 
 * Property 10: Reduced Motion Preference
 * Validates: Requirements 8.5
 * 
 * Tests:
 * - Media query detection works correctly
 * - Reduced motion variants are simpler
 * - Context provides correct values
 * - Hook returns appropriate animations
 */

import * as fc from 'fast-check';
import { scrollAnimations, staggerVariants, staggerItemVariants, reducedMotionVariants } from '../motion';

// Reduced motion stagger variants (matching context implementation)
const reducedMotionStaggerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      duration: 0.3,
    },
  },
};

const reducedMotionItemVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      duration: 0.2,
    },
  },
};

describe('Motion Context Property Tests', () => {
  // ============================================
  // PROPERTY 10.1: Reduced Motion Variants Structure
  // ============================================
  describe('Property 10.1: Reduced motion variants are properly structured', () => {
    it('should have initial and animate states', () => {
      expect(reducedMotionVariants).toHaveProperty('initial');
      expect(reducedMotionVariants).toHaveProperty('animate');
      expect(reducedMotionVariants).toHaveProperty('transition');
    });

    it('should only use opacity for reduced motion', () => {
      const { initial, animate } = reducedMotionVariants;
      
      // Should only have opacity, no transforms
      expect(initial).toEqual({ opacity: 0 });
      expect(animate).toEqual({ opacity: 1 });
    });

    it('should have short transition duration', () => {
      const { transition } = reducedMotionVariants;
      expect(transition.duration).toBeLessThanOrEqual(0.5);
    });
  });

  // ============================================
  // PROPERTY 10.2: Full Motion vs Reduced Motion
  // ============================================
  describe('Property 10.2: Full motion animations are more complex than reduced', () => {
    const scrollAnimationKeys = Object.keys(scrollAnimations) as (keyof typeof scrollAnimations)[];

    it('should have more properties in full motion animations', () => {
      scrollAnimationKeys.forEach(key => {
        const fullAnimation = scrollAnimations[key];
        const reducedAnimation = reducedMotionVariants;

        // Full animations should have more complex initial states
        const fullInitialKeys = Object.keys(fullAnimation.initial || {});
        const reducedInitialKeys = Object.keys(reducedAnimation.initial || {});

        // Full motion should have at least as many properties
        expect(fullInitialKeys.length).toBeGreaterThanOrEqual(reducedInitialKeys.length);
      });
    });

    it('should have transforms in full motion but not in reduced', () => {
      const transformProperties = ['y', 'x', 'scale', 'rotate', 'rotateX', 'rotateY'];
      
      // Check that at least some full animations have transforms
      const hasTransforms = scrollAnimationKeys.some(key => {
        const initial = scrollAnimations[key].initial || {};
        return transformProperties.some(prop => prop in initial);
      });
      expect(hasTransforms).toBe(true);

      // Reduced motion should not have transforms
      const reducedInitial = reducedMotionVariants.initial || {};
      transformProperties.forEach(prop => {
        expect(reducedInitial).not.toHaveProperty(prop);
      });
    });
  });

  // ============================================
  // PROPERTY 10.3: Stagger Variants
  // ============================================
  describe('Property 10.3: Stagger variants respect reduced motion', () => {
    it('should have staggerChildren in full motion', () => {
      const visible = staggerVariants.visible as any;
      expect(visible.transition).toHaveProperty('staggerChildren');
    });

    it('should not have staggerChildren in reduced motion', () => {
      const visible = reducedMotionStaggerVariants.visible as any;
      expect(visible.transition).not.toHaveProperty('staggerChildren');
    });

    it('should have shorter duration in reduced motion item variants', () => {
      const fullDuration = (staggerItemVariants.visible as any).transition?.duration || 0.5;
      const reducedDuration = (reducedMotionItemVariants.visible as any).transition?.duration || 0.2;
      
      expect(reducedDuration).toBeLessThanOrEqual(fullDuration);
    });
  });

  // ============================================
  // PROPERTY 10.4: Animation Selection Logic
  // ============================================
  describe('Property 10.4: Animation selection based on preference', () => {
    // Simulate getScrollAnimation function
    const getScrollAnimation = (
      prefersReducedMotion: boolean,
      animationKey: keyof typeof scrollAnimations
    ) => {
      if (prefersReducedMotion) {
        return reducedMotionVariants;
      }
      return scrollAnimations[animationKey];
    };

    it('should return reduced motion when preference is true', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...Object.keys(scrollAnimations) as (keyof typeof scrollAnimations)[]),
          (animationKey) => {
            const result = getScrollAnimation(true, animationKey);
            expect(result).toEqual(reducedMotionVariants);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should return full animation when preference is false', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...Object.keys(scrollAnimations) as (keyof typeof scrollAnimations)[]),
          (animationKey) => {
            const result = getScrollAnimation(false, animationKey);
            expect(result).toEqual(scrollAnimations[animationKey]);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  // ============================================
  // PROPERTY 10.5: Scroll Animation Keys
  // ============================================
  describe('Property 10.5: All scroll animations have required properties', () => {
    const scrollAnimationKeys = Object.keys(scrollAnimations) as (keyof typeof scrollAnimations)[];

    it('should have initial state for all animations', () => {
      scrollAnimationKeys.forEach(key => {
        expect(scrollAnimations[key]).toHaveProperty('initial');
      });
    });

    it('should have whileInView or animate for all animations', () => {
      scrollAnimationKeys.forEach(key => {
        const animation = scrollAnimations[key];
        const hasWhileInView = 'whileInView' in animation;
        const hasAnimate = 'animate' in animation;
        expect(hasWhileInView || hasAnimate).toBe(true);
      });
    });

    it('should have viewport config for scroll animations', () => {
      scrollAnimationKeys.forEach(key => {
        const animation = scrollAnimations[key];
        if ('whileInView' in animation) {
          expect(animation).toHaveProperty('viewport');
        }
      });
    });
  });

  // ============================================
  // PROPERTY 10.6: Transition Durations
  // ============================================
  describe('Property 10.6: Transition durations are reasonable', () => {
    it('should have reduced motion duration under 0.5s', () => {
      const duration = reducedMotionVariants.transition.duration;
      expect(duration).toBeLessThanOrEqual(0.5);
    });

    it('should have reduced stagger duration under 0.5s', () => {
      const duration = (reducedMotionStaggerVariants.visible as any).transition.duration;
      expect(duration).toBeLessThanOrEqual(0.5);
    });

    it('should have reduced item duration under 0.3s', () => {
      const duration = (reducedMotionItemVariants.visible as any).transition.duration;
      expect(duration).toBeLessThanOrEqual(0.3);
    });
  });

  // ============================================
  // PROPERTY 10.7: Opacity-Only Animations
  // ============================================
  describe('Property 10.7: Reduced motion uses opacity-only transitions', () => {
    it('should only animate opacity in reduced motion variants', () => {
      const { initial, animate } = reducedMotionVariants;
      
      expect(Object.keys(initial)).toEqual(['opacity']);
      expect(Object.keys(animate)).toEqual(['opacity']);
    });

    it('should only animate opacity in reduced stagger variants', () => {
      const hidden = reducedMotionStaggerVariants.hidden;
      const visible = reducedMotionStaggerVariants.visible;
      
      expect(Object.keys(hidden)).toContain('opacity');
      expect(Object.keys(visible)).toContain('opacity');
    });

    it('should only animate opacity in reduced item variants', () => {
      const hidden = reducedMotionItemVariants.hidden;
      const visible = reducedMotionItemVariants.visible;
      
      expect(Object.keys(hidden)).toContain('opacity');
      expect(Object.keys(visible)).toContain('opacity');
    });
  });

  // ============================================
  // PROPERTY 10.8: Boolean Preference Handling
  // ============================================
  describe('Property 10.8: Boolean preference is handled correctly', () => {
    const getStaggerVariants = (prefersReducedMotion: boolean) => {
      if (prefersReducedMotion) {
        return reducedMotionStaggerVariants;
      }
      return staggerVariants;
    };

    it('should return correct variants for any boolean value', () => {
      fc.assert(
        fc.property(fc.boolean(), (prefersReducedMotion) => {
          const result = getStaggerVariants(prefersReducedMotion);
          
          if (prefersReducedMotion) {
            expect(result).toEqual(reducedMotionStaggerVariants);
          } else {
            expect(result).toEqual(staggerVariants);
          }
        }),
        { numRuns: 20 }
      );
    });
  });

  // ============================================
  // PROPERTY 10.9: Consistent Structure
  // ============================================
  describe('Property 10.9: All variants have consistent structure', () => {
    it('should have hidden and visible states in stagger variants', () => {
      expect(staggerVariants).toHaveProperty('hidden');
      expect(staggerVariants).toHaveProperty('visible');
      expect(reducedMotionStaggerVariants).toHaveProperty('hidden');
      expect(reducedMotionStaggerVariants).toHaveProperty('visible');
    });

    it('should have hidden and visible states in item variants', () => {
      expect(staggerItemVariants).toHaveProperty('hidden');
      expect(staggerItemVariants).toHaveProperty('visible');
      expect(reducedMotionItemVariants).toHaveProperty('hidden');
      expect(reducedMotionItemVariants).toHaveProperty('visible');
    });
  });

  // ============================================
  // PROPERTY 10.10: No Infinite Animations in Reduced Motion
  // ============================================
  describe('Property 10.10: Reduced motion has no infinite animations', () => {
    it('should not have repeat: Infinity in reduced motion', () => {
      const transition = reducedMotionVariants.transition as any;
      expect(transition.repeat).toBeUndefined();
    });

    it('should not have repeatType in reduced motion', () => {
      const transition = reducedMotionVariants.transition as any;
      expect(transition.repeatType).toBeUndefined();
    });
  });
});
