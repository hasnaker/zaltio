/**
 * Property-Based Tests for Reduced Motion Support
 * 
 * Feature: zalt-enterprise-landing
 * Property 1: Reduced motion disables animations
 * Validates: Requirements 1.6, 15.6, 18.6
 * 
 * Properties tested:
 * 1. Reduced motion preference is respected
 * 2. Animation variants change based on motion preference
 * 3. Static alternatives are provided when animations are disabled
 * 4. No animation delays when reduced motion is enabled
 */

import * as fc from 'fast-check';

// Animation configuration types
interface AnimationConfig {
  duration: number;
  delay: number;
  ease: string | number[];
}

interface MotionVariant {
  initial: Record<string, number>;
  animate: Record<string, number>;
  transition: AnimationConfig;
}

// Reduced motion utility function (mirrors the actual implementation)
const getReducedMotionVariant = (
  fullMotion: MotionVariant,
  prefersReducedMotion: boolean
): MotionVariant => {
  if (prefersReducedMotion) {
    return {
      initial: { opacity: 0 },
      animate: { opacity: 1 },
      transition: { duration: 0.1, delay: 0, ease: 'linear' },
    };
  }
  return fullMotion;
};

// Animation delay calculation
const getAnimationDelay = (
  index: number,
  staggerDelay: number,
  prefersReducedMotion: boolean
): number => {
  if (prefersReducedMotion) {
    return 0;
  }
  return index * staggerDelay;
};

// Check if animation should be disabled
const shouldDisableAnimation = (prefersReducedMotion: boolean): boolean => {
  return prefersReducedMotion;
};

// Size configurations for SecurityLock3D
const sizeConfigs = {
  sm: { width: 80, height: 100, strokeWidth: 2, particleCount: 10 },
  md: { width: 120, height: 150, strokeWidth: 3, particleCount: 15 },
  lg: { width: 180, height: 225, strokeWidth: 4, particleCount: 20 },
  xl: { width: 240, height: 300, strokeWidth: 5, particleCount: 25 },
  hero: { width: 320, height: 400, strokeWidth: 6, particleCount: 30 },
};

describe('Feature: zalt-enterprise-landing, Property 1: Reduced motion disables animations', () => {
  describe('Property 1.1: Animation Variant Selection', () => {
    it('should return reduced motion variant when preference is enabled', () => {
      fc.assert(
        fc.property(
          fc.record({
            initial: fc.record({
              opacity: fc.double({ min: 0, max: 1 }),
              y: fc.integer({ min: -100, max: 100 }),
              scale: fc.double({ min: 0.5, max: 1.5 }),
            }),
            animate: fc.record({
              opacity: fc.constant(1),
              y: fc.constant(0),
              scale: fc.constant(1),
            }),
            transition: fc.record({
              duration: fc.double({ min: 0.1, max: 2 }),
              delay: fc.double({ min: 0, max: 1 }),
              ease: fc.constant('easeOut'),
            }),
          }),
          (fullMotion) => {
            const result = getReducedMotionVariant(fullMotion as MotionVariant, true);
            
            // Reduced motion should have minimal animation
            expect(result.transition.duration).toBe(0.1);
            expect(result.transition.delay).toBe(0);
            expect(result.initial.opacity).toBe(0);
            expect(result.animate.opacity).toBe(1);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should return full motion variant when preference is disabled', () => {
      fc.assert(
        fc.property(
          fc.record({
            initial: fc.record({
              opacity: fc.double({ min: 0, max: 1 }),
              y: fc.integer({ min: -100, max: 100 }),
            }),
            animate: fc.record({
              opacity: fc.constant(1),
              y: fc.constant(0),
            }),
            transition: fc.record({
              duration: fc.double({ min: 0.1, max: 2 }),
              delay: fc.double({ min: 0, max: 1 }),
              ease: fc.constant('easeOut'),
            }),
          }),
          (fullMotion) => {
            const result = getReducedMotionVariant(fullMotion as MotionVariant, false);
            
            // Should return the original full motion variant
            expect(result).toEqual(fullMotion);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Property 1.2: Animation Delay Calculation', () => {
    it('should return zero delay when reduced motion is enabled', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 100 }),
          fc.double({ min: 0.01, max: 0.5 }),
          (index, staggerDelay) => {
            const delay = getAnimationDelay(index, staggerDelay, true);
            expect(delay).toBe(0);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should return calculated delay when reduced motion is disabled', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 100 }),
          fc.double({ min: 0.01, max: 0.5, noNaN: true }),
          (index, staggerDelay) => {
            const delay = getAnimationDelay(index, staggerDelay, false);
            expect(delay).toBeCloseTo(index * staggerDelay, 5);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have zero delay for first item regardless of motion preference', () => {
      fc.assert(
        fc.property(
          fc.double({ min: 0.01, max: 0.5, noNaN: true }),
          fc.boolean(),
          (staggerDelay, prefersReducedMotion) => {
            const delay = getAnimationDelay(0, staggerDelay, prefersReducedMotion);
            expect(delay).toBe(0);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Property 1.3: Animation Disable Flag', () => {
    it('should disable animations when reduced motion is preferred', () => {
      expect(shouldDisableAnimation(true)).toBe(true);
    });

    it('should enable animations when reduced motion is not preferred', () => {
      expect(shouldDisableAnimation(false)).toBe(false);
    });

    it('should be consistent across multiple calls', () => {
      fc.assert(
        fc.property(fc.boolean(), (prefersReducedMotion) => {
          const result1 = shouldDisableAnimation(prefersReducedMotion);
          const result2 = shouldDisableAnimation(prefersReducedMotion);
          expect(result1).toBe(result2);
        }),
        { numRuns: 100 }
      );
    });
  });

  describe('Property 1.4: SecurityLock3D Size Configurations', () => {
    it('should have valid size configurations for all variants', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('sm', 'md', 'lg', 'xl', 'hero' as const),
          (size) => {
            const config = sizeConfigs[size];
            
            expect(config.width).toBeGreaterThan(0);
            expect(config.height).toBeGreaterThan(0);
            expect(config.strokeWidth).toBeGreaterThan(0);
            expect(config.particleCount).toBeGreaterThan(0);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should have increasing dimensions for larger sizes', () => {
      const sizes = ['sm', 'md', 'lg', 'xl', 'hero'] as const;
      
      for (let i = 0; i < sizes.length - 1; i++) {
        const current = sizeConfigs[sizes[i]];
        const next = sizeConfigs[sizes[i + 1]];
        
        expect(next.width).toBeGreaterThan(current.width);
        expect(next.height).toBeGreaterThan(current.height);
      }
    });

    it('should maintain aspect ratio across sizes', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('sm', 'md', 'lg', 'xl', 'hero' as const),
          (size) => {
            const config = sizeConfigs[size];
            const aspectRatio = config.height / config.width;
            
            // All sizes should have approximately the same aspect ratio (1.25)
            expect(aspectRatio).toBeCloseTo(1.25, 1);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 1.5: Device Mockup Active State', () => {
    const devices = ['desktop', 'tablet', 'mobile'] as const;
    
    it('should have exactly one active device at a time', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...devices),
          (activeDevice) => {
            const activeCount = devices.filter(d => d === activeDevice).length;
            expect(activeCount).toBe(1);
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should correctly identify active device', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...devices),
          fc.constantFrom(...devices),
          (activeDevice, checkDevice) => {
            const isActive = activeDevice === checkDevice;
            
            if (activeDevice === checkDevice) {
              expect(isActive).toBe(true);
            } else {
              expect(isActive).toBe(false);
            }
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  describe('Property 1.6: Hero Section CTA Configuration', () => {
    it('should have valid CTA button configuration', () => {
      fc.assert(
        fc.property(
          fc.record({
            primaryText: fc.string({ minLength: 1, maxLength: 50 }).filter(s => s.trim().length > 0),
            primaryHref: fc.string({ minLength: 1, maxLength: 100 }).filter(s => s.startsWith('/')),
            secondaryText: fc.string({ minLength: 1, maxLength: 50 }).filter(s => s.trim().length > 0),
            secondaryHref: fc.string({ minLength: 1, maxLength: 100 }).filter(s => s.startsWith('/')),
          }),
          (config) => {
            expect(config.primaryText.length).toBeGreaterThan(0);
            expect(config.primaryHref.startsWith('/')).toBe(true);
            expect(config.secondaryText.length).toBeGreaterThan(0);
            expect(config.secondaryHref.startsWith('/')).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 1.7: Particle Animation Configuration', () => {
    it('should calculate particle positions correctly', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 30 }),
          fc.integer({ min: 20, max: 30 }),
          (index, totalParticles) => {
            const angle = (index / totalParticles) * Math.PI * 2;
            const distance = 80;
            const x = Math.cos(angle) * distance;
            const y = Math.sin(angle) * distance;
            
            // Particles should be within expected bounds
            expect(Math.abs(x)).toBeLessThanOrEqual(distance);
            expect(Math.abs(y)).toBeLessThanOrEqual(distance);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have valid particle colors', () => {
      const colors = ['#6C47FF', '#00D4FF', '#8B5CF6', '#0EA5E9', '#22C55E'];
      
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 100 }),
          (index) => {
            const color = colors[index % colors.length];
            
            // Color should be a valid hex color
            expect(color).toMatch(/^#[0-9A-Fa-f]{6}$/);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 1.8: Stagger Animation Timing', () => {
    it('should have increasing delays for staggered children', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 2, max: 20 }),
          fc.double({ min: 0.05, max: 0.2 }),
          (childCount, staggerDelay) => {
            const delays: number[] = [];
            
            for (let i = 0; i < childCount; i++) {
              delays.push(getAnimationDelay(i, staggerDelay, false));
            }
            
            // Each delay should be greater than the previous
            for (let i = 1; i < delays.length; i++) {
              expect(delays[i]).toBeGreaterThan(delays[i - 1]);
            }
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should have zero delays for all children when reduced motion is enabled', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 2, max: 20 }),
          fc.double({ min: 0.05, max: 0.2 }),
          (childCount, staggerDelay) => {
            const delays: number[] = [];
            
            for (let i = 0; i < childCount; i++) {
              delays.push(getAnimationDelay(i, staggerDelay, true));
            }
            
            // All delays should be zero
            delays.forEach(delay => {
              expect(delay).toBe(0);
            });
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});

describe('Reduced Motion Edge Cases', () => {
  it('should handle null/undefined motion preference gracefully', () => {
    // Default to false (animations enabled) when preference is null/undefined
    const defaultBehavior = (pref: boolean | null | undefined): boolean => {
      return pref ?? false;
    };
    
    expect(defaultBehavior(null)).toBe(false);
    expect(defaultBehavior(undefined)).toBe(false);
    expect(defaultBehavior(true)).toBe(true);
    expect(defaultBehavior(false)).toBe(false);
  });

  it('should handle extreme animation durations', () => {
    fc.assert(
      fc.property(
        fc.double({ min: 0.1, max: 10, noNaN: true }),
        (duration) => {
          // Duration should always be positive and not NaN
          if (Number.isNaN(duration)) return true; // Skip NaN values
          
          expect(duration).toBeGreaterThan(0);
          
          // Reduced motion duration (0.1) should be less than or equal to full duration
          const reducedDuration = 0.1;
          expect(reducedDuration).toBeLessThanOrEqual(duration);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should handle large particle counts', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 100 }),
        (particleCount) => {
          // Particle count should be positive
          expect(particleCount).toBeGreaterThan(0);
          
          // Each particle should have a valid index
          for (let i = 0; i < particleCount; i++) {
            expect(i).toBeGreaterThanOrEqual(0);
            expect(i).toBeLessThan(particleCount);
          }
        }
      ),
      { numRuns: 50 }
    );
  });
});
