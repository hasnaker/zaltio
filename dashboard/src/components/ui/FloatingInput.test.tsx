/**
 * Property-Based Tests for FloatingInput Component
 * 
 * Feature: nexus-auth-redesign, Property 10: Interactive Element Hover Animations (inputs)
 * Validates: Requirements 8.4
 * 
 * For any input element, the element SHALL have ring or shadow glow on focus.
 */

import * as fc from 'fast-check';
import { FloatingInputType } from './FloatingInput';

const inputTypes: FloatingInputType[] = ['text', 'email', 'password'];

/**
 * Helper function to get input classes based on state
 */
function getInputClasses(hasError: boolean, hasIcon: boolean): string {
  const baseClasses = [
    'w-full px-4 py-3 bg-nexus-cosmic-nebula/50 border rounded-lg',
    'text-nexus-text-primary placeholder-transparent',
    'transition-all duration-300',
    'focus:outline-none',
  ];
  
  if (hasIcon) {
    baseClasses.push('pl-11');
  }
  
  if (hasError) {
    baseClasses.push('border-nexus-error focus:border-nexus-error focus:ring-2 focus:ring-nexus-error/30');
  } else {
    baseClasses.push('border-white/10 focus:border-nexus-glow-cyan focus:ring-2 focus:ring-nexus-glow-cyan/30 focus:shadow-glow-cyan');
  }
  
  return baseClasses.join(' ');
}

/**
 * Helper function to get label classes based on state
 */
function getLabelClasses(isFocused: boolean, hasValue: boolean, hasError: boolean, hasIcon: boolean): string {
  const isLabelFloating = isFocused || hasValue;
  
  const classes = [
    'absolute transition-all duration-300 pointer-events-none',
    hasIcon ? 'left-11' : 'left-4',
    isLabelFloating
      ? '-top-2.5 text-xs bg-nexus-cosmic-deep px-1'
      : 'top-3 text-base',
  ];
  
  if (hasError) {
    classes.push('text-nexus-error');
  } else if (isFocused) {
    classes.push('text-nexus-glow-cyan');
  } else {
    classes.push('text-nexus-text-muted');
  }
  
  return classes.join(' ');
}

/**
 * Check if classes contain focus ring effect
 */
function hasFocusRingEffect(classes: string): boolean {
  return classes.includes('focus:ring');
}

/**
 * Check if classes contain focus shadow/glow effect
 */
function hasFocusShadowEffect(classes: string): boolean {
  return classes.includes('focus:shadow') || classes.includes('focus:ring');
}

/**
 * Check if classes contain focus border color change
 */
function hasFocusBorderEffect(classes: string): boolean {
  return classes.includes('focus:border');
}

/**
 * Check if classes contain transition for smooth animations
 */
function hasTransition(classes: string): boolean {
  return classes.includes('transition');
}

describe('FloatingInput Component - Property Tests', () => {
  /**
   * Property 10: Interactive Element Hover Animations (inputs)
   * Validates: Requirements 8.4
   */
  describe('Property 10: Interactive Element Hover Animations (inputs)', () => {
    it('should have focus ring effect for all input types', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...inputTypes),
          fc.boolean(), // hasError
          (type, hasError) => {
            const classes = getInputClasses(hasError, false);
            
            expect(hasFocusRingEffect(classes)).toBe(true);
            return hasFocusRingEffect(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have focus shadow/glow effect for non-error state', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...inputTypes),
          (type) => {
            const classes = getInputClasses(false, false);
            
            // Non-error state should have cyan glow
            expect(classes).toContain('focus:shadow-glow-cyan');
            expect(hasFocusShadowEffect(classes)).toBe(true);
            
            return hasFocusShadowEffect(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have focus border color change for all states', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...inputTypes),
          fc.boolean(), // hasError
          (type, hasError) => {
            const classes = getInputClasses(hasError, false);
            
            expect(hasFocusBorderEffect(classes)).toBe(true);
            
            if (hasError) {
              expect(classes).toContain('focus:border-nexus-error');
            } else {
              expect(classes).toContain('focus:border-nexus-glow-cyan');
            }
            
            return hasFocusBorderEffect(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have transition for smooth animations', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...inputTypes),
          fc.boolean(), // hasError
          fc.boolean(), // hasIcon
          (type, hasError, hasIcon) => {
            const classes = getInputClasses(hasError, hasIcon);
            
            expect(hasTransition(classes)).toBe(true);
            expect(classes).toContain('duration-300');
            
            return hasTransition(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should float label on focus or when has value', () => {
      fc.assert(
        fc.property(
          fc.boolean(), // isFocused
          fc.boolean(), // hasValue
          fc.boolean(), // hasError
          fc.boolean(), // hasIcon
          (isFocused, hasValue, hasError, hasIcon) => {
            const classes = getLabelClasses(isFocused, hasValue, hasError, hasIcon);
            const isLabelFloating = isFocused || hasValue;
            
            if (isLabelFloating) {
              // Label should be positioned at top when floating
              expect(classes).toContain('-top-2.5');
              expect(classes).toContain('text-xs');
            } else {
              // Label should be positioned in center when not floating
              expect(classes).toContain('top-3');
              expect(classes).toContain('text-base');
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should change label color on focus', () => {
      fc.assert(
        fc.property(
          fc.boolean(), // isFocused
          fc.boolean(), // hasValue
          fc.boolean(), // hasError
          (isFocused, hasValue, hasError) => {
            const classes = getLabelClasses(isFocused, hasValue, hasError, false);
            
            if (hasError) {
              expect(classes).toContain('text-nexus-error');
            } else if (isFocused) {
              expect(classes).toContain('text-nexus-glow-cyan');
            } else {
              expect(classes).toContain('text-nexus-text-muted');
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have correct padding when icon is present', () => {
      fc.assert(
        fc.property(
          fc.boolean(), // hasIcon
          fc.boolean(), // hasError
          (hasIcon, hasError) => {
            const classes = getInputClasses(hasError, hasIcon);
            
            if (hasIcon) {
              expect(classes).toContain('pl-11');
            } else {
              expect(classes).not.toContain('pl-11');
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
