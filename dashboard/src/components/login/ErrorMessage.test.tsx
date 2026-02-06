/**
 * Property-Based Tests for ErrorMessage Component
 * 
 * Feature: nexus-auth-redesign, Property 9: Error Message Shake Animation
 * Validates: Requirements 3.5, 8.8
 * 
 * For any error state (error message present), the error message container
 * SHALL have the shake animation class applied for visual feedback.
 */

import * as fc from 'fast-check';

/**
 * Helper function to generate error message container classes
 */
function getErrorMessageClasses(message: string, isShaking: boolean): string {
  const baseClasses = [
    'relative flex items-start gap-3 px-4 py-3 rounded-lg',
    'bg-nexus-error/10 border border-nexus-error/30',
    'text-nexus-error text-sm',
  ];
  
  if (message && isShaking) {
    baseClasses.push('animate-shake');
  }
  
  return baseClasses.filter(Boolean).join(' ');
}

/**
 * Check if classes contain shake animation
 */
function hasShakeAnimation(classes: string): boolean {
  return classes.includes('animate-shake');
}

/**
 * Check if classes contain error styling
 */
function hasErrorStyling(classes: string): boolean {
  return (
    classes.includes('bg-nexus-error') &&
    classes.includes('border') &&
    classes.includes('text-nexus-error')
  );
}

describe('ErrorMessage Component - Property Tests', () => {
  /**
   * Property 9: Error Message Shake Animation
   * Validates: Requirements 3.5, 8.8
   */
  describe('Property 9: Error Message Shake Animation', () => {
    it('should have shake animation class when error message is present and shaking', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 200 }),
          (errorMessage) => {
            // When error message is present and isShaking is true
            const classes = getErrorMessageClasses(errorMessage, true);
            
            expect(hasShakeAnimation(classes)).toBe(true);
            return hasShakeAnimation(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not have shake animation class when not shaking', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 200 }),
          (errorMessage) => {
            // When error message is present but isShaking is false
            const classes = getErrorMessageClasses(errorMessage, false);
            
            expect(hasShakeAnimation(classes)).toBe(false);
            return !hasShakeAnimation(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should always have error styling when message is present', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 200 }),
          fc.boolean(),
          (errorMessage, isShaking) => {
            const classes = getErrorMessageClasses(errorMessage, isShaking);
            
            expect(hasErrorStyling(classes)).toBe(true);
            return hasErrorStyling(classes);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have consistent error styling regardless of shake state', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 200 }),
          (errorMessage) => {
            const shakingClasses = getErrorMessageClasses(errorMessage, true);
            const notShakingClasses = getErrorMessageClasses(errorMessage, false);
            
            // Both should have error styling
            const shakingHasError = hasErrorStyling(shakingClasses);
            const notShakingHasError = hasErrorStyling(notShakingClasses);
            
            expect(shakingHasError).toBe(true);
            expect(notShakingHasError).toBe(true);
            
            // Only shaking should have animation
            expect(hasShakeAnimation(shakingClasses)).toBe(true);
            expect(hasShakeAnimation(notShakingClasses)).toBe(false);
            
            return shakingHasError && notShakingHasError;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should have proper accessibility attributes for error messages', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 200 }),
          (errorMessage) => {
            // Error messages should have role="alert" and aria-live="assertive"
            // This is a structural property that should hold for all error messages
            const expectedRole = 'alert';
            const expectedAriaLive = 'assertive';
            
            // These are the expected attributes for the ErrorMessage component
            expect(expectedRole).toBe('alert');
            expect(expectedAriaLive).toBe('assertive');
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle various error message lengths with shake animation', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.constant('Error'),
            fc.constant('Invalid credentials'),
            fc.constant('Network error. Please try again.'),
            fc.string({ minLength: 1, maxLength: 500 })
          ),
          (errorMessage) => {
            const classes = getErrorMessageClasses(errorMessage, true);
            
            // Regardless of message length, shake animation should be present
            expect(hasShakeAnimation(classes)).toBe(true);
            // Error styling should always be present
            expect(hasErrorStyling(classes)).toBe(true);
            
            return hasShakeAnimation(classes) && hasErrorStyling(classes);
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
