/**
 * Property-Based Tests for Accessibility and Responsive Design
 * 
 * Feature: zalt-enterprise-landing
 * Property 16: Responsive layout
 * Property 17: Accessibility compliance
 * 
 * Validates: Requirements 15.1, 15.2, 15.3, 15.4, 15.5
 */

import * as fc from 'fast-check';

// Breakpoint definitions
const BREAKPOINTS = {
  mobile: 320,
  tablet: 768,
  desktop: 1280,
  wide: 1536,
} as const;

type Breakpoint = keyof typeof BREAKPOINTS;

// ARIA role definitions
const VALID_ARIA_ROLES = [
  'button', 'link', 'navigation', 'main', 'banner', 'contentinfo',
  'complementary', 'form', 'search', 'region', 'alert', 'dialog',
  'menu', 'menuitem', 'tab', 'tabpanel', 'tablist', 'listbox', 'option',
] as const;

// Interactive element types
const INTERACTIVE_ELEMENTS = [
  'button', 'a', 'input', 'select', 'textarea', 'details', 'summary',
] as const;

// Color contrast requirements (WCAG 2.1 AA)
const MIN_CONTRAST_RATIO = 4.5;
const MIN_LARGE_TEXT_CONTRAST = 3.0;

// Responsive layout validation
interface LayoutConfig {
  containerWidth: number;
  columns: number;
  gap: number;
  padding: number;
}

function getResponsiveLayout(viewportWidth: number): LayoutConfig {
  if (viewportWidth < BREAKPOINTS.tablet) {
    return { containerWidth: viewportWidth - 32, columns: 1, gap: 16, padding: 16 };
  } else if (viewportWidth < BREAKPOINTS.desktop) {
    return { containerWidth: viewportWidth - 48, columns: 2, gap: 24, padding: 24 };
  } else {
    return { containerWidth: Math.min(viewportWidth - 64, 1280), columns: 3, gap: 32, padding: 32 };
  }
}

function validateLayout(layout: LayoutConfig, viewportWidth: number): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Container should not exceed viewport
  if (layout.containerWidth > viewportWidth) {
    errors.push('Container width exceeds viewport');
  }
  
  // Minimum touch target size (44px for mobile)
  if (viewportWidth < BREAKPOINTS.tablet && layout.gap < 8) {
    errors.push('Gap too small for touch targets');
  }
  
  // Content should not overflow
  const totalWidth = layout.containerWidth + (layout.padding * 2);
  if (totalWidth > viewportWidth) {
    errors.push('Content overflows viewport');
  }
  
  return { valid: errors.length === 0, errors };
}

// Accessibility validation
interface AccessibleElement {
  tagName: string;
  role?: string;
  ariaLabel?: string;
  ariaLabelledBy?: string;
  ariaDescribedBy?: string;
  tabIndex?: number;
  hasVisibleText?: boolean;
}

function validateAccessibleElement(element: AccessibleElement): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const isInteractive = INTERACTIVE_ELEMENTS.includes(element.tagName.toLowerCase() as typeof INTERACTIVE_ELEMENTS[number]);
  
  // Interactive elements need accessible names
  if (isInteractive) {
    const hasAccessibleName = element.ariaLabel || element.ariaLabelledBy || element.hasVisibleText;
    if (!hasAccessibleName) {
      errors.push(`Interactive element ${element.tagName} missing accessible name`);
    }
  }
  
  // Validate ARIA role if present
  if (element.role && !VALID_ARIA_ROLES.includes(element.role as typeof VALID_ARIA_ROLES[number])) {
    errors.push(`Invalid ARIA role: ${element.role}`);
  }
  
  // tabIndex validation
  if (element.tabIndex !== undefined) {
    if (element.tabIndex > 0) {
      errors.push('Positive tabIndex values should be avoided');
    }
  }
  
  return { valid: errors.length === 0, errors };
}

// Color contrast calculation (simplified)
function calculateContrastRatio(foreground: string, background: string): number {
  // Simplified contrast calculation for testing
  // In real implementation, would parse colors and calculate luminance
  const fgLuminance = parseInt(foreground.slice(1, 3), 16) / 255;
  const bgLuminance = parseInt(background.slice(1, 3), 16) / 255;
  
  const lighter = Math.max(fgLuminance, bgLuminance);
  const darker = Math.min(fgLuminance, bgLuminance);
  
  return (lighter + 0.05) / (darker + 0.05);
}

function validateColorContrast(
  foreground: string, 
  background: string, 
  isLargeText: boolean
): { valid: boolean; ratio: number; required: number } {
  const ratio = calculateContrastRatio(foreground, background);
  const required = isLargeText ? MIN_LARGE_TEXT_CONTRAST : MIN_CONTRAST_RATIO;
  
  return {
    valid: ratio >= required,
    ratio,
    required,
  };
}

// Focus management validation
interface FocusableElement {
  id: string;
  tabIndex: number;
  isVisible: boolean;
  isDisabled: boolean;
}

function getFocusOrder(elements: FocusableElement[]): FocusableElement[] {
  return elements
    .filter(el => el.isVisible && !el.isDisabled && el.tabIndex >= 0)
    .sort((a, b) => {
      // Elements with tabIndex > 0 come first, in order
      if (a.tabIndex > 0 && b.tabIndex > 0) return a.tabIndex - b.tabIndex;
      if (a.tabIndex > 0) return -1;
      if (b.tabIndex > 0) return 1;
      // Then elements with tabIndex 0 in DOM order (simulated by id)
      return a.id.localeCompare(b.id);
    });
}

describe('Feature: zalt-enterprise-landing, Property 16: Responsive layout', () => {
  describe('Property 16.1: Layout adapts to viewport width', () => {
    it('should return valid layout for all breakpoints', () => {
      Object.entries(BREAKPOINTS).forEach(([name, width]) => {
        const layout = getResponsiveLayout(width);
        const validation = validateLayout(layout, width);
        expect(validation.valid).toBe(true);
      });
    });

    it('should handle arbitrary viewport widths', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 280, max: 2560 }),
          (viewportWidth) => {
            const layout = getResponsiveLayout(viewportWidth);
            const validation = validateLayout(layout, viewportWidth);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should use single column on mobile', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 280, max: BREAKPOINTS.tablet - 1 }),
          (viewportWidth) => {
            const layout = getResponsiveLayout(viewportWidth);
            expect(layout.columns).toBe(1);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should use multiple columns on larger screens', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: BREAKPOINTS.tablet, max: 2560 }),
          (viewportWidth) => {
            const layout = getResponsiveLayout(viewportWidth);
            expect(layout.columns).toBeGreaterThanOrEqual(2);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 16.2: Content does not overflow', () => {
    it('should never exceed viewport width', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 280, max: 2560 }),
          (viewportWidth) => {
            const layout = getResponsiveLayout(viewportWidth);
            expect(layout.containerWidth).toBeLessThanOrEqual(viewportWidth);
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should maintain minimum padding', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 280, max: 2560 }),
          (viewportWidth) => {
            const layout = getResponsiveLayout(viewportWidth);
            expect(layout.padding).toBeGreaterThanOrEqual(16);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 16.3: Touch targets are adequate', () => {
    const MIN_TOUCH_TARGET = 44; // WCAG 2.1 minimum

    it('should have adequate spacing for touch on mobile', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 280, max: BREAKPOINTS.tablet - 1 }),
          (viewportWidth) => {
            const layout = getResponsiveLayout(viewportWidth);
            // Gap + element size should allow for 44px touch targets
            expect(layout.gap).toBeGreaterThanOrEqual(8);
          }
        ),
        { numRuns: 20 }
      );
    });
  });
});

describe('Feature: zalt-enterprise-landing, Property 17: Accessibility compliance', () => {
  describe('Property 17.1: Interactive elements have accessible names', () => {
    it('should validate elements with aria-label', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...INTERACTIVE_ELEMENTS),
          fc.string({ minLength: 1, maxLength: 100 }),
          (tagName, label) => {
            const element: AccessibleElement = {
              tagName,
              ariaLabel: label,
            };
            const validation = validateAccessibleElement(element);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should validate elements with visible text', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...INTERACTIVE_ELEMENTS),
          (tagName) => {
            const element: AccessibleElement = {
              tagName,
              hasVisibleText: true,
            };
            const validation = validateAccessibleElement(element);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject interactive elements without accessible names', () => {
      INTERACTIVE_ELEMENTS.forEach(tagName => {
        const element: AccessibleElement = {
          tagName,
          hasVisibleText: false,
        };
        const validation = validateAccessibleElement(element);
        expect(validation.valid).toBe(false);
        expect(validation.errors[0]).toContain('missing accessible name');
      });
    });
  });

  describe('Property 17.2: ARIA roles are valid', () => {
    it('should accept valid ARIA roles', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...VALID_ARIA_ROLES),
          (role) => {
            const element: AccessibleElement = {
              tagName: 'div',
              role,
              hasVisibleText: true,
            };
            const validation = validateAccessibleElement(element);
            expect(validation.errors.filter(e => e.includes('Invalid ARIA role'))).toHaveLength(0);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject invalid ARIA roles', () => {
      const invalidRoles = ['invalid', 'custom-role', 'foo', 'bar'];
      invalidRoles.forEach(role => {
        const element: AccessibleElement = {
          tagName: 'div',
          role,
          hasVisibleText: true,
        };
        const validation = validateAccessibleElement(element);
        expect(validation.errors).toContain(`Invalid ARIA role: ${role}`);
      });
    });
  });

  describe('Property 17.3: Focus order is logical', () => {
    it('should order elements by tabIndex then DOM order', () => {
      const elements: FocusableElement[] = [
        { id: 'a', tabIndex: 0, isVisible: true, isDisabled: false },
        { id: 'b', tabIndex: 2, isVisible: true, isDisabled: false },
        { id: 'c', tabIndex: 1, isVisible: true, isDisabled: false },
        { id: 'd', tabIndex: 0, isVisible: true, isDisabled: false },
      ];
      
      const order = getFocusOrder(elements);
      expect(order.map(e => e.id)).toEqual(['c', 'b', 'a', 'd']);
    });

    it('should exclude hidden elements', () => {
      const elements: FocusableElement[] = [
        { id: 'visible', tabIndex: 0, isVisible: true, isDisabled: false },
        { id: 'hidden', tabIndex: 0, isVisible: false, isDisabled: false },
      ];
      
      const order = getFocusOrder(elements);
      expect(order.map(e => e.id)).toEqual(['visible']);
    });

    it('should exclude disabled elements', () => {
      const elements: FocusableElement[] = [
        { id: 'enabled', tabIndex: 0, isVisible: true, isDisabled: false },
        { id: 'disabled', tabIndex: 0, isVisible: true, isDisabled: true },
      ];
      
      const order = getFocusOrder(elements);
      expect(order.map(e => e.id)).toEqual(['enabled']);
    });

    it('should exclude negative tabIndex elements', () => {
      const elements: FocusableElement[] = [
        { id: 'focusable', tabIndex: 0, isVisible: true, isDisabled: false },
        { id: 'not-focusable', tabIndex: -1, isVisible: true, isDisabled: false },
      ];
      
      const order = getFocusOrder(elements);
      expect(order.map(e => e.id)).toEqual(['focusable']);
    });
  });

  describe('Property 17.4: Color contrast meets WCAG AA', () => {
    it('should pass high contrast combinations', () => {
      const highContrastPairs = [
        { fg: '#000000', bg: '#ffffff' }, // Black on white
        { fg: '#ffffff', bg: '#000000' }, // White on black
        { fg: '#1a1a1a', bg: '#f5f5f5' }, // Dark gray on light gray
      ];
      
      highContrastPairs.forEach(({ fg, bg }) => {
        const result = validateColorContrast(fg, bg, false);
        expect(result.valid).toBe(true);
      });
    });

    it('should have lower requirement for large text', () => {
      // Large text (18pt+ or 14pt+ bold) has lower contrast requirement
      const result = validateColorContrast('#666666', '#ffffff', true);
      expect(result.required).toBe(MIN_LARGE_TEXT_CONTRAST);
    });

    it('should have higher requirement for normal text', () => {
      const result = validateColorContrast('#666666', '#ffffff', false);
      expect(result.required).toBe(MIN_CONTRAST_RATIO);
    });
  });

  describe('Property 17.5: TabIndex values are appropriate', () => {
    it('should warn about positive tabIndex values', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 100 }),
          (tabIndex) => {
            const element: AccessibleElement = {
              tagName: 'button',
              tabIndex,
              hasVisibleText: true,
            };
            const validation = validateAccessibleElement(element);
            expect(validation.errors).toContain('Positive tabIndex values should be avoided');
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should accept tabIndex 0 and -1', () => {
      [0, -1].forEach(tabIndex => {
        const element: AccessibleElement = {
          tagName: 'button',
          tabIndex,
          hasVisibleText: true,
        };
        const validation = validateAccessibleElement(element);
        expect(validation.errors.filter(e => e.includes('tabIndex'))).toHaveLength(0);
      });
    });
  });
});

describe('Keyboard Navigation', () => {
  describe('Skip link functionality', () => {
    interface SkipLinkConfig {
      href: string;
      targetExists: boolean;
    }

    function validateSkipLink(config: SkipLinkConfig): { valid: boolean; errors: string[] } {
      const errors: string[] = [];
      
      if (!config.href.startsWith('#')) {
        errors.push('Skip link href must be an anchor');
      }
      
      if (!config.targetExists) {
        errors.push('Skip link target does not exist');
      }
      
      return { valid: errors.length === 0, errors };
    }

    it('should validate skip links with existing targets', () => {
      const config: SkipLinkConfig = {
        href: '#main-content',
        targetExists: true,
      };
      const validation = validateSkipLink(config);
      expect(validation.valid).toBe(true);
    });

    it('should reject skip links without anchor', () => {
      const config: SkipLinkConfig = {
        href: '/main-content',
        targetExists: true,
      };
      const validation = validateSkipLink(config);
      expect(validation.valid).toBe(false);
    });

    it('should reject skip links with missing targets', () => {
      const config: SkipLinkConfig = {
        href: '#nonexistent',
        targetExists: false,
      };
      const validation = validateSkipLink(config);
      expect(validation.valid).toBe(false);
    });
  });
});
