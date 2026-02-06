/**
 * Property-Based Tests for Contact Form and Rate Limiting
 * 
 * Feature: zalt-enterprise-landing
 * Property 14: Form validation rejects invalid input
 * Property 15: Rate limiting
 * 
 * Validates: Requirements 13.2, 13.3, 13.6, 17.6
 */

import * as fc from 'fast-check';

// Form data structure
interface FormData {
  name: string;
  email: string;
  company: string;
  message: string;
}

interface FormErrors {
  name?: string;
  email?: string;
  company?: string;
  message?: string;
}

// Validation functions (mirrors actual implementation)
function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validateForm(formData: FormData): { valid: boolean; errors: FormErrors } {
  const errors: FormErrors = {};

  if (!formData.name.trim()) {
    errors.name = 'Name is required';
  }

  if (!formData.email.trim()) {
    errors.email = 'Email is required';
  } else if (!validateEmail(formData.email)) {
    errors.email = 'Please enter a valid email address';
  }

  if (!formData.company.trim()) {
    errors.company = 'Company is required';
  }

  if (!formData.message.trim()) {
    errors.message = 'Message is required';
  } else if (formData.message.trim().length < 10) {
    errors.message = 'Message must be at least 10 characters';
  }

  return { valid: Object.keys(errors).length === 0, errors };
}

// Rate limiting simulation
interface RateLimitRecord {
  count: number;
  resetTime: number;
}

class RateLimiter {
  private records = new Map<string, RateLimitRecord>();
  private limit: number;
  private windowMs: number;

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  check(key: string, now: number = Date.now()): { allowed: boolean; remaining: number } {
    const record = this.records.get(key);

    if (!record || now > record.resetTime) {
      this.records.set(key, { count: 1, resetTime: now + this.windowMs });
      return { allowed: true, remaining: this.limit - 1 };
    }

    if (record.count >= this.limit) {
      return { allowed: false, remaining: 0 };
    }

    record.count++;
    return { allowed: true, remaining: this.limit - record.count };
  }

  reset(key: string): void {
    this.records.delete(key);
  }
}

describe('Feature: zalt-enterprise-landing, Property 14: Form validation', () => {
  describe('Property 14.1: Email validation', () => {
    it('should accept valid email addresses', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          (email) => {
            expect(validateEmail(email)).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject emails without @', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => !s.includes('@')),
          (email) => {
            expect(validateEmail(email)).toBe(false);
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should reject emails without domain', () => {
      const invalidEmails = ['test@', '@domain.com', 'test@.com', 'test@domain.'];
      invalidEmails.forEach(email => {
        expect(validateEmail(email)).toBe(false);
      });
    });
  });

  describe('Property 14.2: Required field validation', () => {
    it('should reject empty name', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('', '   ', '\t', '\n'),
          fc.emailAddress(),
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.string({ minLength: 10, maxLength: 200 }),
          (name, email, company, message) => {
            const result = validateForm({ name, email, company, message });
            expect(result.valid).toBe(false);
            expect(result.errors.name).toBeDefined();
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject empty email', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.constantFrom('', '   '),
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.string({ minLength: 10, maxLength: 200 }),
          (name, email, company, message) => {
            const result = validateForm({ name, email, company, message });
            expect(result.valid).toBe(false);
            expect(result.errors.email).toBeDefined();
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject empty company', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.emailAddress(),
          fc.constantFrom('', '   '),
          fc.string({ minLength: 10, maxLength: 200 }),
          (name, email, company, message) => {
            const result = validateForm({ name, email, company, message });
            expect(result.valid).toBe(false);
            expect(result.errors.company).toBeDefined();
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject empty message', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.emailAddress(),
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.constantFrom('', '   '),
          (name, email, company, message) => {
            const result = validateForm({ name, email, company, message });
            expect(result.valid).toBe(false);
            expect(result.errors.message).toBeDefined();
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 14.3: Message length validation', () => {
    it('should reject messages shorter than 10 characters', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.emailAddress(),
          fc.string({ minLength: 1, maxLength: 50 }),
          fc.string({ minLength: 1, maxLength: 9 }),
          (name, email, company, message) => {
            const result = validateForm({ name, email, company, message });
            expect(result.valid).toBe(false);
            expect(result.errors.message).toContain('at least 10 characters');
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should accept messages with 10 or more characters', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => s.trim().length > 0),
          fc.emailAddress(),
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => s.trim().length > 0),
          fc.string({ minLength: 10, maxLength: 200 }),
          (name, email, company, message) => {
            const result = validateForm({ name, email, company, message });
            expect(result.errors.message).toBeUndefined();
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  describe('Property 14.4: Valid form acceptance', () => {
    it('should accept valid form data', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => s.trim().length > 0),
          fc.emailAddress(),
          fc.string({ minLength: 1, maxLength: 50 }).filter(s => s.trim().length > 0),
          fc.string({ minLength: 10, maxLength: 200 }),
          (name, email, company, message) => {
            const result = validateForm({ name, email, company, message });
            expect(result.valid).toBe(true);
            expect(Object.keys(result.errors).length).toBe(0);
          }
        ),
        { numRuns: 30 }
      );
    });
  });
});

describe('Feature: zalt-enterprise-landing, Property 15: Rate limiting', () => {
  describe('Property 15.1: Rate limit enforcement', () => {
    it('should allow requests up to the limit', () => {
      const limiter = new RateLimiter(5, 60000);
      const key = 'test-ip';
      const now = Date.now();

      for (let i = 0; i < 5; i++) {
        const result = limiter.check(key, now);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(4 - i);
      }
    });

    it('should block requests after limit is reached', () => {
      const limiter = new RateLimiter(5, 60000);
      const key = 'test-ip';
      const now = Date.now();

      // Use up the limit
      for (let i = 0; i < 5; i++) {
        limiter.check(key, now);
      }

      // Next request should be blocked
      const result = limiter.check(key, now);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should reset after window expires', () => {
      const limiter = new RateLimiter(5, 60000);
      const key = 'test-ip';
      const now = Date.now();

      // Use up the limit
      for (let i = 0; i < 5; i++) {
        limiter.check(key, now);
      }

      // After window expires, should be allowed again
      const result = limiter.check(key, now + 60001);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });
  });

  describe('Property 15.2: Rate limit per key isolation', () => {
    it('should track limits separately per key', () => {
      fc.assert(
        fc.property(
          fc.array(fc.string({ minLength: 1, maxLength: 20 }), { minLength: 2, maxLength: 5 }),
          (keys) => {
            const uniqueKeys = [...new Set(keys)];
            if (uniqueKeys.length < 2) return true; // Skip if not enough unique keys

            const limiter = new RateLimiter(3, 60000);
            const now = Date.now();

            // Exhaust limit for first key
            for (let i = 0; i < 3; i++) {
              limiter.check(uniqueKeys[0], now);
            }

            // Second key should still be allowed
            const result = limiter.check(uniqueKeys[1], now);
            expect(result.allowed).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 15.3: Remaining count accuracy', () => {
    it('should accurately track remaining requests', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 20 }),
          fc.integer({ min: 1, max: 10 }),
          (limit, requests) => {
            const limiter = new RateLimiter(limit, 60000);
            const key = 'test';
            const now = Date.now();

            const actualRequests = Math.min(requests, limit);
            
            for (let i = 0; i < actualRequests; i++) {
              const result = limiter.check(key, now);
              if (i < limit) {
                expect(result.remaining).toBe(limit - i - 1);
              }
            }
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  describe('Property 15.4: Window timing', () => {
    it('should respect window boundaries', () => {
      const limiter = new RateLimiter(2, 1000); // 2 requests per second
      const key = 'test';
      const now = Date.now();

      // First request
      expect(limiter.check(key, now).allowed).toBe(true);
      // Second request
      expect(limiter.check(key, now).allowed).toBe(true);
      // Third request (blocked)
      expect(limiter.check(key, now).allowed).toBe(false);
      
      // Just before window expires (still blocked)
      expect(limiter.check(key, now + 999).allowed).toBe(false);
      
      // After window expires (allowed)
      expect(limiter.check(key, now + 1001).allowed).toBe(true);
    });
  });
});

describe('Contact Form Edge Cases', () => {
  it('should handle unicode characters in name', () => {
    const unicodeNames = ['José García', '田中太郎', 'Müller', 'Αλέξανδρος'];
    
    unicodeNames.forEach(name => {
      const result = validateForm({
        name,
        email: 'test@example.com',
        company: 'Test Co',
        message: 'This is a test message',
      });
      expect(result.errors.name).toBeUndefined();
    });
  });

  it('should handle very long inputs', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1000, maxLength: 2000 }),
        (longString) => {
          // Should not throw
          expect(() => validateForm({
            name: longString,
            email: 'test@example.com',
            company: longString,
            message: longString,
          })).not.toThrow();
        }
      ),
      { numRuns: 10 }
    );
  });

  it('should trim whitespace from inputs', () => {
    const result = validateForm({
      name: '  John Doe  ',
      email: 'test@example.com',
      company: '  Acme Inc  ',
      message: '  This is a test message  ',
    });
    expect(result.valid).toBe(true);
  });

  it('should handle special characters in message', () => {
    const specialMessages = [
      'Hello <script>alert("xss")</script>',
      'Test with "quotes" and \'apostrophes\'',
      'Line 1\nLine 2\nLine 3',
      'Tab\there\tand\tthere',
    ];

    specialMessages.forEach(message => {
      const result = validateForm({
        name: 'Test',
        email: 'test@example.com',
        company: 'Test Co',
        message,
      });
      // Should validate based on length, not content
      expect(result.errors.message).toBeUndefined();
    });
  });
});
