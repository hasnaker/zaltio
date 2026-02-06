/**
 * Property-Based Tests for Form Validation
 * 
 * Feature: zalt-enterprise-landing
 * Property 14: Form validation rejects invalid input
 * Validates: Requirements 13.2, 13.3, 17.6
 */

import * as fc from 'fast-check';
import {
  validateEmail,
  validateRequired,
  validatePhone,
  validateUrl,
  validateDomain,
  validateLength,
  validatePassword,
  validatePasswordMatch,
  validateContactForm,
  validateLeadForm,
  validateNewsletterEmail,
  ValidationResult,
} from '../validation';

describe('Feature: zalt-enterprise-landing, Property 14: Form validation rejects invalid input', () => {
  describe('Email Validation Properties', () => {
    it('should reject emails without @ symbol', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }).filter(s => !s.includes('@') && s.trim().length > 0),
          (invalidEmail) => {
            const result = validateEmail(invalidEmail);
            return result.valid === false && result.code === 'invalid_email';
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject emails without domain part after @', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }).map(s => `${s}@`),
          (invalidEmail) => {
            const result = validateEmail(invalidEmail);
            return result.valid === false;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject emails without TLD (no dot after @)', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.string({ minLength: 1 }).filter(s => !s.includes('@') && !s.includes('.') && s.trim().length > 0),
            fc.string({ minLength: 1 }).filter(s => !s.includes('.') && s.trim().length > 0)
          ).map(([local, domain]) => `${local}@${domain}`),
          (invalidEmail) => {
            const result = validateEmail(invalidEmail);
            return result.valid === false;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept valid email formats', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.stringMatching(/^[a-z][a-z0-9]{2,10}$/),
            fc.stringMatching(/^[a-z]{3,10}$/),
            fc.constantFrom('com', 'org', 'net', 'io', 'co')
          ).map(([local, domain, tld]) => `${local}@${domain}.${tld}`),
          (validEmail) => {
            const result = validateEmail(validEmail);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject empty email', () => {
      const emptyValues = ['', '   ', '\t', '\n'];
      for (const empty of emptyValues) {
        const result = validateEmail(empty);
        expect(result.valid).toBe(false);
        expect(result.code).toBe('required');
      }
    });
  });

  describe('Required Field Validation Properties', () => {
    it('should reject null and undefined values', () => {
      expect(validateRequired(null).valid).toBe(false);
      expect(validateRequired(undefined).valid).toBe(false);
    });

    it('should reject empty strings and whitespace-only strings', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('', ' ', '  ', '\t', '\n', '   \t\n   '),
          (emptyString) => {
            const result = validateRequired(emptyString);
            return result.valid === false && result.code === 'required';
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject empty arrays', () => {
      const result = validateRequired([]);
      expect(result.valid).toBe(false);
      expect(result.code).toBe('required');
    });

    it('should accept non-empty strings', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }).filter(s => s.trim().length > 0),
          (nonEmptyString) => {
            const result = validateRequired(nonEmptyString);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept non-empty arrays', () => {
      fc.assert(
        fc.property(
          fc.array(fc.anything(), { minLength: 1 }),
          (nonEmptyArray) => {
            const result = validateRequired(nonEmptyArray);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept numbers including zero', () => {
      fc.assert(
        fc.property(
          fc.integer(),
          (num) => {
            const result = validateRequired(num);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Phone Validation Properties', () => {
    it('should accept valid international phone formats', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.constantFrom('+1', '+44', '+90', '+49', '+33'),
            fc.stringMatching(/^[0-9]{10}$/)
          ).map(([prefix, number]) => `${prefix}${number}`),
          (validPhone) => {
            const result = validatePhone(validPhone);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject phone numbers with letters', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 5 }).filter(s => /[a-zA-Z]/.test(s)),
          (invalidPhone) => {
            const result = validatePhone(invalidPhone);
            return result.valid === false;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject empty phone numbers', () => {
      const result = validatePhone('');
      expect(result.valid).toBe(false);
      expect(result.code).toBe('required');
    });
  });

  describe('URL Validation Properties', () => {
    it('should accept valid HTTPS URLs', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.constantFrom('https://'),
            fc.stringMatching(/^[a-z]{3,10}$/),
            fc.constantFrom('.com', '.org', '.io', '.net')
          ).map(([protocol, domain, tld]) => `${protocol}${domain}${tld}`),
          (validUrl) => {
            const result = validateUrl(validUrl);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept valid HTTP URLs', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.constantFrom('http://'),
            fc.stringMatching(/^[a-z]{3,10}$/),
            fc.constantFrom('.com', '.org', '.io')
          ).map(([protocol, domain, tld]) => `${protocol}${domain}${tld}`),
          (validUrl) => {
            const result = validateUrl(validUrl);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject URLs without protocol', () => {
      fc.assert(
        fc.property(
          fc.stringMatching(/^[a-z]{3,10}\.(com|org|io)$/),
          (urlWithoutProtocol) => {
            const result = validateUrl(urlWithoutProtocol);
            return result.valid === false;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject empty URLs', () => {
      const result = validateUrl('');
      expect(result.valid).toBe(false);
      expect(result.code).toBe('required');
    });
  });

  describe('Domain Validation Properties', () => {
    it('should accept valid domain names', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.stringMatching(/^[a-z]{3,10}$/),
            fc.constantFrom('.com', '.org', '.io', '.net', '.co')
          ).map(([name, tld]) => `${name}${tld}`),
          (validDomain) => {
            const result = validateDomain(validDomain);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept subdomains', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.stringMatching(/^[a-z]{2,5}$/),
            fc.stringMatching(/^[a-z]{3,8}$/),
            fc.constantFrom('.com', '.org', '.io')
          ).map(([sub, name, tld]) => `${sub}.${name}${tld}`),
          (validDomain) => {
            const result = validateDomain(validDomain);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject domains without TLD', () => {
      fc.assert(
        fc.property(
          fc.stringMatching(/^[a-z]{3,10}$/).filter(s => !s.includes('.')),
          (invalidDomain) => {
            const result = validateDomain(invalidDomain);
            return result.valid === false;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Length Validation Properties', () => {
    it('should reject strings shorter than minimum', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.integer({ min: 5, max: 20 }),
            fc.string({ minLength: 0, maxLength: 4 })
          ),
          ([minLength, shortString]) => {
            const result = validateLength(shortString, { min: minLength });
            return result.valid === false && result.code === 'too_short';
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject strings longer than maximum', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.integer({ min: 1, max: 5 }),
            fc.string({ minLength: 6, maxLength: 20 })
          ),
          ([maxLength, longString]) => {
            const result = validateLength(longString, { max: maxLength });
            return result.valid === false && result.code === 'too_long';
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should accept strings within valid range', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.integer({ min: 1, max: 5 }),
            fc.integer({ min: 10, max: 20 })
          ).chain(([min, max]) => 
            fc.tuple(
              fc.constant(min),
              fc.constant(max),
              fc.string({ minLength: min, maxLength: max })
            )
          ),
          ([min, max, validString]) => {
            const result = validateLength(validString, { min, max });
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Password Validation Properties', () => {
    it('should accept passwords meeting all requirements', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.stringMatching(/^[A-Z][a-z]{3,5}$/),
            fc.stringMatching(/^[0-9]{2,3}$/),
            fc.stringMatching(/^[a-z]{2,4}$/)
          ).map(([upper, num, lower]) => `${upper}${num}${lower}`),
          (validPassword) => {
            const result = validatePassword(validPassword);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject passwords without uppercase', () => {
      fc.assert(
        fc.property(
          fc.stringMatching(/^[a-z0-9]{8,15}$/),
          (noUppercase) => {
            const result = validatePassword(noUppercase);
            return result.valid === false && result.code === 'password_weak';
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject passwords without lowercase', () => {
      fc.assert(
        fc.property(
          fc.stringMatching(/^[A-Z0-9]{8,15}$/),
          (noLowercase) => {
            const result = validatePassword(noLowercase);
            return result.valid === false && result.code === 'password_weak';
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject passwords without numbers', () => {
      fc.assert(
        fc.property(
          fc.stringMatching(/^[A-Za-z]{8,15}$/),
          (noNumbers) => {
            const result = validatePassword(noNumbers);
            return result.valid === false && result.code === 'password_weak';
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject passwords shorter than 8 characters', () => {
      fc.assert(
        fc.property(
          fc.stringMatching(/^[A-Za-z0-9]{1,7}$/),
          (shortPassword) => {
            const result = validatePassword(shortPassword);
            return result.valid === false;
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Password Match Validation Properties', () => {
    it('should accept matching passwords', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 1 }),
          (password) => {
            const result = validatePasswordMatch(password, password);
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject non-matching passwords', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.string({ minLength: 1 }),
            fc.string({ minLength: 1 })
          ).filter(([a, b]) => a !== b),
          ([password, confirmPassword]) => {
            const result = validatePasswordMatch(password, confirmPassword);
            return result.valid === false && result.code === 'passwords_mismatch';
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Contact Form Validation Properties', () => {
    it('should accept valid contact form data', () => {
      fc.assert(
        fc.property(
          fc.record({
            // Name must start with letter and not be all spaces
            name: fc.stringMatching(/^[A-Za-z][A-Za-z ]{1,49}$/).filter(s => s.trim().length >= 2),
            email: fc.tuple(
              fc.stringMatching(/^[a-z]{3,8}$/),
              fc.stringMatching(/^[a-z]{3,8}$/),
              fc.constantFrom('com', 'org', 'io')
            ).map(([local, domain, tld]) => `${local}@${domain}.${tld}`),
            company: fc.option(fc.stringMatching(/^[A-Za-z][A-Za-z ]{1,49}$/).filter(s => s.trim().length >= 2), { nil: undefined }),
            message: fc.stringMatching(/^[A-Za-z][A-Za-z0-9 .,!?]{9,99}$/)
          }),
          (formData) => {
            const result = validateContactForm({
              name: formData.name,
              email: formData.email,
              company: formData.company,
              message: formData.message
            });
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject contact form with invalid email', () => {
      fc.assert(
        fc.property(
          fc.record({
            name: fc.stringMatching(/^[A-Za-z ]{2,50}$/),
            email: fc.string({ minLength: 1 }).filter(s => !s.includes('@')),
            message: fc.stringMatching(/^[A-Za-z0-9 .,!?]{10,100}$/)
          }),
          (formData) => {
            const result = validateContactForm({
              name: formData.name,
              email: formData.email,
              message: formData.message
            });
            return result.valid === false && 
                   result.errors.some(e => e.field === 'email');
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject contact form with empty name', () => {
      const result = validateContactForm({
        name: '',
        email: 'test@example.com',
        message: 'This is a test message'
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'name')).toBe(true);
    });

    it('should reject contact form with empty message', () => {
      const result = validateContactForm({
        name: 'John Doe',
        email: 'test@example.com',
        message: ''
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'message')).toBe(true);
    });
  });

  describe('Lead Form Validation Properties', () => {
    it('should accept valid lead form data', () => {
      fc.assert(
        fc.property(
          fc.record({
            // Name must start with letter and not be all spaces
            name: fc.stringMatching(/^[A-Za-z][A-Za-z ]{1,49}$/).filter(s => s.trim().length >= 2),
            email: fc.tuple(
              fc.stringMatching(/^[a-z]{3,8}$/),
              fc.stringMatching(/^[a-z]{3,8}$/),
              fc.constantFrom('com', 'org', 'io')
            ).map(([local, domain, tld]) => `${local}@${domain}.${tld}`),
            // Company must start with letter and not be all spaces
            company: fc.stringMatching(/^[A-Za-z][A-Za-z ]{1,49}$/).filter(s => s.trim().length >= 2)
          }),
          (formData) => {
            const result = validateLeadForm({
              name: formData.name,
              email: formData.email,
              company: formData.company
            });
            return result.valid === true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject lead form with missing company', () => {
      const result = validateLeadForm({
        name: 'John Doe',
        email: 'test@example.com',
        company: ''
      });
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.field === 'company')).toBe(true);
    });
  });

  describe('Newsletter Email Validation Properties', () => {
    it('should validate newsletter email same as regular email', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.stringMatching(/^[a-z]{3,8}$/),
            fc.stringMatching(/^[a-z]{3,8}$/),
            fc.constantFrom('com', 'org', 'io')
          ).map(([local, domain, tld]) => `${local}@${domain}.${tld}`),
          (validEmail) => {
            const emailResult = validateEmail(validEmail);
            const newsletterResult = validateNewsletterEmail(validEmail);
            return emailResult.valid === newsletterResult.valid;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});

describe('Validation Edge Cases', () => {
  it('should handle unicode characters in names', () => {
    const result = validateContactForm({
      name: 'José García',
      email: 'jose@example.com',
      message: 'This is a test message with unicode'
    });
    expect(result.valid).toBe(true);
  });

  it('should handle very long valid inputs', () => {
    // Name max is 100, so 101 should fail
    const longName = 'A'.repeat(101);
    // Message max is 5000, so 5001 should fail
    const longMessage = 'A'.repeat(5001);
    const result = validateContactForm({
      name: longName,
      email: 'test@example.com',
      message: longMessage
    });
    // Should fail due to length constraints
    expect(result.valid).toBe(false);
  });

  it('should handle special characters in email local part', () => {
    const result = validateEmail('test.user+tag@example.com');
    expect(result.valid).toBe(true);
  });

  it('should handle subdomains in email', () => {
    const result = validateEmail('user@mail.example.com');
    expect(result.valid).toBe(true);
  });
});
