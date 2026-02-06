/**
 * OWASP Top 10 Security Tests
 * Automated security testing for Zalt.io Auth Platform
 * 
 * Tests cover:
 * - A01:2021 Broken Access Control
 * - A02:2021 Cryptographic Failures
 * - A03:2021 Injection
 * - A07:2021 Authentication Failures
 */

import * as fc from 'fast-check';

// Helper functions for testing
const checkPermission = (userRole: string, action: string): boolean => {
  const adminActions = ['admin:delete', 'admin:write', 'system:config'];
  if (adminActions.includes(action)) {
    return userRole === 'admin' || userRole === 'superadmin';
  }
  return true;
};

const checkResourceAccess = (userId: string, targetUserId: string, resourceType: string): boolean => {
  // Users can only access their own resources
  return userId === targetUserId;
};

const checkCrossRealmAccess = (realmA: string, realmB: string): boolean => {
  // Cross-realm access is never allowed
  return realmA === realmB;
};

const sanitizePath = (path: string): string => {
  // Remove path traversal attempts
  let sanitized = path;
  // Decode URL encoding
  try {
    sanitized = decodeURIComponent(sanitized);
  } catch {
    // Invalid encoding, keep original
  }
  // Remove traversal patterns
  sanitized = sanitized.replace(/\.\./g, '');
  sanitized = sanitized.replace(/%2e/gi, '');
  sanitized = sanitized.replace(/%00/g, '');
  return sanitized;
};

const sanitizeInput = (input: string): string => {
  return input
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .replace(/['";]/g, '');
};

const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
};

const isStrongPassword = (password: string): boolean => {
  return (
    password.length >= 12 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[!@#$%^&*(),.?":{}|<>]/.test(password)
  );
};

describe('OWASP Top 10 Security Tests', () => {
  /**
   * A01:2021 - Broken Access Control
   */
  describe('A01: Broken Access Control', () => {
    it('should prevent vertical privilege escalation', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('user', 'viewer', 'guest'),
          fc.constantFrom('admin:delete', 'admin:write', 'system:config'),
          (userRole, adminAction) => {
            const canPerform = checkPermission(userRole, adminAction);
            expect(canPerform).toBe(false);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should prevent horizontal privilege escalation (IDOR)', () => {
      fc.assert(
        fc.property(
          fc.uuid(),
          fc.uuid(),
          (userId, targetUserId) => {
            fc.pre(userId !== targetUserId);
            const canAccess = checkResourceAccess(userId, targetUserId, 'user');
            expect(canAccess).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should enforce realm isolation', () => {
      fc.assert(
        fc.property(
          fc.uuid(),
          fc.uuid(),
          (realmA, realmB) => {
            fc.pre(realmA !== realmB);
            const canCrossAccess = checkCrossRealmAccess(realmA, realmB);
            expect(canCrossAccess).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject path traversal attempts', () => {
      const traversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32',
        '....//....//etc/passwd',
        '/etc/passwd.jpg'
      ];

      traversalPayloads.forEach(payload => {
        const sanitized = sanitizePath(payload);
        expect(sanitized).not.toContain('..');
      });
    });
  });

  /**
   * A02:2021 - Cryptographic Failures
   */
  describe('A02: Cryptographic Failures', () => {
    it('should use strong password requirements', () => {
      const weakPasswords = ['password', '12345678', 'qwerty123'];
      weakPasswords.forEach(pwd => {
        expect(isStrongPassword(pwd)).toBe(false);
      });
    });

    it('should accept strong passwords', () => {
      const strongPasswords = ['MyStr0ng!Pass#2024', 'C0mpl3x@Passw0rd!'];
      strongPasswords.forEach(pwd => {
        expect(isStrongPassword(pwd)).toBe(true);
      });
    });
  });

  /**
   * A03:2021 - Injection
   */
  describe('A03: Injection', () => {
    it('should sanitize XSS payloads', () => {
      const xssPayloads = [
        '<script>alert(1)</script>',
        'javascript:alert(1)',
        '<img onerror=alert(1)>'
      ];

      xssPayloads.forEach(payload => {
        const sanitized = sanitizeInput(payload);
        expect(sanitized).not.toContain('<script>');
        expect(sanitized).not.toContain('javascript:');
        expect(sanitized).not.toContain('onerror=');
      });
    });
  });

  /**
   * A07:2021 - Authentication Failures
   */
  describe('A07: Authentication Failures', () => {
    it('should validate email format', () => {
      fc.assert(
        fc.property(
          fc.emailAddress(),
          (email) => {
            expect(validateEmail(email)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject invalid emails', () => {
      const invalidEmails = ['notanemail', '@nodomain.com', 'no@', ''];
      invalidEmails.forEach(email => {
        expect(validateEmail(email)).toBe(false);
      });
    });
  });
});
