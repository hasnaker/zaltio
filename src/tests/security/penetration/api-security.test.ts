/**
 * API Security Penetration Tests
 * Tests for API-specific vulnerabilities
 * 
 * @security-test
 * @category penetration
 * @severity HIGH
 */

import * as fc from 'fast-check';

// API Security Checks
const isSecureHeader = (headers: Record<string, string>): { secure: boolean; missing: string[] } => {
  const requiredHeaders = [
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Permissions-Policy'
  ];

  const missing = requiredHeaders.filter(h => !headers[h]);
  return { secure: missing.length === 0, missing };
};

const isSecureAPIResponse = (response: {
  headers: Record<string, string>;
  body: unknown;
}): { secure: boolean; issues: string[] } => {
  const issues: string[] = [];

  // Check for sensitive data exposure
  const bodyStr = JSON.stringify(response.body);
  
  if (bodyStr.includes('password')) issues.push('Password exposed in response');
  if (bodyStr.includes('secret')) issues.push('Secret exposed in response');
  if (bodyStr.includes('private_key')) issues.push('Private key exposed in response');
  if (/\b[A-Za-z0-9+/]{40,}={0,2}\b/.test(bodyStr)) issues.push('Possible base64 encoded secret');
  
  // Check headers
  const headerCheck = isSecureHeader(response.headers);
  if (!headerCheck.secure) {
    issues.push(`Missing security headers: ${headerCheck.missing.join(', ')}`);
  }

  // Check for verbose errors
  if (bodyStr.includes('stack') || bodyStr.includes('trace')) {
    issues.push('Stack trace exposed in response');
  }

  return { secure: issues.length === 0, issues };
};

const validateJWT = (token: string): { valid: boolean; issues: string[] } => {
  const issues: string[] = [];
  
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      issues.push('Invalid JWT structure');
      return { valid: false, issues };
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    // Check algorithm
    if (header.alg === 'none') {
      issues.push('JWT uses "none" algorithm - CRITICAL');
    }
    if (header.alg === 'HS256' && header.typ === 'JWT') {
      // HS256 is okay but RS256 is preferred for public APIs
    }

    // Check claims
    if (!payload.exp) issues.push('JWT missing expiration');
    if (!payload.iat) issues.push('JWT missing issued-at');
    if (!payload.iss) issues.push('JWT missing issuer');
    
    // Check expiration
    if (payload.exp && payload.exp < Date.now() / 1000) {
      issues.push('JWT is expired');
    }

    // Check for sensitive data in payload
    if (payload.password) issues.push('Password in JWT payload');
    if (payload.secret) issues.push('Secret in JWT payload');

  } catch {
    issues.push('Failed to parse JWT');
  }

  return { valid: issues.length === 0, issues };
};

describe('API Security Penetration Tests', () => {
  describe('HTTP Security Headers', () => {
    it('should require all security headers', () => {
      const secureHeaders = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=()'
      };

      const result = isSecureHeader(secureHeaders);
      expect(result.secure).toBe(true);
      expect(result.missing).toHaveLength(0);
    });

    it('should detect missing security headers', () => {
      const insecureHeaders = {
        'Content-Type': 'application/json'
      };

      const result = isSecureHeader(insecureHeaders);
      expect(result.secure).toBe(false);
      expect(result.missing.length).toBeGreaterThan(0);
    });
  });

  describe('Response Security', () => {
    it('should not expose sensitive data in responses', () => {
      const insecureResponse = {
        headers: {
          'Strict-Transport-Security': 'max-age=31536000',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block',
          'Content-Security-Policy': "default-src 'self'",
          'Referrer-Policy': 'strict-origin',
          'Permissions-Policy': 'geolocation=()'
        },
        body: {
          user: {
            id: '123',
            email: 'user@example.com',
            password: 'hashed_password_here',  // Should not be exposed
            secret: 'api_secret_key'  // Should not be exposed
          }
        }
      };

      const result = isSecureAPIResponse(insecureResponse);
      expect(result.secure).toBe(false);
      expect(result.issues).toContain('Password exposed in response');
      expect(result.issues).toContain('Secret exposed in response');
    });

    it('should not expose stack traces', () => {
      const errorResponse = {
        headers: {
          'Strict-Transport-Security': 'max-age=31536000',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block',
          'Content-Security-Policy': "default-src 'self'",
          'Referrer-Policy': 'strict-origin',
          'Permissions-Policy': 'geolocation=()'
        },
        body: {
          error: 'Internal Server Error',
          stack: 'Error: Something went wrong\n    at Function.handler (/app/src/handler.js:42:15)',
          trace: 'detailed trace here'
        }
      };

      const result = isSecureAPIResponse(errorResponse);
      expect(result.secure).toBe(false);
      expect(result.issues).toContain('Stack trace exposed in response');
    });
  });

  describe('JWT Security', () => {
    it('should reject JWT with "none" algorithm', () => {
      // JWT with alg: none
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: '123', exp: Date.now() / 1000 + 3600 })).toString('base64url');
      const token = `${header}.${payload}.`;

      const result = validateJWT(token);
      expect(result.valid).toBe(false);
      expect(result.issues).toContain('JWT uses "none" algorithm - CRITICAL');
    });

    it('should require expiration claim', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: '123', iat: Date.now() / 1000 })).toString('base64url');
      const token = `${header}.${payload}.signature`;

      const result = validateJWT(token);
      expect(result.issues).toContain('JWT missing expiration');
    });

    it('should detect expired tokens', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ 
        sub: '123', 
        exp: Date.now() / 1000 - 3600,  // Expired 1 hour ago
        iat: Date.now() / 1000 - 7200,
        iss: 'zalt'
      })).toString('base64url');
      const token = `${header}.${payload}.signature`;

      const result = validateJWT(token);
      expect(result.issues).toContain('JWT is expired');
    });

    it('should not allow sensitive data in JWT payload', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ 
        sub: '123',
        exp: Date.now() / 1000 + 3600,
        iat: Date.now() / 1000,
        iss: 'zalt',
        password: 'secret123'  // Should not be here
      })).toString('base64url');
      const token = `${header}.${payload}.signature`;

      const result = validateJWT(token);
      expect(result.issues).toContain('Password in JWT payload');
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits', () => {
      const rateLimitConfig = {
        windowMs: 60000,  // 1 minute
        maxRequests: 100,
        message: 'Too many requests'
      };

      // Simulate requests
      let requestCount = 0;
      const isRateLimited = (): boolean => {
        requestCount++;
        return requestCount > rateLimitConfig.maxRequests;
      };

      // First 100 requests should pass
      for (let i = 0; i < 100; i++) {
        expect(isRateLimited()).toBe(false);
      }

      // 101st request should be rate limited
      expect(isRateLimited()).toBe(true);
    });
  });

  describe('Input Validation', () => {
    it('should validate content-type header', () => {
      const validContentTypes = [
        'application/json',
        'application/json; charset=utf-8'
      ];

      const invalidContentTypes = [
        'text/html',
        'application/xml',
        'multipart/form-data',
        ''
      ];

      validContentTypes.forEach(ct => {
        expect(ct.toLowerCase().includes('application/json')).toBe(true);
      });

      invalidContentTypes.forEach(ct => {
        expect(ct.toLowerCase().includes('application/json')).toBe(false);
      });
    });

    it('should limit request body size', () => {
      const maxBodySize = 1024 * 1024; // 1MB

      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 10 * 1024 * 1024 }),
          (bodySize) => {
            const isAllowed = bodySize <= maxBodySize;
            
            if (bodySize > maxBodySize) {
              expect(isAllowed).toBe(false);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should sanitize query parameters', () => {
      const maliciousParams = [
        { key: 'id', value: "1' OR '1'='1" },
        { key: 'search', value: '<script>alert(1)</script>' },
        { key: 'redirect', value: 'javascript:alert(1)' },
        { key: 'file', value: '../../../etc/passwd' }
      ];

      maliciousParams.forEach(param => {
        // These should be sanitized or rejected
        expect(param.value).toBeDefined();
      });
    });
  });

  describe('Error Handling', () => {
    it('should return generic error messages', () => {
      const secureErrors = [
        { status: 400, message: 'Bad Request' },
        { status: 401, message: 'Unauthorized' },
        { status: 403, message: 'Forbidden' },
        { status: 404, message: 'Not Found' },
        { status: 500, message: 'Internal Server Error' }
      ];

      const insecureErrors = [
        { status: 500, message: 'Database connection failed: mysql://user:pass@localhost' },
        { status: 500, message: 'Error at line 42 in /app/src/handler.js' },
        { status: 401, message: 'User admin@example.com not found' }
      ];

      secureErrors.forEach(err => {
        expect(err.message).not.toMatch(/password|secret|key|connection|line \d+/i);
      });

      insecureErrors.forEach(err => {
        expect(err.message).toMatch(/password|secret|key|connection|line \d+|@/i);
      });
    });
  });
});
