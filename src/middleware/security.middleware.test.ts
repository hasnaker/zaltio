/**
 * Security Headers Middleware Tests
 * Task 6.5: Security Headers
 * 
 * Tests:
 * - HSTS header
 * - X-Content-Type-Options
 * - X-Frame-Options
 * - Content-Security-Policy
 * - X-XSS-Protection
 * - CORS headers
 * - Header validation
 */

import * as fc from 'fast-check';
import {
  SecurityHeadersConfig,
  DEFAULT_SECURITY_CONFIG,
  buildHSTSHeader,
  buildCSPHeader,
  buildPermissionsPolicyHeader,
  buildXSSProtectionHeader,
  generateSecurityHeaders,
  generateCORSHeaders,
  applySecurityHeaders,
  createSecureResponse,
  createSecureErrorResponse,
  validateSecurityHeaders,
  isOriginInAllowedList,
  API_SECURITY_HEADERS
} from './security.middleware';

describe('Security Headers Middleware - Unit Tests', () => {
  describe('DEFAULT_SECURITY_CONFIG', () => {
    it('should have HSTS max-age of at least 1 year', () => {
      expect(DEFAULT_SECURITY_CONFIG.hstsMaxAge).toBeGreaterThanOrEqual(31536000);
    });

    it('should include subdomains in HSTS', () => {
      expect(DEFAULT_SECURITY_CONFIG.hstsIncludeSubDomains).toBe(true);
    });

    it('should enable HSTS preload', () => {
      expect(DEFAULT_SECURITY_CONFIG.hstsPreload).toBe(true);
    });

    it('should deny framing', () => {
      expect(DEFAULT_SECURITY_CONFIG.frameOptions).toBe('DENY');
    });

    it('should enable content type nosniff', () => {
      expect(DEFAULT_SECURITY_CONFIG.contentTypeNosniff).toBe(true);
    });

    it('should enable XSS protection in block mode', () => {
      expect(DEFAULT_SECURITY_CONFIG.xssProtection).toBe(true);
      expect(DEFAULT_SECURITY_CONFIG.xssProtectionMode).toBe('block');
    });

    it('should enable CSP', () => {
      expect(DEFAULT_SECURITY_CONFIG.cspEnabled).toBe(true);
    });

    it('should have strict referrer policy', () => {
      expect(DEFAULT_SECURITY_CONFIG.referrerPolicy).toBe('strict-origin-when-cross-origin');
    });
  });

  describe('buildHSTSHeader', () => {
    it('should build basic HSTS header', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        hstsMaxAge: 31536000,
        hstsIncludeSubDomains: false,
        hstsPreload: false
      };

      const header = buildHSTSHeader(config);
      expect(header).toBe('max-age=31536000');
    });

    it('should include subdomains when enabled', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        hstsMaxAge: 31536000,
        hstsIncludeSubDomains: true,
        hstsPreload: false
      };

      const header = buildHSTSHeader(config);
      expect(header).toContain('includeSubDomains');
    });

    it('should include preload when enabled', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        hstsMaxAge: 31536000,
        hstsIncludeSubDomains: true,
        hstsPreload: true
      };

      const header = buildHSTSHeader(config);
      expect(header).toContain('preload');
    });

    it('should build full HSTS header with all options', () => {
      const header = buildHSTSHeader(DEFAULT_SECURITY_CONFIG);
      expect(header).toBe('max-age=31536000; includeSubDomains; preload');
    });
  });

  describe('buildCSPHeader', () => {
    it('should build CSP header from directives', () => {
      const directives = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"]
      };

      const header = buildCSPHeader(directives);
      expect(header).toContain("default-src 'self'");
      expect(header).toContain("script-src 'self' 'unsafe-inline'");
    });

    it('should separate directives with semicolons', () => {
      const directives = {
        'default-src': ["'self'"],
        'img-src': ['https:']
      };

      const header = buildCSPHeader(directives);
      expect(header).toContain('; ');
    });
  });

  describe('buildPermissionsPolicyHeader', () => {
    it('should build permissions policy header', () => {
      const policies = {
        'camera': [],
        'microphone': []
      };

      const header = buildPermissionsPolicyHeader(policies);
      expect(header).toContain('camera=()');
      expect(header).toContain('microphone=()');
    });

    it('should handle allowlist values', () => {
      const policies = {
        'geolocation': ['self']
      };

      const header = buildPermissionsPolicyHeader(policies);
      expect(header).toContain('geolocation=(self)');
    });
  });

  describe('buildXSSProtectionHeader', () => {
    it('should return 0 when disabled', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        xssProtection: false
      };

      const header = buildXSSProtectionHeader(config);
      expect(header).toBe('0');
    });

    it('should return 1; mode=block when enabled with block mode', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        xssProtection: true,
        xssProtectionMode: 'block'
      };

      const header = buildXSSProtectionHeader(config);
      expect(header).toBe('1; mode=block');
    });

    it('should return 1 when enabled without block mode', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        xssProtection: true,
        xssProtectionMode: '1'
      };

      const header = buildXSSProtectionHeader(config);
      expect(header).toBe('1');
    });
  });

  describe('generateSecurityHeaders', () => {
    it('should generate all required security headers', () => {
      const headers = generateSecurityHeaders();

      expect(headers['Strict-Transport-Security']).toBeDefined();
      expect(headers['X-Content-Type-Options']).toBe('nosniff');
      expect(headers['X-Frame-Options']).toBe('DENY');
      expect(headers['X-XSS-Protection']).toBeDefined();
      expect(headers['Content-Security-Policy']).toBeDefined();
      expect(headers['Referrer-Policy']).toBeDefined();
      expect(headers['Permissions-Policy']).toBeDefined();
    });

    it('should include additional security headers', () => {
      const headers = generateSecurityHeaders();

      expect(headers['X-DNS-Prefetch-Control']).toBe('off');
      expect(headers['X-Download-Options']).toBe('noopen');
      expect(headers['X-Permitted-Cross-Domain-Policies']).toBe('none');
    });
  });

  describe('generateCORSHeaders', () => {
    it('should generate CORS headers for allowed origin', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        corsEnabled: true,
        corsOrigins: ['https://example.com']
      };

      const headers = generateCORSHeaders('https://example.com', config);

      expect(headers['Access-Control-Allow-Origin']).toBe('https://example.com');
      expect(headers['Access-Control-Allow-Methods']).toBeDefined();
      expect(headers['Access-Control-Allow-Headers']).toBeDefined();
    });

    it('should return wildcard for * origin', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        corsEnabled: true,
        corsOrigins: ['*']
      };

      const headers = generateCORSHeaders('https://any-origin.com', config);

      expect(headers['Access-Control-Allow-Origin']).toBe('*');
    });

    it('should return empty headers when CORS disabled', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        corsEnabled: false
      };

      const headers = generateCORSHeaders('https://example.com', config);

      expect(Object.keys(headers).length).toBe(0);
    });

    it('should not return headers for disallowed origin', () => {
      const config: SecurityHeadersConfig = {
        ...DEFAULT_SECURITY_CONFIG,
        corsEnabled: true,
        corsOrigins: ['https://allowed.com']
      };

      const headers = generateCORSHeaders('https://disallowed.com', config);

      expect(headers['Access-Control-Allow-Origin']).toBeFalsy();
    });
  });

  describe('applySecurityHeaders', () => {
    it('should apply security headers to response', () => {
      const response = {
        statusCode: 200,
        body: JSON.stringify({ success: true })
      };

      const securedResponse = applySecurityHeaders(response);

      expect(securedResponse.headers?.['Strict-Transport-Security']).toBeDefined();
      expect(securedResponse.headers?.['X-Frame-Options']).toBe('DENY');
    });

    it('should preserve existing headers', () => {
      const response = {
        statusCode: 200,
        headers: { 'X-Custom-Header': 'value' },
        body: JSON.stringify({ success: true })
      };

      const securedResponse = applySecurityHeaders(response);

      expect(securedResponse.headers?.['X-Custom-Header']).toBe('value');
    });
  });

  describe('createSecureResponse', () => {
    it('should create response with security headers', () => {
      const response = createSecureResponse(200, { success: true });

      expect(response.statusCode).toBe(200);
      expect(response.headers?.['Content-Type']).toBe('application/json');
      expect(response.headers?.['Strict-Transport-Security']).toBeDefined();
    });

    it('should stringify body if object', () => {
      const response = createSecureResponse(200, { data: 'test' });

      expect(typeof response.body).toBe('string');
      expect(JSON.parse(response.body)).toEqual({ data: 'test' });
    });
  });

  describe('createSecureErrorResponse', () => {
    it('should create error response with security headers', () => {
      const response = createSecureErrorResponse(400, 'BAD_REQUEST', 'Invalid input');

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('BAD_REQUEST');
      expect(body.error.message).toBe('Invalid input');
      expect(body.error.timestamp).toBeDefined();
    });
  });

  describe('validateSecurityHeaders', () => {
    it('should validate complete headers', () => {
      const headers = generateSecurityHeaders();
      const result = validateSecurityHeaders(headers);

      expect(result.valid).toBe(true);
      expect(result.missing.length).toBe(0);
    });

    it('should detect missing required headers', () => {
      const headers = {
        'Content-Type': 'application/json'
      };

      const result = validateSecurityHeaders(headers);

      expect(result.valid).toBe(false);
      expect(result.missing).toContain('Strict-Transport-Security');
      expect(result.missing).toContain('X-Frame-Options');
    });

    it('should warn about short HSTS max-age', () => {
      const headers = {
        ...generateSecurityHeaders(),
        'Strict-Transport-Security': 'max-age=3600'
      };

      const result = validateSecurityHeaders(headers);

      expect(result.warnings.some(w => w.includes('HSTS'))).toBe(true);
    });
  });

  describe('isOriginInAllowedList', () => {
    it('should return true for wildcard', () => {
      expect(isOriginInAllowedList('https://any.com', ['*'])).toBe(true);
    });

    it('should return true for exact match', () => {
      expect(isOriginInAllowedList('https://example.com', ['https://example.com'])).toBe(true);
    });

    it('should return false for non-matching origin', () => {
      expect(isOriginInAllowedList('https://other.com', ['https://example.com'])).toBe(false);
    });

    it('should return false for undefined origin', () => {
      expect(isOriginInAllowedList(undefined, ['https://example.com'])).toBe(false);
    });
  });

  describe('API_SECURITY_HEADERS', () => {
    it('should be pre-generated headers', () => {
      expect(API_SECURITY_HEADERS['Strict-Transport-Security']).toBeDefined();
      expect(API_SECURITY_HEADERS['X-Frame-Options']).toBe('DENY');
    });
  });

  describe('Property-based tests', () => {
    describe('HSTS header', () => {
      it('should always include max-age', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 0, max: 100000000 }),
            fc.boolean(),
            fc.boolean(),
            (maxAge, includeSubDomains, preload) => {
              const config: SecurityHeadersConfig = {
                ...DEFAULT_SECURITY_CONFIG,
                hstsMaxAge: maxAge,
                hstsIncludeSubDomains: includeSubDomains,
                hstsPreload: preload
              };

              const header = buildHSTSHeader(config);
              expect(header).toContain(`max-age=${maxAge}`);

              return true;
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('Security headers completeness', () => {
      it('should always generate required headers', () => {
        fc.assert(
          fc.property(fc.constant(null), () => {
            const headers = generateSecurityHeaders();
            const validation = validateSecurityHeaders(headers);

            expect(validation.valid).toBe(true);
            expect(validation.missing.length).toBe(0);

            return true;
          }),
          { numRuns: 10 }
        );
      });
    });
  });
});
