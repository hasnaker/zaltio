/**
 * Security Headers E2E Tests
 * Task 6.5: Security Headers
 * 
 * Tests:
 * - All responses have security headers
 * - HSTS max-age >= 1 year
 * - CSP correctly configured
 * - Clickjacking protection active
 * - CORS properly configured
 */

import {
  DEFAULT_SECURITY_CONFIG,
  generateSecurityHeaders,
  generateCORSHeaders,
  applySecurityHeaders,
  createSecureResponse,
  createSecureErrorResponse,
  validateSecurityHeaders,
  getRealmSecurityConfig,
  isOriginInAllowedList
} from '../../middleware/security.middleware';

describe('Security Headers E2E Tests', () => {
  describe('All Responses Have Security Headers', () => {
    it('should include HSTS header', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Strict-Transport-Security']).toBeDefined();
    });

    it('should include X-Content-Type-Options header', () => {
      const headers = generateSecurityHeaders();
      expect(headers['X-Content-Type-Options']).toBe('nosniff');
    });

    it('should include X-Frame-Options header', () => {
      const headers = generateSecurityHeaders();
      expect(headers['X-Frame-Options']).toBe('DENY');
    });

    it('should include X-XSS-Protection header', () => {
      const headers = generateSecurityHeaders();
      expect(headers['X-XSS-Protection']).toBeDefined();
    });

    it('should include Content-Security-Policy header', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Content-Security-Policy']).toBeDefined();
    });

    it('should include Referrer-Policy header', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Referrer-Policy']).toBeDefined();
    });

    it('should include Permissions-Policy header', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Permissions-Policy']).toBeDefined();
    });

    it('should include additional security headers', () => {
      const headers = generateSecurityHeaders();
      expect(headers['X-DNS-Prefetch-Control']).toBe('off');
      expect(headers['X-Download-Options']).toBe('noopen');
      expect(headers['X-Permitted-Cross-Domain-Policies']).toBe('none');
    });
  });

  describe('HSTS Configuration', () => {
    it('should have max-age >= 1 year (31536000 seconds)', () => {
      const headers = generateSecurityHeaders();
      const hsts = headers['Strict-Transport-Security'];
      
      const maxAgeMatch = hsts.match(/max-age=(\d+)/);
      expect(maxAgeMatch).not.toBeNull();
      
      const maxAge = parseInt(maxAgeMatch![1], 10);
      expect(maxAge).toBeGreaterThanOrEqual(31536000);
    });

    it('should include includeSubDomains', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Strict-Transport-Security']).toContain('includeSubDomains');
    });

    it('should include preload', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Strict-Transport-Security']).toContain('preload');
    });
  });

  describe('CSP Configuration', () => {
    it('should have default-src directive', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Content-Security-Policy']).toContain('default-src');
    });

    it('should restrict script-src', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Content-Security-Policy']).toContain('script-src');
    });

    it('should prevent framing with frame-ancestors', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Content-Security-Policy']).toContain("frame-ancestors 'none'");
    });

    it('should restrict form-action', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Content-Security-Policy']).toContain('form-action');
    });

    it('should restrict base-uri', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Content-Security-Policy']).toContain('base-uri');
    });

    it('should block object-src', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Content-Security-Policy']).toContain("object-src 'none'");
    });
  });

  describe('Clickjacking Protection', () => {
    it('should set X-Frame-Options to DENY', () => {
      const headers = generateSecurityHeaders();
      expect(headers['X-Frame-Options']).toBe('DENY');
    });

    it('should have frame-ancestors none in CSP', () => {
      const headers = generateSecurityHeaders();
      expect(headers['Content-Security-Policy']).toContain("frame-ancestors 'none'");
    });
  });

  describe('CORS Configuration', () => {
    it('should generate CORS headers for allowed origin', () => {
      const config = {
        ...DEFAULT_SECURITY_CONFIG,
        corsOrigins: ['https://clinisyn.com']
      };

      const headers = generateCORSHeaders('https://clinisyn.com', config);

      expect(headers['Access-Control-Allow-Origin']).toBe('https://clinisyn.com');
    });

    it('should include allowed methods', () => {
      const headers = generateCORSHeaders('https://example.com', DEFAULT_SECURITY_CONFIG);

      expect(headers['Access-Control-Allow-Methods']).toContain('GET');
      expect(headers['Access-Control-Allow-Methods']).toContain('POST');
    });

    it('should include allowed headers', () => {
      const headers = generateCORSHeaders('https://example.com', DEFAULT_SECURITY_CONFIG);

      expect(headers['Access-Control-Allow-Headers']).toContain('Content-Type');
      expect(headers['Access-Control-Allow-Headers']).toContain('Authorization');
    });

    it('should set max-age for preflight caching', () => {
      const headers = generateCORSHeaders('https://example.com', DEFAULT_SECURITY_CONFIG);

      expect(headers['Access-Control-Max-Age']).toBeDefined();
    });

    it('should not allow credentials with wildcard origin', () => {
      const config = {
        ...DEFAULT_SECURITY_CONFIG,
        corsOrigins: ['*']
      };

      const headers = generateCORSHeaders('https://example.com', config);

      expect(headers['Access-Control-Allow-Credentials']).toBeUndefined();
    });

    it('should allow credentials with specific origin', () => {
      const config = {
        ...DEFAULT_SECURITY_CONFIG,
        corsOrigins: ['https://example.com']
      };

      const headers = generateCORSHeaders('https://example.com', config);

      expect(headers['Access-Control-Allow-Credentials']).toBe('true');
    });
  });

  describe('Response Creation', () => {
    it('should create secure success response', () => {
      const response = createSecureResponse(200, { data: 'test' });

      expect(response.statusCode).toBe(200);
      expect(response.headers?.['Strict-Transport-Security']).toBeDefined();
      expect(response.headers?.['X-Frame-Options']).toBe('DENY');
    });

    it('should create secure error response', () => {
      const response = createSecureErrorResponse(400, 'BAD_REQUEST', 'Invalid input');

      expect(response.statusCode).toBe(400);
      expect(response.headers?.['Strict-Transport-Security']).toBeDefined();
      
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('BAD_REQUEST');
    });

    it('should apply headers to existing response', () => {
      const original = {
        statusCode: 200,
        headers: { 'X-Custom': 'value' },
        body: '{}'
      };

      const secured = applySecurityHeaders(original);

      expect(secured.headers?.['X-Custom']).toBe('value');
      expect(secured.headers?.['Strict-Transport-Security']).toBeDefined();
    });
  });

  describe('Header Validation', () => {
    it('should validate complete headers as valid', () => {
      const headers = generateSecurityHeaders();
      const result = validateSecurityHeaders(headers);

      expect(result.valid).toBe(true);
      expect(result.missing.length).toBe(0);
    });

    it('should detect missing required headers', () => {
      const incompleteHeaders = {
        'Content-Type': 'application/json'
      };

      const result = validateSecurityHeaders(incompleteHeaders);

      expect(result.valid).toBe(false);
      expect(result.missing.length).toBeGreaterThan(0);
    });

    it('should warn about weak HSTS configuration', () => {
      const weakHeaders = {
        ...generateSecurityHeaders(),
        'Strict-Transport-Security': 'max-age=3600' // Only 1 hour
      };

      const result = validateSecurityHeaders(weakHeaders);

      expect(result.warnings.some(w => w.includes('HSTS'))).toBe(true);
    });
  });

  describe('Realm-Specific Configuration', () => {
    it('should use realm-specific CORS origins', () => {
      const realmConfig = getRealmSecurityConfig('clinisyn-psychologists', {
        cors_origins: ['https://clinisyn.com', 'https://app.clinisyn.com']
      });

      expect(realmConfig.corsOrigins).toContain('https://clinisyn.com');
      expect(realmConfig.corsOrigins).toContain('https://app.clinisyn.com');
    });

    it('should use default config when no realm settings', () => {
      const realmConfig = getRealmSecurityConfig('test-realm');

      expect(realmConfig.hstsMaxAge).toBe(DEFAULT_SECURITY_CONFIG.hstsMaxAge);
    });
  });

  describe('Origin Validation', () => {
    it('should allow wildcard origin', () => {
      expect(isOriginInAllowedList('https://any.com', ['*'])).toBe(true);
    });

    it('should allow exact match', () => {
      expect(isOriginInAllowedList('https://clinisyn.com', ['https://clinisyn.com'])).toBe(true);
    });

    it('should reject non-matching origin', () => {
      expect(isOriginInAllowedList('https://evil.com', ['https://clinisyn.com'])).toBe(false);
    });

    it('should reject undefined origin', () => {
      expect(isOriginInAllowedList(undefined, ['https://clinisyn.com'])).toBe(false);
    });
  });

  describe('Security Scenarios', () => {
    it('should protect against clickjacking', () => {
      const headers = generateSecurityHeaders();

      // Both X-Frame-Options and CSP frame-ancestors should be set
      expect(headers['X-Frame-Options']).toBe('DENY');
      expect(headers['Content-Security-Policy']).toContain("frame-ancestors 'none'");
    });

    it('should protect against MIME type sniffing', () => {
      const headers = generateSecurityHeaders();

      expect(headers['X-Content-Type-Options']).toBe('nosniff');
    });

    it('should enforce HTTPS via HSTS', () => {
      const headers = generateSecurityHeaders();
      const hsts = headers['Strict-Transport-Security'];

      expect(hsts).toContain('max-age=');
      expect(hsts).toContain('includeSubDomains');
    });

    it('should restrict dangerous features via Permissions-Policy', () => {
      const headers = generateSecurityHeaders();
      const permissions = headers['Permissions-Policy'];

      expect(permissions).toContain('camera=()');
      expect(permissions).toContain('microphone=()');
      expect(permissions).toContain('geolocation=()');
    });

    it('should have strict referrer policy', () => {
      const headers = generateSecurityHeaders();

      expect(headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin');
    });
  });

  describe('Healthcare Compliance', () => {
    it('should meet HIPAA security requirements', () => {
      const headers = generateSecurityHeaders();
      const validation = validateSecurityHeaders(headers);

      // All required headers must be present
      expect(validation.valid).toBe(true);

      // HSTS must be at least 1 year
      const hsts = headers['Strict-Transport-Security'];
      const maxAgeMatch = hsts.match(/max-age=(\d+)/);
      expect(parseInt(maxAgeMatch![1], 10)).toBeGreaterThanOrEqual(31536000);

      // Must prevent framing
      expect(headers['X-Frame-Options']).toBe('DENY');

      // Must have CSP
      expect(headers['Content-Security-Policy']).toBeDefined();
    });

    it('should support Clinisyn CORS requirements', () => {
      const clinsynConfig = getRealmSecurityConfig('clinisyn-psychologists', {
        cors_origins: ['https://clinisyn.com', 'https://app.clinisyn.com']
      });

      const headers = generateCORSHeaders('https://clinisyn.com', clinsynConfig);

      expect(headers['Access-Control-Allow-Origin']).toBe('https://clinisyn.com');
      expect(headers['Access-Control-Allow-Credentials']).toBe('true');
    });
  });
});
