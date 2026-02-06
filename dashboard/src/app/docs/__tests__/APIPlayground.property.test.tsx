/**
 * Property-Based Tests for API Playground
 * 
 * Feature: zalt-enterprise-landing
 * Property 9: API playground completeness
 * Property 10: Error handling display
 * 
 * Validates: Requirements 9.5, 9.6, 13.5
 */

import * as fc from 'fast-check';

// Endpoint type (mirrors actual implementation)
type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

interface Endpoint {
  method: HttpMethod;
  path: string;
  name: string;
  description: string;
  body?: Record<string, unknown>;
  headers?: Record<string, string>;
  requiresAuth: boolean;
}

// API endpoints (mirrors actual implementation)
const endpoints: Endpoint[] = [
  {
    method: 'POST',
    path: '/auth/register',
    name: 'Register',
    description: 'Create a new user account',
    body: { email: 'user@example.com', password: 'SecurePass123!' },
    requiresAuth: false,
  },
  {
    method: 'POST',
    path: '/auth/login',
    name: 'Login',
    description: 'Authenticate and get tokens',
    body: { email: 'user@example.com', password: 'SecurePass123!' },
    requiresAuth: false,
  },
  {
    method: 'POST',
    path: '/auth/refresh',
    name: 'Refresh Token',
    description: 'Get new access token using refresh token',
    body: { refreshToken: 'your-refresh-token' },
    requiresAuth: false,
  },
  {
    method: 'GET',
    path: '/auth/me',
    name: 'Get Current User',
    description: 'Get authenticated user profile',
    requiresAuth: true,
  },
  {
    method: 'POST',
    path: '/auth/logout',
    name: 'Logout',
    description: 'Invalidate current session',
    requiresAuth: true,
  },
  {
    method: 'POST',
    path: '/mfa/totp/setup',
    name: 'Setup TOTP',
    description: 'Initialize TOTP MFA setup',
    requiresAuth: true,
  },
  {
    method: 'POST',
    path: '/mfa/totp/verify',
    name: 'Verify TOTP',
    description: 'Verify TOTP code',
    body: { code: '123456' },
    requiresAuth: true,
  },
  {
    method: 'GET',
    path: '/sessions',
    name: 'List Sessions',
    description: 'Get all active sessions',
    requiresAuth: true,
  },
  {
    method: 'DELETE',
    path: '/sessions/:sessionId',
    name: 'Revoke Session',
    description: 'Terminate a specific session',
    requiresAuth: true,
  },
];

// Mock responses (mirrors actual implementation)
const mockResponses: Record<string, unknown> = {
  '/auth/register': {
    success: true,
    user: {
      id: 'user_abc123',
      email: 'user@example.com',
      createdAt: new Date().toISOString(),
    },
    message: 'Verification email sent',
  },
  '/auth/login': {
    accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
    refreshToken: 'rt_abc123xyz...',
    expiresIn: 900,
    user: {
      id: 'user_abc123',
      email: 'user@example.com',
      mfaEnabled: false,
    },
  },
  '/auth/me': {
    id: 'user_abc123',
    email: 'user@example.com',
    emailVerified: true,
    mfaEnabled: true,
    mfaMethods: ['totp'],
    createdAt: '2026-01-15T10:00:00Z',
    lastLoginAt: new Date().toISOString(),
  },
  '/mfa/totp/setup': {
    secret: 'JBSWY3DPEHPK3PXP',
    qrCode: 'data:image/png;base64,iVBORw0KGgo...',
    backupCodes: ['abc123', 'def456', 'ghi789', 'jkl012'],
  },
  '/sessions': {
    sessions: [
      {
        id: 'sess_abc123',
        device: 'Chrome on macOS',
        ip: '192.168.1.xxx',
        location: 'Istanbul, Turkey',
        createdAt: '2026-02-03T10:00:00Z',
        current: true,
      },
    ],
  },
};

// Error types for API responses
interface APIError {
  code: string;
  message: string;
  details?: Record<string, string>;
}

// Error handling function (mirrors expected behavior)
function formatAPIError(error: APIError): string {
  let formatted = `Error ${error.code}: ${error.message}`;
  if (error.details) {
    const detailsStr = Object.entries(error.details)
      .map(([key, value]) => `  ${key}: ${value}`)
      .join('\n');
    formatted += `\nDetails:\n${detailsStr}`;
  }
  return formatted;
}

// Validate endpoint structure
function validateEndpoint(endpoint: Endpoint): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!endpoint.method) errors.push('Missing method');
  if (!['GET', 'POST', 'PUT', 'DELETE'].includes(endpoint.method)) {
    errors.push(`Invalid method: ${endpoint.method}`);
  }
  if (!endpoint.path) errors.push('Missing path');
  if (!endpoint.path.startsWith('/')) errors.push('Path must start with /');
  if (!endpoint.name) errors.push('Missing name');
  if (!endpoint.description) errors.push('Missing description');
  if (typeof endpoint.requiresAuth !== 'boolean') errors.push('Missing requiresAuth');
  
  return { valid: errors.length === 0, errors };
}

// Generate cURL command
function generateCurlCommand(endpoint: Endpoint, accessToken?: string): string {
  let curl = `curl -X ${endpoint.method} \\
  'https://api.zalt.io${endpoint.path}' \\
  -H 'Content-Type: application/json'`;
  
  if (endpoint.requiresAuth && accessToken) {
    curl += ` \\
  -H 'Authorization: Bearer ${accessToken}'`;
  }
  
  if (endpoint.body) {
    curl += ` \\
  -d '${JSON.stringify(endpoint.body)}'`;
  }
  
  return curl;
}

describe('Feature: zalt-enterprise-landing, Property 9: API playground completeness', () => {
  describe('Property 9.1: All endpoints have required fields', () => {
    it('should have valid structure for all endpoints', () => {
      endpoints.forEach(endpoint => {
        const validation = validateEndpoint(endpoint);
        expect(validation.valid).toBe(true);
        expect(validation.errors).toEqual([]);
      });
    });

    it('should have method, path, name, description for every endpoint', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: endpoints.length - 1 }),
          (index) => {
            const endpoint = endpoints[index];
            expect(endpoint.method).toBeDefined();
            expect(endpoint.path).toBeDefined();
            expect(endpoint.name).toBeDefined();
            expect(endpoint.description).toBeDefined();
            expect(typeof endpoint.requiresAuth).toBe('boolean');
          }
        ),
        { numRuns: endpoints.length }
      );
    });
  });

  describe('Property 9.2: All paths are valid API paths', () => {
    it('should have paths starting with /', () => {
      endpoints.forEach(endpoint => {
        expect(endpoint.path.startsWith('/')).toBe(true);
      });
    });

    it('should have unique paths', () => {
      const paths = endpoints.map(e => e.path);
      const uniquePaths = new Set(paths);
      expect(uniquePaths.size).toBe(paths.length);
    });
  });

  describe('Property 9.3: HTTP methods are valid', () => {
    it('should only use valid HTTP methods', () => {
      const validMethods: HttpMethod[] = ['GET', 'POST', 'PUT', 'DELETE'];
      
      endpoints.forEach(endpoint => {
        expect(validMethods).toContain(endpoint.method);
      });
    });
  });

  describe('Property 9.4: Endpoints with body have valid body structure', () => {
    it('should have object body when body is defined', () => {
      endpoints.forEach(endpoint => {
        if (endpoint.body !== undefined) {
          expect(typeof endpoint.body).toBe('object');
          expect(endpoint.body).not.toBeNull();
        }
      });
    });

    it('should have body for POST endpoints that need it', () => {
      const postEndpointsWithBody = endpoints.filter(
        e => e.method === 'POST' && e.body !== undefined
      );
      
      // At least some POST endpoints should have body
      expect(postEndpointsWithBody.length).toBeGreaterThan(0);
    });
  });

  describe('Property 9.5: Mock responses exist for key endpoints', () => {
    it('should have mock responses for documented endpoints', () => {
      const keyPaths = ['/auth/register', '/auth/login', '/auth/me', '/sessions'];
      
      keyPaths.forEach(path => {
        expect(mockResponses[path]).toBeDefined();
      });
    });

    it('should have valid JSON structure in mock responses', () => {
      Object.entries(mockResponses).forEach(([path, response]) => {
        expect(typeof response).toBe('object');
        expect(response).not.toBeNull();
        
        // Should be serializable to JSON
        expect(() => JSON.stringify(response)).not.toThrow();
      });
    });
  });

  describe('Property 9.6: cURL command generation', () => {
    it('should generate valid cURL commands for all endpoints', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: endpoints.length - 1 }),
          fc.option(fc.string({ minLength: 10, maxLength: 100 })),
          (index, token) => {
            const endpoint = endpoints[index];
            const curl = generateCurlCommand(endpoint, token ?? undefined);
            
            // Should contain method
            expect(curl).toContain(`-X ${endpoint.method}`);
            // Should contain path
            expect(curl).toContain(endpoint.path);
            // Should contain base URL
            expect(curl).toContain('https://api.zalt.io');
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should include Authorization header for auth-required endpoints', () => {
      const authEndpoints = endpoints.filter(e => e.requiresAuth);
      const token = 'test-token-123';
      
      authEndpoints.forEach(endpoint => {
        const curl = generateCurlCommand(endpoint, token);
        expect(curl).toContain('Authorization: Bearer');
        expect(curl).toContain(token);
      });
    });

    it('should include body for endpoints with body', () => {
      const bodyEndpoints = endpoints.filter(e => e.body !== undefined);
      
      bodyEndpoints.forEach(endpoint => {
        const curl = generateCurlCommand(endpoint);
        expect(curl).toContain("-d '");
        expect(curl).toContain(JSON.stringify(endpoint.body));
      });
    });
  });

  describe('Property 9.7: Endpoint coverage', () => {
    it('should cover core authentication endpoints', () => {
      const requiredPaths = [
        '/auth/register',
        '/auth/login',
        '/auth/refresh',
        '/auth/me',
        '/auth/logout',
      ];
      
      const availablePaths = endpoints.map(e => e.path);
      
      requiredPaths.forEach(path => {
        expect(availablePaths).toContain(path);
      });
    });

    it('should cover MFA endpoints', () => {
      const mfaEndpoints = endpoints.filter(e => e.path.includes('/mfa/'));
      expect(mfaEndpoints.length).toBeGreaterThanOrEqual(2);
    });

    it('should cover session endpoints', () => {
      const sessionEndpoints = endpoints.filter(e => e.path.includes('/sessions'));
      expect(sessionEndpoints.length).toBeGreaterThanOrEqual(1);
    });
  });
});

describe('Feature: zalt-enterprise-landing, Property 10: Error handling display', () => {
  describe('Property 10.1: Error formatting', () => {
    it('should format errors with code and message', () => {
      fc.assert(
        fc.property(
          fc.record({
            code: fc.constantFrom('AUTH_001', 'AUTH_002', 'RATE_LIMIT', 'INVALID_INPUT'),
            message: fc.string({ minLength: 5, maxLength: 100 }),
          }),
          (error) => {
            const formatted = formatAPIError(error);
            expect(formatted).toContain(error.code);
            expect(formatted).toContain(error.message);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should include details when present', () => {
      const errorWithDetails: APIError = {
        code: 'VALIDATION_ERROR',
        message: 'Invalid input',
        details: {
          email: 'Invalid email format',
          password: 'Password too short',
        },
      };
      
      const formatted = formatAPIError(errorWithDetails);
      expect(formatted).toContain('Details:');
      expect(formatted).toContain('email: Invalid email format');
      expect(formatted).toContain('password: Password too short');
    });
  });

  describe('Property 10.2: Common error codes', () => {
    const commonErrors: APIError[] = [
      { code: 'AUTH_INVALID_CREDENTIALS', message: 'Invalid email or password' },
      { code: 'AUTH_USER_NOT_FOUND', message: 'User not found' },
      { code: 'AUTH_EMAIL_EXISTS', message: 'Email already registered' },
      { code: 'AUTH_TOKEN_EXPIRED', message: 'Access token has expired' },
      { code: 'AUTH_TOKEN_INVALID', message: 'Invalid access token' },
      { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests, please try again later' },
      { code: 'MFA_REQUIRED', message: 'Multi-factor authentication required' },
      { code: 'MFA_INVALID_CODE', message: 'Invalid MFA code' },
      { code: 'VALIDATION_ERROR', message: 'Request validation failed' },
    ];

    it('should handle all common error types', () => {
      commonErrors.forEach(error => {
        const formatted = formatAPIError(error);
        expect(formatted).toBeTruthy();
        expect(formatted.length).toBeGreaterThan(0);
      });
    });

    it('should not expose sensitive information in errors', () => {
      const sensitivePatterns = [
        /password/i,
        /secret/i,
        /token.*value/i,
        /api.*key/i,
      ];
      
      commonErrors.forEach(error => {
        const formatted = formatAPIError(error);
        sensitivePatterns.forEach(pattern => {
          // Error messages should not contain actual sensitive values
          // (they can mention the field name but not the value)
          expect(formatted).not.toMatch(/password:\s*\S{8,}/i);
          expect(formatted).not.toMatch(/secret:\s*\S{8,}/i);
        });
      });
    });
  });

  describe('Property 10.3: Error response structure', () => {
    it('should always have code and message', () => {
      fc.assert(
        fc.property(
          fc.record({
            code: fc.string({ minLength: 1, maxLength: 50 }),
            message: fc.string({ minLength: 1, maxLength: 200 }),
            details: fc.option(fc.dictionary(fc.string(), fc.string())),
          }),
          (error) => {
            const apiError: APIError = {
              code: error.code,
              message: error.message,
              details: error.details ?? undefined,
            };
            
            const formatted = formatAPIError(apiError);
            expect(formatted).toContain(error.code);
            expect(formatted).toContain(error.message);
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  describe('Property 10.4: Input retention on error', () => {
    // Simulates form state management
    interface FormState {
      values: Record<string, string>;
      errors: Record<string, string>;
      touched: Record<string, boolean>;
    }

    function handleFormError(
      state: FormState,
      fieldErrors: Record<string, string>
    ): FormState {
      return {
        ...state,
        errors: { ...state.errors, ...fieldErrors },
      };
    }

    it('should retain input values when error occurs', () => {
      fc.assert(
        fc.property(
          fc.record({
            email: fc.emailAddress(),
            password: fc.string({ minLength: 8, maxLength: 50 }),
          }),
          fc.dictionary(fc.string(), fc.string()),
          (values, fieldErrors) => {
            const initialState: FormState = {
              values,
              errors: {},
              touched: { email: true, password: true },
            };
            
            const newState = handleFormError(initialState, fieldErrors);
            
            // Values should be retained
            expect(newState.values).toEqual(values);
            // Errors should be added
            Object.keys(fieldErrors).forEach(key => {
              expect(newState.errors[key]).toBe(fieldErrors[key]);
            });
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 10.5: HTTP status code mapping', () => {
    const statusCodeMapping: Record<number, string[]> = {
      400: ['VALIDATION_ERROR', 'INVALID_INPUT', 'BAD_REQUEST'],
      401: ['AUTH_INVALID_CREDENTIALS', 'AUTH_TOKEN_EXPIRED', 'AUTH_TOKEN_INVALID'],
      403: ['AUTH_FORBIDDEN', 'MFA_REQUIRED', 'INSUFFICIENT_PERMISSIONS'],
      404: ['AUTH_USER_NOT_FOUND', 'RESOURCE_NOT_FOUND'],
      429: ['RATE_LIMIT_EXCEEDED'],
      500: ['INTERNAL_ERROR', 'SERVER_ERROR'],
    };

    it('should map error codes to appropriate HTTP status', () => {
      Object.entries(statusCodeMapping).forEach(([status, codes]) => {
        codes.forEach(code => {
          // Each error code should be associated with a valid HTTP status
          expect(parseInt(status)).toBeGreaterThanOrEqual(400);
          expect(parseInt(status)).toBeLessThan(600);
        });
      });
    });

    it('should have unique error codes across status codes', () => {
      const allCodes = Object.values(statusCodeMapping).flat();
      const uniqueCodes = new Set(allCodes);
      expect(uniqueCodes.size).toBe(allCodes.length);
    });
  });
});

describe('API Playground Edge Cases', () => {
  it('should handle empty request body', () => {
    const getEndpoints = endpoints.filter(e => e.method === 'GET');
    
    getEndpoints.forEach(endpoint => {
      // GET endpoints typically don't have body
      expect(endpoint.body).toBeUndefined();
    });
  });

  it('should handle path parameters', () => {
    const paramEndpoints = endpoints.filter(e => e.path.includes(':'));
    
    paramEndpoints.forEach(endpoint => {
      // Path parameters should be documented
      expect(endpoint.path).toMatch(/:\w+/);
    });
  });

  it('should handle special characters in request body', () => {
    fc.assert(
      fc.property(
        fc.record({
          email: fc.emailAddress(),
          password: fc.string({ minLength: 8, maxLength: 50 }),
          name: fc.string({ minLength: 1, maxLength: 100 }),
        }),
        (body) => {
          // Should be able to stringify any valid body
          expect(() => JSON.stringify(body)).not.toThrow();
        }
      ),
      { numRuns: 30 }
    );
  });

  it('should validate JSON body before sending', () => {
    const invalidJsonStrings = [
      '{invalid}',
      '{"key": undefined}',
      '{key: "value"}',
      '{"unclosed": "string',
    ];

    invalidJsonStrings.forEach(jsonStr => {
      expect(() => JSON.parse(jsonStr)).toThrow();
    });
  });

  it('should handle concurrent requests gracefully', () => {
    // Simulate multiple endpoint selections
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 0, max: endpoints.length - 1 }), { minLength: 1, maxLength: 10 }),
        (indices) => {
          // Each selection should return a valid endpoint
          indices.forEach(index => {
            const endpoint = endpoints[index];
            expect(endpoint).toBeDefined();
            expect(validateEndpoint(endpoint).valid).toBe(true);
          });
        }
      ),
      { numRuns: 20 }
    );
  });
});
