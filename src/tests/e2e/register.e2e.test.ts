/**
 * User Registration E2E Tests
 * 
 * Task 1.3: User Registration Handler
 * Validates: Requirements 1.1, 9.2
 * 
 * @e2e-test
 * @phase Phase 1
 * @security-critical
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from '../../handlers/register-handler';

// Mock dependencies
jest.mock('../../repositories/user.repository', () => ({
  createUser: jest.fn().mockImplementation((input) => ({
    id: 'user-' + Date.now(),
    realm_id: input.realm_id,
    email: input.email,
    email_verified: false,
    created_at: new Date().toISOString()
  })),
  findUserByEmail: jest.fn().mockResolvedValue(null)
}));

jest.mock('../../repositories/realm.repository', () => ({
  findRealmById: jest.fn().mockResolvedValue({
    id: 'clinisyn-psychologists',
    name: 'Clinisyn Psychologists',
    status: 'active'
  }),
  getRealmSettings: jest.fn().mockResolvedValue({
    password_policy: {
      min_length: 12,
      require_uppercase: true,
      require_lowercase: true,
      require_numbers: true,
      require_special: true
    }
  })
}));

jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({
    allowed: true,
    remaining: 2,
    resetAt: Math.floor(Date.now() / 1000) + 3600
  })
}));

jest.mock('../../utils/password', () => ({
  checkPasswordPwned: jest.fn().mockResolvedValue(0),
  validatePasswordPolicy: jest.fn().mockReturnValue({ valid: true, errors: [] })
}));

jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

import { findUserByEmail } from '../../repositories/user.repository';
import { findRealmById } from '../../repositories/realm.repository';
import { checkRateLimit } from '../../services/ratelimit.service';
import { checkPasswordPwned, validatePasswordPolicy } from '../../utils/password';

function createMockEvent(body: object, ip: string = '192.168.1.1'): APIGatewayProxyEvent {
  return {
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Test-Agent/1.0'
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/register',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: ip
      }
    } as any,
    resource: '/v1/auth/register',
    multiValueHeaders: {}
  };
}

describe('User Registration E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Successful Registration', () => {
    it('should register a new user with valid credentials', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!',
        profile: {
          first_name: 'Ayşe',
          last_name: 'Yılmaz'
        }
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(201);
      expect(body.message).toContain('registered successfully');
      expect(body.user.email).toBe('dr.ayse@example.com');
      expect(body.user.email_verified).toBe(false);
    });

    it('should include rate limit headers in response', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.mehmet@example.com',
        password: 'SecurePass!123'
      });

      const response = await handler(event);

      expect(response.headers).toHaveProperty('X-RateLimit-Remaining');
      expect(response.headers).toHaveProperty('X-RateLimit-Reset');
    });
  });

  describe('Email Validation', () => {
    it('should reject invalid email format', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'invalid-email',
        password: 'SecurePass!123'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_EMAIL');
    });

    it('should reject empty email', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: '',
        password: 'SecurePass!123'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(400);
    });
  });

  describe('Password Validation', () => {
    it('should reject weak password (too short)', async () => {
      (validatePasswordPolicy as jest.Mock).mockReturnValueOnce({
        valid: false,
        errors: ['Password must be at least 12 characters long']
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'test@example.com',
        password: 'Short!1'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });

    it('should reject password found in HaveIBeenPwned', async () => {
      (checkPasswordPwned as jest.Mock).mockResolvedValueOnce(1000000);

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'test@example.com',
        password: 'password123!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('PASSWORD_COMPROMISED');
      expect(body.details.breach_count).toBe(1000000);
      expect(body.details.recommendation).toBe('Use a unique password with at least 12 characters');
      expect(body.error.timestamp).toBeDefined();
    });
  });

  describe('Duplicate User Prevention', () => {
    it('should reject registration with existing email', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValueOnce({
        id: 'existing-user-id',
        email: 'existing@example.com'
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'existing@example.com',
        password: 'SecurePass!123'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(409);
      expect(body.error.code).toBe('USER_EXISTS');
    });
  });

  describe('Rate Limiting', () => {
    it('should reject when rate limit exceeded', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValueOnce({
        allowed: false,
        remaining: 0,
        resetAt: Math.floor(Date.now() / 1000) + 3600,
        retryAfter: 3600
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'test@example.com',
        password: 'SecurePass!123'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(body.error.details.retry_after).toBe(3600);
    });

    it('should use IP-based rate limiting', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'test@example.com',
        password: 'SecurePass!123'
      }, '10.0.0.1');

      await handler(event);

      expect(checkRateLimit).toHaveBeenCalledWith(
        'global',
        'register:10.0.0.1',
        expect.objectContaining({
          maxRequests: 3,
          windowSeconds: 3600
        })
      );
    });
  });

  describe('Realm Validation', () => {
    it('should reject invalid realm_id format', async () => {
      const event = createMockEvent({
        realm_id: '',
        email: 'test@example.com',
        password: 'SecurePass!123'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REALM');
    });

    it('should reject non-existent realm', async () => {
      (findRealmById as jest.Mock).mockResolvedValueOnce(null);

      const event = createMockEvent({
        realm_id: 'non-existent-realm',
        email: 'test@example.com',
        password: 'SecurePass!123'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('REALM_NOT_FOUND');
    });
  });

  describe('Request Validation', () => {
    it('should reject empty request body', async () => {
      const event = {
        ...createMockEvent({}),
        body: null
      };

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject invalid JSON', async () => {
      const event = {
        ...createMockEvent({}),
        body: 'invalid json {'
      };

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in response', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'test@example.com',
        password: 'SecurePass!123'
      });

      const response = await handler(event);

      expect(response.headers).toHaveProperty('X-Content-Type-Options', 'nosniff');
      expect(response.headers).toHaveProperty('X-Frame-Options', 'DENY');
    });
  });

  describe('Audit Logging', () => {
    it('should log successful registration', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'test@example.com',
        password: 'SecurePass!123'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'user_registered'
        })
      );
    });

    it('should log pwned password rejection', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');
      (checkPasswordPwned as jest.Mock).mockResolvedValueOnce(5000);

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'test@example.com',
        password: 'compromised123!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'pwned_password_rejected'
        })
      );
    });
  });
});
