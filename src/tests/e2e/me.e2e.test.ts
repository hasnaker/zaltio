/**
 * Get Current User E2E Tests
 * 
 * Task 1.7: Get Current User Handler
 * Validates: Requirements 2.1, 9.5
 * 
 * @e2e-test
 * @phase Phase 1
 * @security-critical
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies - must be before handler import
jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../../repositories/user.repository', () => ({
  findUserById: jest.fn()
}));

jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

// Import handler AFTER mocks
import { handler } from '../../handlers/me.handler';
import { verifyAccessToken } from '../../utils/jwt';
import { findUserById } from '../../repositories/user.repository';

const mockPayload = {
  sub: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  type: 'access',
  jti: 'token-jti-123'
};

const mockUser = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  email_verified: true,
  password_hash: '$argon2id$v=19$m=32768,t=5,p=2$SENSITIVE_HASH_DATA',
  profile: { 
    first_name: 'Ayşe', 
    last_name: 'Yılmaz',
    avatar_url: 'https://example.com/avatar.jpg'
  },
  status: 'active',
  mfa_enabled: false,
  mfa_secret: 'SENSITIVE_MFA_SECRET',
  failed_login_attempts: 0,
  created_at: '2026-01-01T00:00:00.000Z',
  updated_at: '2026-01-15T00:00:00.000Z'
};

function createMockEvent(
  accessToken: string = 'valid-access-token'
): APIGatewayProxyEvent {
  return {
    body: null,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`
    },
    httpMethod: 'GET',
    isBase64Encoded: false,
    path: '/v1/auth/me',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: '192.168.1.1'
      }
    } as any,
    resource: '/v1/auth/me',
    multiValueHeaders: {}
  };
}

describe('Get Current User E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (verifyAccessToken as jest.Mock).mockResolvedValue(mockPayload);
    (findUserById as jest.Mock).mockResolvedValue(mockUser);
  });

  describe('Successful User Retrieval', () => {
    it('should return current user with valid token', async () => {
      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.user.id).toBe('user-123');
      expect(body.user.email).toBe('dr.ayse@example.com');
      expect(body.user.email_verified).toBe(true);
      expect(body.user.profile.first_name).toBe('Ayşe');
      expect(body.user.profile.last_name).toBe('Yılmaz');
    });

    it('should include all safe user fields', async () => {
      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.user).toHaveProperty('id');
      expect(body.user).toHaveProperty('realm_id');
      expect(body.user).toHaveProperty('email');
      expect(body.user).toHaveProperty('email_verified');
      expect(body.user).toHaveProperty('profile');
      expect(body.user).toHaveProperty('status');
      expect(body.user).toHaveProperty('mfa_enabled');
      expect(body.user).toHaveProperty('created_at');
      expect(body.user).toHaveProperty('updated_at');
    });
  });

  describe('Security - Sensitive Data Protection', () => {
    it('should NEVER return password_hash', async () => {
      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.user.password_hash).toBeUndefined();
      expect(response.body).not.toContain('SENSITIVE_HASH_DATA');
      expect(response.body).not.toContain('argon2id');
    });

    it('should NEVER return mfa_secret', async () => {
      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.user.mfa_secret).toBeUndefined();
      expect(response.body).not.toContain('SENSITIVE_MFA_SECRET');
    });

    it('should not return failed_login_attempts', async () => {
      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.user.failed_login_attempts).toBeUndefined();
    });

    it('should not return locked_until', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        locked_until: '2026-01-15T12:00:00.000Z'
      });

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.user.locked_until).toBeUndefined();
    });
  });

  describe('Authorization Validation', () => {
    it('should reject request without Authorization header', async () => {
      const event = {
        ...createMockEvent(),
        headers: { 'Content-Type': 'application/json' }
      };

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.error.message).toBe('Authorization header with Bearer token is required');
    });

    it('should reject request with invalid Bearer format', async () => {
      const event = {
        ...createMockEvent(),
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': 'Basic dXNlcjpwYXNz'
        }
      };

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject expired access token', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Token expired'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('TOKEN_EXPIRED');
      expect(body.error.message).toBe('Access token has expired');
    });

    it('should reject invalid access token', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid signature'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_TOKEN');
      expect(body.error.message).toBe('Invalid access token');
    });

    it('should reject manipulated token', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('jwt malformed'));

      const event = createMockEvent('manipulated.token.here');

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('User Not Found', () => {
    it('should return 404 if user not found', async () => {
      (findUserById as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('USER_NOT_FOUND');
    });

    it('should log security event when user not found', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');
      (findUserById as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent();

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'user_not_found',
          user_id: 'user-123'
        })
      );
    });
  });

  describe('Suspended Account', () => {
    it('should reject suspended user', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        status: 'suspended'
      });

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(403);
      expect(body.error.code).toBe('ACCOUNT_SUSPENDED');
    });
  });

  describe('Response Headers', () => {
    it('should include security headers', async () => {
      const event = createMockEvent();

      const response = await handler(event);

      expect(response.headers).toHaveProperty('X-Content-Type-Options', 'nosniff');
      expect(response.headers).toHaveProperty('X-Frame-Options', 'DENY');
    });

    it('should include Cache-Control no-store header', async () => {
      const event = createMockEvent();

      const response = await handler(event);

      expect(response.headers).toHaveProperty('Cache-Control', 'no-store, no-cache, must-revalidate');
    });

    it('should include CORS headers', async () => {
      const event = createMockEvent();

      const response = await handler(event);

      expect(response.headers).toHaveProperty('Access-Control-Allow-Origin', '*');
      expect(response.headers).toHaveProperty('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    });
  });

  describe('Error Response Format', () => {
    it('should include timestamp in error response', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.error.timestamp).toBeDefined();
      expect(new Date(body.error.timestamp).getTime()).not.toBeNaN();
    });

    it('should include request_id in error response', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.error.request_id).toBe('test-request-id');
    });
  });

  describe('Internal Error Handling', () => {
    it('should handle database errors gracefully', async () => {
      (findUserById as jest.Mock).mockRejectedValue(new Error('Database connection failed'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(500);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('An unexpected error occurred');
    });
  });

  describe('Case Insensitive Authorization Header', () => {
    it('should accept lowercase authorization header', async () => {
      const event = {
        ...createMockEvent(),
        headers: {
          'Content-Type': 'application/json',
          'authorization': 'Bearer valid-token'
        }
      };

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
    });
  });

  describe('MFA Status', () => {
    it('should return mfa_enabled status', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        mfa_enabled: true
      });

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.user.mfa_enabled).toBe(true);
    });
  });
});
