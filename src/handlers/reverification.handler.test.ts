/**
 * Reverification Handler Tests
 * Task 4.2: Implement Reverification Handler (Lambda)
 * 
 * Tests:
 * - POST /reverify/password - Verify with password
 * - POST /reverify/mfa - Verify with MFA
 * - POST /reverify/webauthn - Verify with WebAuthn
 * - GET /reverify/status - Check reverification status
 * 
 * Validates: Requirements 3.4, 3.6
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from './reverification.handler';
import { reverificationService, ReverificationError } from '../services/reverification.service';
import * as rateLimitService from '../services/ratelimit.service';
import * as userRepository from '../repositories/user.repository';
import * as passwordUtils from '../utils/password';
import * as mfaHandler from './mfa-handler';

// Mock services
jest.mock('../services/reverification.service', () => {
  const actual = jest.requireActual('../services/reverification.service');
  return {
    ...actual,
    reverificationService: {
      completeReverification: jest.fn(),
      getReverificationStatus: jest.fn(),
      levelSatisfies: jest.fn()
    },
    ReverificationError: actual.ReverificationError
  };
});

jest.mock('../services/ratelimit.service');
jest.mock('../repositories/user.repository');
jest.mock('../utils/password');
jest.mock('./mfa-handler', () => ({
  verifyMFACode: jest.fn()
}));

const mockReverificationService = reverificationService as jest.Mocked<typeof reverificationService>;
const mockRateLimitService = rateLimitService as jest.Mocked<typeof rateLimitService>;
const mockUserRepository = userRepository as jest.Mocked<typeof userRepository>;
const mockPasswordUtils = passwordUtils as jest.Mocked<typeof passwordUtils>;
const mockMfaHandler = mfaHandler as jest.Mocked<typeof mfaHandler>;

// Helper to create mock event
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/reverify/status',
    headers: {
      Authorization: 'Bearer test_token'
    },
    body: null,
    queryStringParameters: null,
    pathParameters: null,
    requestContext: {
      authorizer: {
        userId: 'user_123',
        realmId: 'realm_456',
        sessionId: 'session_789',
        email: 'test@example.com'
      },
      identity: {
        sourceIp: '192.168.1.1'
      }
    } as any,
    ...overrides
  } as APIGatewayProxyEvent;
}

// Mock user data
const mockUser = {
  id: 'user_123',
  realm_id: 'realm_456',
  email: 'test@example.com',
  password_hash: 'hashed_password',
  mfa_enabled: true,
  mfa_secret: 'encrypted_secret',
  webauthn_credentials: [{ id: 'cred_1', publicKey: 'key' }],
  status: 'active' as const,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z'
};

describe('Reverification Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default rate limit to allow
    mockRateLimitService.checkRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 4,
      resetAt: Date.now() + 60000
    });
    
    // Default user lookup
    mockUserRepository.findUserById.mockResolvedValue(mockUser as any);
    
    // Default MFA verification to fail (must be explicitly set to pass)
    mockMfaHandler.verifyMFACode.mockResolvedValue({ valid: false });
  });

  describe('OPTIONS (CORS preflight)', () => {
    it('should return 200 for OPTIONS request', async () => {
      const event = createMockEvent({ httpMethod: 'OPTIONS' });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
      expect(result.headers).toHaveProperty('Access-Control-Allow-Origin', '*');
      expect(result.headers).toHaveProperty('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    });
  });

  describe('POST /reverify/password', () => {
    it('should verify with password successfully', async () => {
      mockPasswordUtils.verifyPassword.mockResolvedValueOnce(true);
      mockReverificationService.completeReverification.mockResolvedValueOnce({
        sessionId: 'session_789',
        level: 'password',
        verifiedAt: '2026-01-01T10:00:00Z',
        expiresAt: '2026-01-01T10:10:00Z',
        method: 'password'
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        body: JSON.stringify({ password: 'correct_password' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Reverification successful');
      expect(body.reverification.level).toBe('password');
      expect(body.reverification.verified_at).toBeDefined();
      expect(body.reverification.expires_at).toBeDefined();
    });

    it('should reject without authentication', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        headers: {},
        requestContext: {} as any,
        body: JSON.stringify({ password: 'test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject when rate limited', async () => {
      mockRateLimitService.checkRateLimit.mockResolvedValueOnce({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 60000,
        retryAfter: 60
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        body: JSON.stringify({ password: 'test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should reject missing password', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        body: JSON.stringify({})
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_PASSWORD');
    });

    it('should reject invalid password', async () => {
      mockPasswordUtils.verifyPassword.mockResolvedValueOnce(false);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        body: JSON.stringify({ password: 'wrong_password' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should reject invalid JSON', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        body: 'not json'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should handle user not found', async () => {
      mockUserRepository.findUserById.mockResolvedValueOnce(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        body: JSON.stringify({ password: 'test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
    });
  });

  describe('POST /reverify/mfa', () => {
    it('should verify with MFA successfully', async () => {
      mockMfaHandler.verifyMFACode.mockResolvedValueOnce({
        valid: true,
        usedBackupCode: false
      });
      mockReverificationService.completeReverification.mockResolvedValueOnce({
        sessionId: 'session_789',
        level: 'mfa',
        verifiedAt: '2026-01-01T10:00:00Z',
        expiresAt: '2026-01-01T10:15:00Z',
        method: 'totp'
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/mfa',
        body: JSON.stringify({ code: '123456' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Reverification successful');
      expect(body.reverification.level).toBe('mfa');
      expect(body.used_backup_code).toBe(false);
    });

    it('should verify with backup code', async () => {
      mockMfaHandler.verifyMFACode.mockResolvedValueOnce({
        valid: true,
        usedBackupCode: true
      });
      mockReverificationService.completeReverification.mockResolvedValueOnce({
        sessionId: 'session_789',
        level: 'mfa',
        verifiedAt: '2026-01-01T10:00:00Z',
        expiresAt: '2026-01-01T10:15:00Z',
        method: 'backup_code'
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/mfa',
        body: JSON.stringify({ code: 'ABCD1234' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.used_backup_code).toBe(true);
    });

    it('should reject missing code', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/mfa',
        body: JSON.stringify({})
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_CODE');
    });

    it('should reject invalid code format', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/mfa',
        body: JSON.stringify({ code: '12345' }) // Only 5 digits
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_CODE_FORMAT');
    });

    it('should reject when MFA not enabled', async () => {
      mockUserRepository.findUserById.mockResolvedValueOnce({
        ...mockUser,
        mfa_enabled: false
      } as any);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/mfa',
        body: JSON.stringify({ code: '123456' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MFA_NOT_ENABLED');
    });

    it('should reject invalid MFA code', async () => {
      mockMfaHandler.verifyMFACode.mockResolvedValueOnce({
        valid: false
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/mfa',
        body: JSON.stringify({ code: '000000' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_MFA_CODE');
    });
  });

  describe('POST /reverify/webauthn', () => {
    const validCredential = {
      id: 'credential_id',
      rawId: 'raw_id',
      response: {
        clientDataJSON: 'client_data',
        authenticatorData: 'auth_data',
        signature: 'signature'
      },
      type: 'public-key'
    };

    it('should verify with WebAuthn successfully', async () => {
      mockReverificationService.completeReverification.mockResolvedValueOnce({
        sessionId: 'session_789',
        level: 'webauthn',
        verifiedAt: '2026-01-01T10:00:00Z',
        expiresAt: '2026-01-01T10:30:00Z',
        method: 'webauthn'
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/webauthn',
        body: JSON.stringify({
          credential: validCredential,
          challenge: 'test_challenge'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Reverification successful');
      expect(body.reverification.level).toBe('webauthn');
    });

    it('should reject missing credential', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/webauthn',
        body: JSON.stringify({ challenge: 'test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_CREDENTIAL');
    });

    it('should reject missing challenge', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/webauthn',
        body: JSON.stringify({ credential: validCredential })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_CHALLENGE');
    });

    it('should reject invalid credential format', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/webauthn',
        body: JSON.stringify({
          credential: { type: 'public-key' }, // Missing id and response
          challenge: 'test'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_CREDENTIAL');
    });

    it('should reject when WebAuthn not configured', async () => {
      mockUserRepository.findUserById.mockResolvedValueOnce({
        ...mockUser,
        webauthn_credentials: []
      } as any);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/webauthn',
        body: JSON.stringify({
          credential: validCredential,
          challenge: 'test'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('WEBAUTHN_NOT_CONFIGURED');
    });
  });

  describe('GET /reverify/status', () => {
    it('should return reverification status', async () => {
      mockReverificationService.getReverificationStatus.mockResolvedValueOnce({
        hasReverification: true,
        reverification: {
          sessionId: 'session_789',
          level: 'mfa',
          verifiedAt: '2026-01-01T10:00:00Z',
          expiresAt: '2026-01-01T10:15:00Z',
          method: 'totp'
        },
        isValid: true,
        requiredLevel: null
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/reverify/status'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.has_reverification).toBe(true);
      expect(body.is_valid).toBe(true);
      expect(body.reverification.level).toBe('mfa');
    });

    it('should return status with required level check', async () => {
      mockReverificationService.getReverificationStatus.mockResolvedValueOnce({
        hasReverification: true,
        reverification: {
          sessionId: 'session_789',
          level: 'mfa',
          verifiedAt: '2026-01-01T10:00:00Z',
          expiresAt: '2026-01-01T10:15:00Z',
          method: 'totp'
        },
        isValid: true,
        requiredLevel: 'password'
      });
      mockReverificationService.levelSatisfies.mockReturnValueOnce(true);

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/reverify/status',
        queryStringParameters: { level: 'password' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.required_level).toBe('password');
      expect(body.satisfies_required).toBe(true);
    });

    it('should return no reverification when none exists', async () => {
      mockReverificationService.getReverificationStatus.mockResolvedValueOnce({
        hasReverification: false,
        reverification: null,
        isValid: false,
        requiredLevel: null
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/reverify/status'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.has_reverification).toBe(false);
      expect(body.is_valid).toBe(false);
      expect(body.reverification).toBeNull();
    });

    it('should reject invalid level parameter', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/reverify/status',
        queryStringParameters: { level: 'invalid' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_LEVEL');
    });

    it('should reject without authentication', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/reverify/status',
        headers: {},
        requestContext: {} as any
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('Unknown endpoint', () => {
    it('should return 404 for unknown path', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/reverify/unknown'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should return 404 for wrong method', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/reverify/password'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('Error handling', () => {
    it('should handle ReverificationError', async () => {
      mockPasswordUtils.verifyPassword.mockResolvedValueOnce(true);
      mockReverificationService.completeReverification.mockRejectedValueOnce(
        new ReverificationError('TEST_ERROR', 'Test error message', 400, 'mfa')
      );

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        body: JSON.stringify({ password: 'test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('TEST_ERROR');
      expect(body.error.required_level).toBe('mfa');
    });

    it('should handle unexpected errors', async () => {
      mockPasswordUtils.verifyPassword.mockRejectedValueOnce(new Error('Unexpected'));

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/reverify/password',
        body: JSON.stringify({ password: 'test' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(500);
      expect(body.error.code).toBe('INTERNAL_ERROR');
    });
  });
});
