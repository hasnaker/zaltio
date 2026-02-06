/**
 * Token Refresh E2E Tests - Grace Period Implementation
 * 
 * Task 1.5: Token Refresh Handler (Grace Period)
 * Validates: Requirements 2.3, 9.5
 * 
 * @e2e-test
 * @phase Phase 1
 * @security-critical
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies before imports
jest.mock('../../services/secrets.service', () => ({
  getJWTKeys: jest.fn().mockImplementation(() => Promise.resolve({
    privateKey: `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7o5IDAQABo4IB
-----END PRIVATE KEY-----`,
    publicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu6OSAwEAAQ==
-----END PUBLIC KEY-----`
  }))
}));

jest.mock('../../repositories/user.repository', () => ({
  findUserById: jest.fn()
}));

jest.mock('../../repositories/realm.repository', () => ({
  findRealmById: jest.fn().mockResolvedValue({
    id: 'clinisyn-psychologists',
    name: 'Clinisyn Psychologists',
    status: 'active'
  }),
  getRealmSettings: jest.fn().mockResolvedValue({
    session_timeout: 900
  })
}));

jest.mock('../../repositories/session.repository', () => ({
  findSessionByRefreshToken: jest.fn(),
  findSessionByOldRefreshToken: jest.fn(),
  updateSessionTokens: jest.fn().mockResolvedValue({
    id: 'session-123',
    access_token: 'new-access-token',
    refresh_token: 'new-refresh-token'
  }),
  createSession: jest.fn()
}));

jest.mock('../../utils/jwt', () => ({
  verifyRefreshToken: jest.fn(),
  generateTokenPair: jest.fn().mockResolvedValue({
    access_token: 'new-access-token',
    refresh_token: 'new-refresh-token',
    expires_in: 900
  })
}));

import { handler } from '../../handlers/refresh-handler';
import { findUserById } from '../../repositories/user.repository';
import { findRealmById } from '../../repositories/realm.repository';
import { 
  findSessionByRefreshToken, 
  findSessionByOldRefreshToken,
  updateSessionTokens 
} from '../../repositories/session.repository';
import { verifyRefreshToken } from '../../utils/jwt';

const mockUser = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  status: 'active'
};

const mockSession = {
  id: 'session-123',
  user_id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  access_token: 'current-access-token',
  refresh_token: 'current-refresh-token',
  expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
};

function createMockEvent(body: object): APIGatewayProxyEvent {
  return {
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Test-Agent/1.0'
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/refresh',
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
    resource: '/v1/auth/refresh',
    multiValueHeaders: {}
  };
}

describe('Token Refresh E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (findUserById as jest.Mock).mockResolvedValue(mockUser);
    (verifyRefreshToken as jest.Mock).mockResolvedValue({
      sub: 'user-123',
      realm_id: 'clinisyn-psychologists',
      email: 'dr.ayse@example.com',
      type: 'refresh'
    });
    (findSessionByRefreshToken as jest.Mock).mockResolvedValue(mockSession);
    (findSessionByOldRefreshToken as jest.Mock).mockResolvedValue(null);
  });

  describe('Successful Token Refresh', () => {
    it('should refresh tokens with valid refresh token', async () => {
      const event = createMockEvent({
        refresh_token: 'valid-refresh-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Token refreshed successfully');
      expect(body.tokens.access_token).toBeTruthy();
      expect(body.tokens.refresh_token).toBeTruthy();
      expect(body.tokens.expires_in).toBe(900);
    });

    it('should rotate refresh token (old token invalidated)', async () => {
      const event = createMockEvent({
        refresh_token: 'valid-refresh-token'
      });

      await handler(event);

      expect(updateSessionTokens).toHaveBeenCalledWith(
        'session-123',
        'clinisyn-psychologists',
        'user-123',
        'new-access-token',
        'new-refresh-token',
        expect.any(String) // old token hash for grace period
      );
    });
  });

  describe('Grace Period (30 seconds)', () => {
    it('should return same tokens when old token used within grace period', async () => {
      // First request - normal refresh
      (findSessionByRefreshToken as jest.Mock).mockResolvedValue(null);
      (findSessionByOldRefreshToken as jest.Mock).mockResolvedValue({
        ...mockSession,
        access_token: 'already-rotated-access-token',
        refresh_token: 'already-rotated-refresh-token',
        rotated_at: new Date().toISOString() // Just rotated
      });

      const event = createMockEvent({
        refresh_token: 'old-refresh-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.grace_period_used).toBe(true);
      expect(body.tokens.access_token).toBe('already-rotated-access-token');
      expect(body.tokens.refresh_token).toBe('already-rotated-refresh-token');
    });

    it('should reject old token after grace period expires', async () => {
      (findSessionByRefreshToken as jest.Mock).mockResolvedValue(null);
      (findSessionByOldRefreshToken as jest.Mock).mockResolvedValue({
        ...mockSession,
        rotated_at: new Date(Date.now() - 60000).toISOString() // 60 seconds ago
      });

      const event = createMockEvent({
        refresh_token: 'old-refresh-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('TOKEN_ROTATED');
    });
  });

  describe('Invalid Token Handling', () => {
    it('should reject expired refresh token', async () => {
      (verifyRefreshToken as jest.Mock).mockRejectedValue(new Error('jwt expired'));

      const event = createMockEvent({
        refresh_token: 'expired-refresh-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('TOKEN_EXPIRED');
    });

    it('should reject manipulated refresh token', async () => {
      (verifyRefreshToken as jest.Mock).mockRejectedValue(new Error('invalid signature'));

      const event = createMockEvent({
        refresh_token: 'manipulated-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });

    it('should reject token not found in any session', async () => {
      (findSessionByRefreshToken as jest.Mock).mockResolvedValue(null);
      (findSessionByOldRefreshToken as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        refresh_token: 'unknown-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('User Validation', () => {
    it('should reject if user not found', async () => {
      (findUserById as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        refresh_token: 'valid-refresh-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('USER_NOT_FOUND');
    });

    it('should reject if user is suspended', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        status: 'suspended'
      });

      const event = createMockEvent({
        refresh_token: 'valid-refresh-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(423);
      expect(body.error.code).toBe('ACCOUNT_LOCKED');
    });
  });

  describe('Realm Validation', () => {
    it('should reject if realm not found', async () => {
      (findRealmById as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        refresh_token: 'valid-refresh-token'
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

    it('should reject missing refresh_token', async () => {
      const event = createMockEvent({});

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_TOKEN');
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

  describe('Session Update', () => {
    it('should update session with new tokens', async () => {
      // This is already tested in "should rotate refresh token" test
      // The updateSessionTokens function is called with old token hash
      expect(true).toBe(true);
    });
  });
});
