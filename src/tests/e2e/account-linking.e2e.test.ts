/**
 * Account Linking E2E Tests
 * 
 * Task 4.4: Account Linking
 * Validates: Requirements 4.4 (Account Linking)
 * 
 * @e2e-test
 * @phase Phase 4
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock security logger first
const mockLogSecurityEvent = jest.fn().mockResolvedValue(undefined);
jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: mockLogSecurityEvent
}));

// Mock dependencies
jest.mock('../../repositories/user.repository', () => ({
  findUserById: jest.fn(),
  findUserByEmail: jest.fn(),
  updateUserMetadata: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../../utils/password', () => ({
  verifyPassword: jest.fn()
}));

jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({
    allowed: true,
    remaining: 9,
    resetAt: Date.now() + 60000
  })
}));

// Import after mocks
import {
  listProvidersHandler,
  verifyLinkingHandler,
  unlinkProviderHandler
} from '../../handlers/account-linking.handler';
import { findUserById, updateUserMetadata } from '../../repositories/user.repository';
import { verifyAccessToken } from '../../utils/jwt';
import { verifyPassword } from '../../utils/password';
import { checkRateLimit } from '../../services/ratelimit.service';

const mockUserWithPassword = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  email_verified: true,
  password_hash: '$argon2id$v=19$m=32768,t=5,p=2$...',
  profile: {
    first_name: 'Ayşe',
    last_name: 'Yılmaz',
    metadata: {
      linked_providers: [
        {
          provider: 'google',
          providerId: 'google-123',
          email: 'dr.ayse@gmail.com',
          linkedAt: '2026-01-15T10:00:00Z'
        }
      ]
    }
  },
  status: 'active'
};

const mockUserOAuthOnly = {
  id: 'user-456',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.mehmet@example.com',
  email_verified: true,
  password_hash: '', // No password
  profile: {
    first_name: 'Mehmet',
    last_name: 'Kaya',
    metadata: {
      linked_providers: [
        {
          provider: 'apple',
          providerId: 'apple-456',
          email: 'dr.mehmet@icloud.com',
          linkedAt: '2026-01-15T10:00:00Z'
        }
      ]
    }
  },
  status: 'active'
};

const mockTokenPayload = {
  sub: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  type: 'access'
};

function createMockEvent(
  method: string = 'GET',
  body: string | null = null,
  pathParams: Record<string, string> = {},
  headers: Record<string, string> = {}
): APIGatewayProxyEvent {
  return {
    body,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer valid-token',
      ...headers
    },
    httpMethod: method,
    isBase64Encoded: false,
    path: '/v1/auth/account/providers',
    pathParameters: Object.keys(pathParams).length > 0 ? pathParams : null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '/v1/auth/account/providers',
    multiValueHeaders: {}
  };
}

describe('Account Linking E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (verifyAccessToken as jest.Mock).mockResolvedValue(mockTokenPayload);
    (findUserById as jest.Mock).mockResolvedValue(mockUserWithPassword);
    (verifyPassword as jest.Mock).mockResolvedValue(true);
    (checkRateLimit as jest.Mock).mockResolvedValue({
      allowed: true,
      remaining: 9,
      resetAt: Date.now() + 60000
    });
    mockLogSecurityEvent.mockClear();
  });

  describe('List Providers Handler', () => {
    it('should list linked providers for authenticated user', async () => {
      const event = createMockEvent('GET');

      const response = await listProvidersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.providers).toHaveLength(1);
      expect(body.providers[0].provider).toBe('google');
      expect(body.has_password).toBe(true);
    });

    it('should indicate when user has no password', async () => {
      (findUserById as jest.Mock).mockResolvedValue(mockUserOAuthOnly);
      (verifyAccessToken as jest.Mock).mockResolvedValue({
        ...mockTokenPayload,
        sub: 'user-456'
      });

      const event = createMockEvent('GET');

      const response = await listProvidersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.has_password).toBe(false);
      expect(body.can_add_password).toBe(true);
    });

    it('should reject unauthenticated requests', async () => {
      const event = createMockEvent('GET', null, {}, { Authorization: '' });

      const response = await listProvidersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject invalid token', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent('GET');

      const response = await listProvidersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });

    it('should return 404 for non-existent user', async () => {
      (findUserById as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent('GET');

      const response = await listProvidersHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('USER_NOT_FOUND');
    });
  });

  describe('Verify Linking Handler', () => {
    it('should verify password for account linking', async () => {
      const event = createMockEvent('POST', JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        user_id: 'user-123',
        password: 'correct-password'
      }));

      const response = await verifyLinkingHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.verified).toBe(true);
      expect(body.linking_confirmed).toBe(true);
    });

    it('should reject invalid password', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent('POST', JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        user_id: 'user-123',
        password: 'wrong-password'
      }));

      const response = await verifyLinkingHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });

    it('should log failed password verification', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent('POST', JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        user_id: 'user-123',
        password: 'wrong-password'
      }));

      await verifyLinkingHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'account_linking_password_failed'
        })
      );
    });

    it('should log successful password verification', async () => {
      const event = createMockEvent('POST', JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        user_id: 'user-123',
        password: 'correct-password'
      }));

      await verifyLinkingHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'account_linking_password_verified'
        })
      );
    });

    it('should reject missing required fields', async () => {
      const event = createMockEvent('POST', JSON.stringify({
        realm_id: 'clinisyn-psychologists'
        // Missing user_id and password
      }));

      const response = await verifyLinkingHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should enforce rate limiting', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 60000
      });

      const event = createMockEvent('POST', JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        user_id: 'user-123',
        password: 'password'
      }));

      const response = await verifyLinkingHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });
  });

  describe('Unlink Provider Handler', () => {
    it('should unlink provider with password verification', async () => {
      const event = createMockEvent(
        'DELETE',
        JSON.stringify({ password: 'correct-password' }),
        { provider: 'google' }
      );

      const response = await unlinkProviderHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.provider).toBe('google');
      expect(updateUserMetadata).toHaveBeenCalled();
    });

    it('should require password for users with password', async () => {
      const event = createMockEvent(
        'DELETE',
        null,
        { provider: 'google' }
      );

      const response = await unlinkProviderHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('PASSWORD_REQUIRED');
    });

    it('should reject invalid password when unlinking', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent(
        'DELETE',
        JSON.stringify({ password: 'wrong-password' }),
        { provider: 'google' }
      );

      const response = await unlinkProviderHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });

    it('should prevent unlinking last auth method', async () => {
      // User with only one provider and no password
      (findUserById as jest.Mock).mockResolvedValue(mockUserOAuthOnly);
      (verifyAccessToken as jest.Mock).mockResolvedValue({
        ...mockTokenPayload,
        sub: 'user-456'
      });

      const event = createMockEvent(
        'DELETE',
        null,
        { provider: 'apple' }
      );

      const response = await unlinkProviderHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('CANNOT_UNLINK');
      expect(body.error.message).toContain('only authentication method');
    });

    it('should reject invalid provider', async () => {
      const event = createMockEvent(
        'DELETE',
        JSON.stringify({ password: 'password' }),
        { provider: 'facebook' }
      );

      const response = await unlinkProviderHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_PROVIDER');
    });

    it('should reject unlinking non-linked provider', async () => {
      const event = createMockEvent(
        'DELETE',
        JSON.stringify({ password: 'correct-password' }),
        { provider: 'apple' } // User only has google linked
      );

      const response = await unlinkProviderHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('PROVIDER_NOT_LINKED');
    });

    it('should log provider unlink', async () => {
      const event = createMockEvent(
        'DELETE',
        JSON.stringify({ password: 'correct-password' }),
        { provider: 'google' }
      );

      await unlinkProviderHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'provider_unlinked',
          details: expect.objectContaining({ provider: 'google' })
        })
      );
    });

    it('should enforce rate limiting', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 60000
      });

      const event = createMockEvent(
        'DELETE',
        JSON.stringify({ password: 'password' }),
        { provider: 'google' }
      );

      const response = await unlinkProviderHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });
  });

  describe('Account Takeover Protection', () => {
    it('should require password verification for linking existing account', async () => {
      // This is tested via verifyLinkingHandler
      const event = createMockEvent('POST', JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        user_id: 'user-123',
        password: 'correct-password'
      }));

      const response = await verifyLinkingHandler(event);

      expect(response.statusCode).toBe(200);
      expect(verifyPassword).toHaveBeenCalled();
    });

    it('should log all linking attempts for audit', async () => {
      const event = createMockEvent('POST', JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        user_id: 'user-123',
        password: 'correct-password'
      }));

      await verifyLinkingHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalled();
    });
  });
});
