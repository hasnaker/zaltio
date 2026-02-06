/**
 * Apple Sign-In Handler E2E Tests
 * 
 * Task 4.3: Apple Sign-In Handler
 * Validates: Requirements 4.1, 4.2 (Social Login)
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
jest.mock('../../repositories/realm.repository', () => ({
  findRealmById: jest.fn()
}));

jest.mock('../../repositories/user.repository', () => ({
  findUserByEmail: jest.fn(),
  createUser: jest.fn()
}));

jest.mock('../../repositories/session.repository', () => ({
  createSession: jest.fn().mockResolvedValue({ id: 'session-123' })
}));

jest.mock('../../utils/jwt', () => ({
  generateTokenPair: jest.fn().mockResolvedValue({
    access_token: 'mock-access-token',
    refresh_token: 'mock-refresh-token',
    expires_in: 900
  })
}));

jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({
    allowed: true,
    remaining: 9,
    resetAt: Date.now() + 60000
  })
}));

// Mock OAuth service functions that make external calls
jest.mock('../../services/oauth.service', () => {
  const actual = jest.requireActual('../../services/oauth.service');
  return {
    ...actual,
    exchangeAppleCode: jest.fn(),
    verifyIDToken: jest.fn()
  };
});

// Import after mocks
import {
  appleAuthorizeHandler,
  appleCallbackHandler
} from '../../handlers/social-handler';
import { findRealmById } from '../../repositories/realm.repository';
import { findUserByEmail, createUser } from '../../repositories/user.repository';
import { checkRateLimit } from '../../services/ratelimit.service';
import { exchangeAppleCode, verifyIDToken, encryptState, OAuthState } from '../../services/oauth.service';

// Set environment variables for tests
process.env.OAUTH_APPLE_CLIENT_ID = 'com.clinisyn.auth';
process.env.OAUTH_APPLE_CLIENT_SECRET = 'test-apple-secret';
process.env.API_BASE_URL = 'https://api.zalt.io';

const mockRealm = {
  id: 'clinisyn-psychologists',
  name: 'Clinisyn Psychologists',
  domain: 'clinisyn.zalt.io'
};

const mockUser = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  email_verified: true,
  profile: { first_name: 'Ayşe', last_name: 'Yılmaz' },
  status: 'active'
};

const mockAppleClaims = {
  iss: 'https://appleid.apple.com',
  sub: 'apple-user-123',
  aud: 'com.clinisyn.auth',
  exp: Math.floor(Date.now() / 1000) + 3600,
  iat: Math.floor(Date.now() / 1000),
  email: 'dr.ayse@example.com',
  email_verified: true
};

function createMockEvent(
  queryParams: Record<string, string> = {},
  body: string | null = null,
  method: string = 'GET'
): APIGatewayProxyEvent {
  return {
    body,
    headers: {
      'Content-Type': method === 'POST' ? 'application/x-www-form-urlencoded' : 'application/json',
      'User-Agent': 'Test-Agent/1.0'
    },
    httpMethod: method,
    isBase64Encoded: false,
    path: '/v1/auth/social/apple/authorize',
    pathParameters: null,
    queryStringParameters: queryParams,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '/v1/auth/social/apple/authorize',
    multiValueHeaders: {}
  };
}

describe('Apple Sign-In Handler E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (findRealmById as jest.Mock).mockResolvedValue(mockRealm);
    (checkRateLimit as jest.Mock).mockResolvedValue({
      allowed: true,
      remaining: 9,
      resetAt: Date.now() + 60000
    });
    mockLogSecurityEvent.mockClear();
  });

  describe('Authorize Handler', () => {
    it('should redirect to Apple authorization URL', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await appleAuthorizeHandler(event);

      expect(response.statusCode).toBe(302);
      expect(response.headers?.Location).toContain('appleid.apple.com');
      expect(response.headers?.Location).toContain('client_id=com.clinisyn.auth');
    });

    it('should include response_mode=form_post', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await appleAuthorizeHandler(event);
      const location = response.headers?.Location as string;

      expect(location).toContain('response_mode=form_post');
    });

    it('should include encrypted state with realm_id', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await appleAuthorizeHandler(event);
      const location = response.headers?.Location as string;

      expect(location).toContain('state=');
    });

    it('should request code and id_token response type', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await appleAuthorizeHandler(event);
      const location = response.headers?.Location as string;

      // Apple uses "code id_token" response type
      expect(location).toContain('response_type=code');
    });

    it('should reject missing realm_id', async () => {
      const event = createMockEvent({});

      const response = await appleAuthorizeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toContain('realm_id');
    });

    it('should reject when OAuth not configured', async () => {
      const originalClientId = process.env.OAUTH_APPLE_CLIENT_ID;
      delete process.env.OAUTH_APPLE_CLIENT_ID;

      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await appleAuthorizeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('OAUTH_NOT_CONFIGURED');

      process.env.OAUTH_APPLE_CLIENT_ID = originalClientId;
    });

    it('should enforce rate limiting', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 60000
      });

      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await appleAuthorizeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });

    it('should log OAuth authorize start', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });
      await appleAuthorizeHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'oauth_authorize_started',
          details: expect.objectContaining({ provider: 'apple' })
        })
      );
    });
  });

  describe('Callback Handler (POST)', () => {
    beforeEach(() => {
      (exchangeAppleCode as jest.Mock).mockResolvedValue({
        accessToken: 'apple-access-token',
        refreshToken: 'apple-refresh-token',
        idToken: 'apple-id-token',
        tokenType: 'Bearer',
        expiresIn: 3600
      });
      (verifyIDToken as jest.Mock).mockResolvedValue({
        valid: true,
        claims: mockAppleClaims
      });
    });

    // Helper to create POST body for Apple callback
    function createAppleCallbackBody(params: Record<string, string>): string {
      return new URLSearchParams(params).toString();
    }

    it('should handle successful callback for existing user', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);

      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: encryptedState
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);
      const responseBody = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(responseBody.message).toBe('Login successful');
      expect(responseBody.tokens.access_token).toBeDefined();
    });

    it('should create new user for first-time Apple Sign-In', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(null);
      (createUser as jest.Mock).mockResolvedValue({
        ...mockUser,
        id: 'new-user-123'
      });

      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      // Apple provides user info only on first sign-in
      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: encryptedState,
        user: JSON.stringify({
          name: { firstName: 'Ayşe', lastName: 'Yılmaz' },
          email: 'dr.ayse@example.com'
        })
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);
      const responseBody = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(responseBody.message).toBe('Account created successfully');
      expect(createUser).toHaveBeenCalled();
    });

    it('should handle Apple private relay email', async () => {
      const privateRelayEmail = 'abc123@privaterelay.appleid.com';
      (findUserByEmail as jest.Mock).mockResolvedValue(null);
      (createUser as jest.Mock).mockResolvedValue({
        ...mockUser,
        id: 'new-user-123',
        email: privateRelayEmail
      });
      (verifyIDToken as jest.Mock).mockResolvedValue({
        valid: true,
        claims: { ...mockAppleClaims, email: privateRelayEmail }
      });

      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: encryptedState
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);

      expect(response.statusCode).toBe(200);
      expect(createUser).toHaveBeenCalledWith(
        expect.objectContaining({
          email: privateRelayEmail,
          profile: expect.objectContaining({
            metadata: expect.objectContaining({
              is_private_relay: true
            })
          })
        })
      );
    });

    it('should reject OAuth error response', async () => {
      const body = createAppleCallbackBody({
        error: 'user_cancelled_authorize',
        error_description: 'User cancelled authorization'
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);
      const responseBody = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(responseBody.error.code).toBe('OAUTH_ERROR');
    });

    it('should reject missing authorization code', async () => {
      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      const body = createAppleCallbackBody({
        state: encryptedState
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);
      const responseBody = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(responseBody.error.message).toContain('Missing authorization code');
    });

    it('should reject invalid state', async () => {
      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: 'invalid-state'
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);
      const responseBody = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(responseBody.error.message).toContain('Invalid or expired state');
    });

    it('should reject expired state', async () => {
      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now() - 15 * 60 * 1000 // 15 minutes ago
      };
      const encryptedState = encryptState(state);

      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: encryptedState
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);

      expect(response.statusCode).toBe(400);
    });

    it('should reject invalid ID token', async () => {
      (verifyIDToken as jest.Mock).mockResolvedValue({
        valid: false,
        error: 'Invalid signature'
      });

      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: encryptedState
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);
      const responseBody = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(responseBody.error.code).toBe('INVALID_ID_TOKEN');
    });

    it('should reject missing email in ID token', async () => {
      (verifyIDToken as jest.Mock).mockResolvedValue({
        valid: true,
        claims: { ...mockAppleClaims, email: undefined }
      });

      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: encryptedState
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);
      const responseBody = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(responseBody.error.code).toBe('MISSING_EMAIL');
    });

    it('should redirect with tokens when redirect_url provided', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);

      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        redirectUrl: 'https://clinisyn.com/dashboard',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: encryptedState
      });

      const event = createMockEvent({}, body, 'POST');

      const response = await appleCallbackHandler(event);

      expect(response.statusCode).toBe(302);
      expect(response.headers?.Location).toContain('clinisyn.com/dashboard');
      expect(response.headers?.Location).toContain('access_token=');
    });

    it('should log OAuth login success', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);

      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      const body = createAppleCallbackBody({
        code: 'apple-auth-code',
        state: encryptedState
      });

      const event = createMockEvent({}, body, 'POST');

      await appleCallbackHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'oauth_login_success',
          details: expect.objectContaining({ provider: 'apple' })
        })
      );
    });
  });

  describe('Realm-Specific Credentials', () => {
    it('should use realm-specific Apple credentials when available', async () => {
      process.env.OAUTH_APPLE_CLIENT_ID_CLINISYN_PSYCHOLOGISTS = 'com.clinisyn.psychologists';

      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await appleAuthorizeHandler(event);
      const location = response.headers?.Location as string;

      expect(response.statusCode).toBe(302);
      expect(location).toContain('client_id=com.clinisyn.psychologists');

      delete process.env.OAUTH_APPLE_CLIENT_ID_CLINISYN_PSYCHOLOGISTS;
    });
  });
});
