/**
 * Google OAuth Handler E2E Tests
 * 
 * Task 4.2: Google OAuth Handler
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
    exchangeGoogleCode: jest.fn(),
    getGoogleUserInfo: jest.fn()
  };
});

// Import after mocks
import {
  googleAuthorizeHandler,
  googleCallbackHandler
} from '../../handlers/social-handler';
import { findRealmById } from '../../repositories/realm.repository';
import { findUserByEmail, createUser } from '../../repositories/user.repository';
import { checkRateLimit } from '../../services/ratelimit.service';
import { exchangeGoogleCode, getGoogleUserInfo, encryptState, OAuthState } from '../../services/oauth.service';

// Set environment variables for tests
process.env.OAUTH_GOOGLE_CLIENT_ID = 'test-google-client-id';
process.env.OAUTH_GOOGLE_CLIENT_SECRET = 'test-google-secret';
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

const mockGoogleUser = {
  id: 'google-user-123',
  email: 'dr.ayse@example.com',
  emailVerified: true,
  name: 'Dr. Ayşe Yılmaz',
  givenName: 'Ayşe',
  familyName: 'Yılmaz',
  picture: 'https://lh3.googleusercontent.com/photo.jpg'
};

function createMockEvent(
  queryParams: Record<string, string> = {},
  body: string | null = null
): APIGatewayProxyEvent {
  return {
    body,
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Test-Agent/1.0'
    },
    httpMethod: 'GET',
    isBase64Encoded: false,
    path: '/v1/auth/social/google/authorize',
    pathParameters: null,
    queryStringParameters: queryParams,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '/v1/auth/social/google/authorize',
    multiValueHeaders: {}
  };
}

describe('Google OAuth Handler E2E Tests', () => {
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
    it('should redirect to Google authorization URL', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await googleAuthorizeHandler(event);

      expect(response.statusCode).toBe(302);
      expect(response.headers?.Location).toContain('accounts.google.com');
      expect(response.headers?.Location).toContain('client_id=test-google-client-id');
    });

    it('should include PKCE parameters in URL', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await googleAuthorizeHandler(event);

      expect(response.headers?.Location).toContain('code_challenge=');
      expect(response.headers?.Location).toContain('code_challenge_method=S256');
    });

    it('should include encrypted state with realm_id', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await googleAuthorizeHandler(event);

      expect(response.headers?.Location).toContain('state=');
    });

    it('should reject missing realm_id', async () => {
      const event = createMockEvent({});

      const response = await googleAuthorizeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toContain('realm_id');
    });

    it('should reject when OAuth not configured', async () => {
      // Remove OAuth config
      const originalClientId = process.env.OAUTH_GOOGLE_CLIENT_ID;
      delete process.env.OAUTH_GOOGLE_CLIENT_ID;

      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await googleAuthorizeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('OAUTH_NOT_CONFIGURED');

      // Restore
      process.env.OAUTH_GOOGLE_CLIENT_ID = originalClientId;
    });

    it('should enforce rate limiting', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 60000
      });

      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await googleAuthorizeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });

    it('should request offline access for refresh token', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await googleAuthorizeHandler(event);
      const location = response.headers?.Location as string;

      expect(response.statusCode).toBe(302);
      expect(location).toContain('access_type=offline');
    });
  });

  describe('Callback Handler', () => {
    beforeEach(() => {
      // Return tokens WITHOUT idToken to skip ID token verification
      // In production, ID token verification would use JWKS
      (exchangeGoogleCode as jest.Mock).mockResolvedValue({
        accessToken: 'google-access-token',
        refreshToken: 'google-refresh-token',
        // No idToken - skip verification in tests
        tokenType: 'Bearer',
        expiresIn: 3600
      });
      (getGoogleUserInfo as jest.Mock).mockResolvedValue(mockGoogleUser);
    });

    // Helper to get state from authorize response
    async function getStateFromAuthorize(realmId: string, redirectUrl?: string): Promise<string> {
      const params: Record<string, string> = { realm_id: realmId };
      if (redirectUrl) params.redirect_url = redirectUrl;
      
      const event = createMockEvent(params);
      const response = await googleAuthorizeHandler(event);
      
      const location = response.headers?.Location as string;
      const url = new URL(location);
      return url.searchParams.get('state') || '';
    }

    it('should handle successful callback for existing user', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);

      // First, go through authorize to store PKCE
      const state = await getStateFromAuthorize('clinisyn-psychologists');

      const event = createMockEvent({
        code: 'auth-code-123',
        state
      });

      const response = await googleCallbackHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Login successful');
      expect(body.tokens.access_token).toBeDefined();
    });

    it('should create new user for first-time OAuth login', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(null);
      (createUser as jest.Mock).mockResolvedValue({
        ...mockUser,
        id: 'new-user-123'
      });

      // First, go through authorize to store PKCE
      const state = await getStateFromAuthorize('clinisyn-psychologists');

      const event = createMockEvent({
        code: 'auth-code-123',
        state
      });

      const response = await googleCallbackHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Account created successfully');
      expect(createUser).toHaveBeenCalled();
    });

    it('should reject OAuth error response', async () => {
      const event = createMockEvent({
        error: 'access_denied',
        error_description: 'User denied access'
      });

      const response = await googleCallbackHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('OAUTH_ERROR');
    });

    it('should reject missing authorization code', async () => {
      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now()
      };
      const encryptedState = encryptState(state);

      const event = createMockEvent({
        state: encryptedState
      });

      const response = await googleCallbackHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.message).toContain('Missing authorization code');
    });

    it('should reject invalid state', async () => {
      const event = createMockEvent({
        code: 'auth-code-123',
        state: 'invalid-state'
      });

      const response = await googleCallbackHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.message).toContain('Invalid or expired state');
    });

    it('should reject expired state', async () => {
      const state: OAuthState = {
        realmId: 'clinisyn-psychologists',
        nonce: 'test-nonce',
        timestamp: Date.now() - 15 * 60 * 1000 // 15 minutes ago
      };
      const encryptedState = encryptState(state);

      const event = createMockEvent({
        code: 'auth-code-123',
        state: encryptedState
      });

      const response = await googleCallbackHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
    });

    it('should redirect with tokens when redirect_url provided', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);

      // First, go through authorize to store PKCE with redirect_url
      const state = await getStateFromAuthorize('clinisyn-psychologists', 'https://clinisyn.com/dashboard');

      const event = createMockEvent({
        code: 'auth-code-123',
        state
      });

      const response = await googleCallbackHandler(event);

      expect(response.statusCode).toBe(302);
      expect(response.headers?.Location).toContain('clinisyn.com/dashboard');
      expect(response.headers?.Location).toContain('access_token=');
    });
  });

  describe('Security Logging', () => {
    it('should log OAuth authorize start', async () => {
      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });
      await googleAuthorizeHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'oauth_authorize_started',
          details: expect.objectContaining({ provider: 'google' })
        })
      );
    });

    it('should log OAuth login success', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);
      (exchangeGoogleCode as jest.Mock).mockResolvedValue({
        accessToken: 'token',
        tokenType: 'Bearer',
        expiresIn: 3600
      });
      (getGoogleUserInfo as jest.Mock).mockResolvedValue(mockGoogleUser);

      // First, go through authorize to store PKCE
      const authorizeEvent = createMockEvent({ realm_id: 'clinisyn-psychologists' });
      const authorizeResponse = await googleAuthorizeHandler(authorizeEvent);
      const location = authorizeResponse.headers?.Location as string;
      const url = new URL(location);
      const state = url.searchParams.get('state') || '';

      mockLogSecurityEvent.mockClear(); // Clear authorize log

      const event = createMockEvent({
        code: 'auth-code-123',
        state
      });

      await googleCallbackHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'oauth_login_success'
        })
      );
    });
  });

  describe('Realm-Specific Credentials', () => {
    it('should use realm-specific OAuth credentials when available', async () => {
      // Set realm-specific credentials
      process.env.OAUTH_GOOGLE_CLIENT_ID_CLINISYN_PSYCHOLOGISTS = 'clinisyn-specific-client-id';

      const event = createMockEvent({ realm_id: 'clinisyn-psychologists' });

      const response = await googleAuthorizeHandler(event);
      const location = response.headers?.Location as string;

      expect(response.statusCode).toBe(302);
      expect(location).toContain('client_id=clinisyn-specific-client-id');

      // Cleanup
      delete process.env.OAUTH_GOOGLE_CLIENT_ID_CLINISYN_PSYCHOLOGISTS;
    });
  });
});
