/**
 * User Login E2E Tests
 * 
 * Task 1.4: User Login Handler
 * Validates: Requirements 2.1, 2.3, 2.5
 * 
 * @e2e-test
 * @phase Phase 1
 * @security-critical
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Generate test RSA keys BEFORE mocks
const crypto = require('crypto');
const { publicKey: testPublicKey, privateKey: testPrivateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Mock dependencies - must be before handler import
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
  findUserByEmail: jest.fn(),
  updateUserLoginAttempts: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('../../repositories/realm.repository', () => ({
  findRealmById: jest.fn().mockResolvedValue({
    id: 'clinisyn-psychologists',
    name: 'Clinisyn Psychologists',
    status: 'active'
  }),
  getRealmSettings: jest.fn().mockResolvedValue({
    session_timeout: 900,
    mfa_policy: 'optional'
  })
}));

jest.mock('../../repositories/session.repository', () => ({
  createSession: jest.fn().mockResolvedValue({
    id: 'session-123',
    user_id: 'user-123',
    realm_id: 'clinisyn-psychologists'
  })
}));

jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({
    allowed: true,
    remaining: 4,
    resetAt: Math.floor(Date.now() / 1000) + 900
  }),
  getRealmRateLimitConfig: jest.fn().mockReturnValue({
    maxRequests: 5,
    windowSeconds: 900
  })
}));

jest.mock('../../utils/password', () => ({
  verifyPassword: jest.fn().mockResolvedValue(true),
  needsRehash: jest.fn().mockReturnValue(false),
  hashPassword: jest.fn().mockResolvedValue('new-hash')
}));

jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

// Mock JWT to avoid key issues
jest.mock('../../utils/jwt', () => ({
  generateTokenPair: jest.fn().mockResolvedValue({
    access_token: 'mock-access-token',
    refresh_token: 'mock-refresh-token',
    expires_in: 900
  })
}));

// Import handler AFTER mocks
import { handler } from '../../handlers/login-handler';
import { findUserByEmail, updateUserLoginAttempts } from '../../repositories/user.repository';
import { findRealmById } from '../../repositories/realm.repository';
import { checkRateLimit } from '../../services/ratelimit.service';
import { verifyPassword } from '../../utils/password';

const mockUser = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  email_verified: true,
  password_hash: '$argon2id$v=19$m=32768,t=5,p=2$hash',
  profile: { first_name: 'Ayşe', last_name: 'Yılmaz' },
  status: 'active',
  failed_login_attempts: 0
};

function createMockEvent(body: object, ip: string = '192.168.1.1'): APIGatewayProxyEvent {
  return {
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Test-Agent/1.0'
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/login',
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
    resource: '/v1/auth/login',
    multiValueHeaders: {}
  };
}

describe('User Login E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);
    (verifyPassword as jest.Mock).mockResolvedValue(true);
  });

  describe('Successful Login', () => {
    it('should login with valid credentials', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Login successful');
      expect(body.user.email).toBe('dr.ayse@example.com');
      expect(body.tokens.access_token).toBeTruthy();
      expect(body.tokens.refresh_token).toBeTruthy();
      expect(body.tokens.expires_in).toBe(900);
    });

    it('should include rate limit headers', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);

      expect(response.headers).toHaveProperty('X-RateLimit-Remaining');
      expect(response.headers).toHaveProperty('X-RateLimit-Reset');
    });

    it('should reset failed attempts on successful login', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        failed_login_attempts: 3
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      await handler(event);

      expect(updateUserLoginAttempts).toHaveBeenCalledWith('user-123', 0, undefined);
    });
  });

  describe('Invalid Credentials', () => {
    it('should reject invalid password with generic message', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'WrongPassword!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
      expect(body.error.message).toBe('Invalid email or password');
    });

    it('should reject non-existent user with same message (no enumeration)', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'nonexistent@example.com',
        password: 'SomePassword!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
      expect(body.error.message).toBe('Invalid email or password');
    });

    it('should increment failed attempts on wrong password', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'WrongPassword!'
      });

      await handler(event);

      expect(updateUserLoginAttempts).toHaveBeenCalledWith(
        'user-123',
        1,
        undefined
      );
    });
  });

  describe('Account Lockout', () => {
    it('should lock account after 5 failed attempts', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        failed_login_attempts: 4
      });
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'WrongPassword!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(423);
      expect(body.error.code).toBe('ACCOUNT_LOCKED');
      expect(updateUserLoginAttempts).toHaveBeenCalledWith(
        'user-123',
        5,
        expect.any(String) // locked_until timestamp
      );
    }, 20000); // Increase timeout for progressive delay

    it('should reject login for locked account', async () => {
      const lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      (findUserByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        failed_login_attempts: 5,
        locked_until: lockedUntil
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(423);
      expect(body.error.code).toBe('ACCOUNT_LOCKED');
      expect(body.error.details.locked_until).toBe(lockedUntil);
    });

    it('should allow login after lockout expires', async () => {
      const expiredLock = new Date(Date.now() - 1000).toISOString();
      (findUserByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        failed_login_attempts: 5,
        locked_until: expiredLock
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
    }, 20000); // Increase timeout for progressive delay
  });

  describe('Rate Limiting', () => {
    it('should reject when rate limit exceeded', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValueOnce({
        allowed: false,
        remaining: 0,
        resetAt: Math.floor(Date.now() / 1000) + 900,
        retryAfter: 900
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
      expect(response.headers).toHaveProperty('Retry-After');
    });
  });

  describe('Suspended Account', () => {
    it('should reject login for suspended account', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        status: 'suspended'
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(423);
      expect(body.error.code).toBe('ACCOUNT_SUSPENDED');
    });
  });

  describe('Realm Validation', () => {
    it('should reject invalid realm', async () => {
      const event = createMockEvent({
        realm_id: '',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REALM');
    });

    it('should reject non-existent realm', async () => {
      (findRealmById as jest.Mock).mockResolvedValueOnce(null);

      const event = createMockEvent({
        realm_id: 'non-existent',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('REALM_NOT_FOUND');
    });
  });

  describe('Device Fingerprint', () => {
    it('should accept login with device fingerprint', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!',
        device_fingerprint: {
          userAgent: 'Mozilla/5.0',
          screen: '1920x1080',
          timezone: 'Europe/Istanbul',
          language: 'tr-TR',
          platform: 'MacIntel'
        }
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
    });
  });

  describe('Security Headers', () => {
    it('should include security headers', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await handler(event);

      expect(response.headers).toHaveProperty('X-Content-Type-Options', 'nosniff');
      expect(response.headers).toHaveProperty('X-Frame-Options', 'DENY');
    });
  });

  describe('Audit Logging', () => {
    it('should log successful login', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'login_success'
        })
      );
    });

    it('should log failed login', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'WrongPassword!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'login_failure'
        })
      );
    });
  });
});
