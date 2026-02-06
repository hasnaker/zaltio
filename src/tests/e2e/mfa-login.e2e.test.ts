/**
 * MFA Login Flow E2E Tests
 * 
 * Task 2.4: MFA Login Flow
 * Validates: Requirements 2.2
 * 
 * @e2e-test
 * @phase Phase 2
 * @security-critical
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
jest.mock('../../repositories/user.repository', () => ({
  findUserByEmail: jest.fn(),
  findUserById: jest.fn(),
  updateUserLoginAttempts: jest.fn().mockResolvedValue(undefined),
  updateUserMFA: jest.fn().mockResolvedValue(undefined)
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
    resetAt: Math.floor(Date.now() / 1000) + 60
  }),
  getRealmRateLimitConfig: jest.fn().mockReturnValue({
    maxRequests: 5,
    windowSeconds: 60
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

jest.mock('../../utils/jwt', () => ({
  generateTokenPair: jest.fn().mockResolvedValue({
    access_token: 'mock-access-token',
    refresh_token: 'mock-refresh-token',
    expires_in: 900
  })
}));

jest.mock('../../services/encryption.service', () => ({
  encryptData: jest.fn().mockResolvedValue({ encrypted: 'data', iv: 'iv' }),
  decryptData: jest.fn()
}));

// Import handlers AFTER mocks
import { handler as loginHandler } from '../../handlers/login-handler';
import { mfaLoginVerifyHandler } from '../../handlers/mfa-handler';
import { findUserByEmail, findUserById } from '../../repositories/user.repository';
import { checkRateLimit } from '../../services/ratelimit.service';
import { decryptData } from '../../services/encryption.service';
import { generateTOTPSecret, generateTOTP, hashBackupCodes, generateBackupCodes } from '../../services/mfa.service';

const mockUserWithoutMFA = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  email_verified: true,
  password_hash: '$argon2id$v=19$m=32768,t=5,p=2$hash',
  profile: { first_name: 'Ayşe', last_name: 'Yılmaz' },
  status: 'active',
  mfa_enabled: false,
  failed_login_attempts: 0
};

const mfaSecret = generateTOTPSecret();
const backupCodes = generateBackupCodes();
const hashedBackupCodes = hashBackupCodes(backupCodes);

const mockUserWithMFA = {
  ...mockUserWithoutMFA,
  mfa_enabled: true,
  mfa_secret: JSON.stringify({ encrypted: mfaSecret, iv: 'test-iv' }),
  backup_codes: hashedBackupCodes
};

function createLoginEvent(body: object, ip: string = '192.168.1.1'): APIGatewayProxyEvent {
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
      identity: { sourceIp: ip }
    } as any,
    resource: '/v1/auth/login',
    multiValueHeaders: {}
  };
}

function createMfaVerifyEvent(body: object, ip: string = '192.168.1.1'): APIGatewayProxyEvent {
  return {
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Test-Agent/1.0'
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/mfa/login/verify',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: ip }
    } as any,
    resource: '/v1/auth/mfa/login/verify',
    multiValueHeaders: {}
  };
}

describe('MFA Login Flow E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (findUserByEmail as jest.Mock).mockResolvedValue(mockUserWithMFA);
    (findUserById as jest.Mock).mockResolvedValue(mockUserWithMFA);
    (decryptData as jest.Mock).mockResolvedValue(mfaSecret);
  });

  describe('Login with MFA Enabled', () => {
    it('should return mfa_required when user has MFA enabled', async () => {
      const event = createLoginEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await loginHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.mfa_required).toBe(true);
      expect(body.mfa_session_id).toBeDefined();
      expect(body.mfa_session_id).toHaveLength(64); // 32 bytes hex
      expect(body.mfa_expires_in).toBe(300); // 5 minutes
      expect(body.tokens).toBeUndefined(); // No tokens yet
    });

    it('should return user info in MFA challenge response', async () => {
      const event = createLoginEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await loginHandler(event);
      const body = JSON.parse(response.body);

      expect(body.user.id).toBe('user-123');
      expect(body.user.email).toBe('dr.ayse@example.com');
    });

    it('should return tokens directly when MFA not enabled', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(mockUserWithoutMFA);

      const event = createLoginEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const response = await loginHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.mfa_required).toBeUndefined();
      expect(body.tokens).toBeDefined();
      expect(body.tokens.access_token).toBe('mock-access-token');
    });
  });

  describe('MFA Verify Handler', () => {
    let mfaSessionId: string;

    beforeEach(async () => {
      // First login to get MFA session
      const loginEvent = createLoginEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const loginResponse = await loginHandler(loginEvent);
      const loginBody = JSON.parse(loginResponse.body);
      mfaSessionId = loginBody.mfa_session_id;
    });

    it('should verify TOTP code and return tokens', async () => {
      const code = generateTOTP(mfaSecret);
      
      const event = createMfaVerifyEvent({
        mfa_session_id: mfaSessionId,
        code
      });

      const response = await mfaLoginVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('MFA verification successful');
      expect(body.tokens).toBeDefined();
      expect(body.tokens.access_token).toBe('mock-access-token');
      expect(body.tokens.refresh_token).toBe('mock-refresh-token');
    });

    it('should reject invalid TOTP code', async () => {
      const event = createMfaVerifyEvent({
        mfa_session_id: mfaSessionId,
        code: '000000'
      });

      const response = await mfaLoginVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_MFA_CODE');
    });

    it('should accept backup code', async () => {
      const event = createMfaVerifyEvent({
        mfa_session_id: mfaSessionId,
        code: backupCodes[0]
      });

      const response = await mfaLoginVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.used_backup_code).toBe(true);
    });

    it('should reject expired MFA session', async () => {
      const event = createMfaVerifyEvent({
        mfa_session_id: 'expired-or-invalid-session',
        code: '123456'
      });

      const response = await mfaLoginVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('MFA_SESSION_EXPIRED');
    });

    it('should reject missing mfa_session_id', async () => {
      const event = createMfaVerifyEvent({
        code: '123456'
      });

      const response = await mfaLoginVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject missing code', async () => {
      const event = createMfaVerifyEvent({
        mfa_session_id: mfaSessionId
      });

      const response = await mfaLoginVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });
  });

  describe('MFA Rate Limiting', () => {
    let mfaSessionId: string;

    beforeEach(async () => {
      const loginEvent = createLoginEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      const loginResponse = await loginHandler(loginEvent);
      const loginBody = JSON.parse(loginResponse.body);
      mfaSessionId = loginBody.mfa_session_id;
    });

    it('should rate limit MFA verify attempts', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValueOnce({
        allowed: false,
        remaining: 0,
        resetAt: Math.floor(Date.now() / 1000) + 60,
        retryAfter: 60
      });

      const event = createMfaVerifyEvent({
        mfa_session_id: mfaSessionId,
        code: '123456'
      });

      const response = await mfaLoginVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });
  });

  describe('Security Logging', () => {
    it('should log MFA challenge issued', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');

      const event = createLoginEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });

      await loginHandler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'mfa_challenge_issued'
        })
      );
    });

    it('should log MFA verify success', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');

      // First login
      const loginEvent = createLoginEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });
      const loginResponse = await loginHandler(loginEvent);
      const { mfa_session_id } = JSON.parse(loginResponse.body);

      // Then verify
      const code = generateTOTP(mfaSecret);
      const verifyEvent = createMfaVerifyEvent({
        mfa_session_id,
        code
      });

      await mfaLoginVerifyHandler(verifyEvent);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'mfa_verify_success'
        })
      );
    });

    it('should log MFA verify failure', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');

      // First login
      const loginEvent = createLoginEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com',
        password: 'GüvenliŞifre123!'
      });
      const loginResponse = await loginHandler(loginEvent);
      const { mfa_session_id } = JSON.parse(loginResponse.body);

      // Then verify with wrong code
      const verifyEvent = createMfaVerifyEvent({
        mfa_session_id,
        code: '000000'
      });

      await mfaLoginVerifyHandler(verifyEvent);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'mfa_verify_failure'
        })
      );
    });
  });
});
