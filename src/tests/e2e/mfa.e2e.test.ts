/**
 * MFA (Multi-Factor Authentication) E2E Tests
 * 
 * Task 2.1: TOTP MFA Service
 * Task 2.2: TOTP Setup Handler
 * Task 2.3: Backup Codes
 * Validates: Requirements 2.2
 * 
 * @e2e-test
 * @phase Phase 2
 * @security-critical
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: jest.fn(),
  generateTokenPair: jest.fn().mockResolvedValue({
    access_token: 'mock-access-token',
    refresh_token: 'mock-refresh-token',
    expires_in: 900
  })
}));

jest.mock('../../repositories/user.repository', () => ({
  findUserById: jest.fn(),
  updateUserMFA: jest.fn().mockResolvedValue(undefined),
  findUserByEmail: jest.fn(),
  updateUserLoginAttempts: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('../../repositories/realm.repository', () => ({
  findRealmById: jest.fn().mockResolvedValue({
    id: 'clinisyn-psychologists',
    name: 'Clinisyn',
    status: 'active'
  }),
  getRealmSettings: jest.fn().mockResolvedValue({
    session_timeout: 900,
    mfa_policy: 'optional'
  })
}));

jest.mock('../../repositories/session.repository', () => ({
  createSession: jest.fn().mockResolvedValue({ id: 'session-123' })
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

jest.mock('../../services/encryption.service', () => ({
  encryptData: jest.fn().mockResolvedValue({ encrypted: 'data', iv: 'iv' }),
  decryptData: jest.fn()
}));

jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

// Import handlers and services AFTER mocks
import { mfaSetupHandler, mfaVerifyHandler, mfaDisableHandler } from '../../handlers/mfa-handler';
import { verifyAccessToken } from '../../utils/jwt';
import { findUserById, updateUserMFA } from '../../repositories/user.repository';
import { verifyPassword } from '../../utils/password';
import { 
  generateTOTPSecret, 
  generateTOTP, 
  verifyTOTPCode,
  generateBackupCodes,
  hashBackupCodes,
  verifyBackupCode,
  generateQRCodeURL,
  TOTP_CONFIG
} from '../../services/mfa.service';

const mockPayload = {
  sub: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  type: 'access'
};

const mockUser = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  email_verified: true,
  password_hash: '$argon2id$v=19$m=32768,t=5,p=2$hash',
  mfa_enabled: false,
  mfa_secret: null,
  backup_codes: null,
  status: 'active'
};

function createMockEvent(
  body: object | null = null,
  accessToken: string = 'valid-access-token'
): APIGatewayProxyEvent {
  return {
    body: body ? JSON.stringify(body) : null,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/mfa/setup',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '/v1/auth/mfa/setup',
    multiValueHeaders: {}
  };
}

describe('MFA E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (verifyAccessToken as jest.Mock).mockResolvedValue(mockPayload);
    (findUserById as jest.Mock).mockResolvedValue(mockUser);
    (verifyPassword as jest.Mock).mockResolvedValue(true);
  });

  describe('TOTP Service Functions', () => {
    describe('Secret Generation', () => {
      it('should generate 20 byte base32 encoded secret', () => {
        const secret = generateTOTPSecret();
        
        expect(secret).toHaveLength(32);
        expect(secret).toMatch(/^[A-Z2-7]+$/);
      });

      it('should generate cryptographically random secrets', () => {
        const secrets = new Set<string>();
        for (let i = 0; i < 50; i++) {
          secrets.add(generateTOTPSecret());
        }
        expect(secrets.size).toBe(50);
      });
    });

    describe('TOTP Code Generation', () => {
      it('should generate 6 digit codes', () => {
        const secret = generateTOTPSecret();
        const code = generateTOTP(secret);
        
        expect(code).toMatch(/^\d{6}$/);
      });

      it('should be deterministic for same timestamp', () => {
        const secret = generateTOTPSecret();
        const timestamp = 1704067200;
        
        expect(generateTOTP(secret, timestamp)).toBe(generateTOTP(secret, timestamp));
      });
    });

    describe('TOTP Verification', () => {
      it('should verify correct code', () => {
        const secret = generateTOTPSecret();
        const code = generateTOTP(secret);
        
        expect(verifyTOTPCode(secret, code)).toBe(true);
      });

      it('should reject wrong code', () => {
        const secret = generateTOTPSecret();
        
        expect(verifyTOTPCode(secret, '000000')).toBe(false);
      });

      it('should accept code within 1 period window (clock drift)', () => {
        const secret = generateTOTPSecret();
        const now = Math.floor(Date.now() / 1000);
        
        // Previous period
        const prevCode = generateTOTP(secret, now - 30);
        expect(verifyTOTPCode(secret, prevCode)).toBe(true);
        
        // Next period
        const nextCode = generateTOTP(secret, now + 30);
        expect(verifyTOTPCode(secret, nextCode)).toBe(true);
      });
    });

    describe('QR Code URL', () => {
      it('should generate valid otpauth:// URL', () => {
        const secret = generateTOTPSecret();
        const url = generateQRCodeURL(secret, 'test@example.com');
        
        expect(url).toMatch(/^otpauth:\/\/totp\//);
        expect(url).toContain(secret);
        expect(url).toContain('issuer=');
        expect(url).toContain('algorithm=SHA1');
        expect(url).toContain('digits=6');
        expect(url).toContain('period=30');
      });
    });
  });

  describe('Backup Codes', () => {
    it('should generate 8 backup codes', () => {
      const codes = generateBackupCodes();
      
      expect(codes).toHaveLength(8);
    });

    it('should generate 8 character alphanumeric codes', () => {
      const codes = generateBackupCodes();
      
      codes.forEach(code => {
        expect(code).toHaveLength(8);
        expect(code).toMatch(/^[A-F0-9]+$/);
      });
    });

    it('should hash codes with SHA-256', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      hashed.forEach(hash => {
        expect(hash).toHaveLength(64); // SHA-256 = 64 hex chars
      });
    });

    it('should verify backup code correctly', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      const index = verifyBackupCode(codes[0], hashed);
      expect(index).toBe(0);
    });

    it('should be case insensitive for verification', () => {
      const codes = generateBackupCodes();
      const hashed = hashBackupCodes(codes);
      
      const index = verifyBackupCode(codes[0].toLowerCase(), hashed);
      expect(index).toBe(0);
    });
  });

  describe('MFA Setup Handler', () => {
    it('should return secret and QR code URL', async () => {
      const event = createMockEvent();

      const response = await mfaSetupHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.secret).toBeDefined();
      expect(body.secret).toHaveLength(32);
      expect(body.otpauth_url).toMatch(/^otpauth:\/\/totp\//);
    });

    it('should reject if MFA already enabled', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        mfa_enabled: true
      });

      const event = createMockEvent();

      const response = await mfaSetupHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('MFA_ALREADY_ENABLED');
    });

    it('should reject without authorization', async () => {
      const event = {
        ...createMockEvent(),
        headers: { 'Content-Type': 'application/json' }
      };

      const response = await mfaSetupHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject expired token', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(
        Object.assign(new Error('Token expired'), { name: 'TokenExpiredError' })
      );

      const event = createMockEvent();

      const response = await mfaSetupHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('TOKEN_EXPIRED');
    });
  });

  describe('MFA Verify Handler', () => {
    it('should enable MFA with valid code', async () => {
      const secret = generateTOTPSecret();
      const code = generateTOTP(secret);

      const event = createMockEvent({ secret, code });

      const response = await mfaVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('MFA enabled successfully');
      expect(body.backup_codes).toHaveLength(8);
      expect(body.warning).toContain('Save these backup codes');
    });

    it('should reject invalid code', async () => {
      const secret = generateTOTPSecret();

      const event = createMockEvent({ secret, code: '000000' });

      const response = await mfaVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_CODE');
    });

    it('should reject missing code', async () => {
      const secret = generateTOTPSecret();

      const event = createMockEvent({ secret });

      const response = await mfaVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject missing secret', async () => {
      const event = createMockEvent({ code: '123456' });

      const response = await mfaVerifyHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should call updateUserMFA on success', async () => {
      const secret = generateTOTPSecret();
      const code = generateTOTP(secret);

      const event = createMockEvent({ secret, code });

      await mfaVerifyHandler(event);

      expect(updateUserMFA).toHaveBeenCalledWith(
        'clinisyn-psychologists',
        'user-123',
        true,
        expect.any(String),
        expect.any(Array)
      );
    });
  });

  describe('MFA Disable Handler', () => {
    it('should disable MFA with valid password', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        mfa_enabled: true
      });

      const event = createMockEvent({ password: 'ValidPassword123!' });

      const response = await mfaDisableHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('MFA disabled successfully');
    });

    it('should reject invalid password', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent({ password: 'WrongPassword!' });

      const response = await mfaDisableHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });

    it('should reject missing password', async () => {
      const event = createMockEvent({});

      const response = await mfaDisableHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should call updateUserMFA to disable', async () => {
      const event = createMockEvent({ password: 'ValidPassword123!' });

      await mfaDisableHandler(event);

      expect(updateUserMFA).toHaveBeenCalledWith(
        'clinisyn-psychologists',
        'user-123',
        false
      );
    });
  });

  describe('Security Requirements', () => {
    it('should use SHA-1 algorithm (RFC 6238 compliant)', () => {
      expect(TOTP_CONFIG.algorithm).toBe('sha1');
    });

    it('should use 6 digit codes', () => {
      expect(TOTP_CONFIG.digits).toBe(6);
    });

    it('should use 30 second period', () => {
      expect(TOTP_CONFIG.period).toBe(30);
    });

    it('should allow 1 period window for clock drift', () => {
      expect(TOTP_CONFIG.window).toBe(1);
    });

    it('should use 20 byte (160 bit) secrets', () => {
      expect(TOTP_CONFIG.secretLength).toBe(20);
    });
  });
});
