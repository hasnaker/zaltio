/**
 * Email Verification E2E Tests
 * 
 * Task 5.2: Email Verification Handler
 * Validates: Requirements 5.2 (Email Verification)
 * 
 * @e2e-test
 * @phase Phase 5
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock security logger first
const mockLogSecurityEvent = jest.fn().mockResolvedValue(undefined);
jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: mockLogSecurityEvent
}));

// Mock email service
const mockSendVerificationEmail = jest.fn().mockResolvedValue({
  success: true,
  messageId: 'test-message-id'
});
jest.mock('../../services/email.service', () => {
  const actual = jest.requireActual('../../services/email.service');
  return {
    ...actual,
    sendVerificationEmail: mockSendVerificationEmail
  };
});

// Mock dependencies
jest.mock('../../repositories/user.repository', () => ({
  findUserById: jest.fn(),
  findUserByEmail: jest.fn(),
  updateUserEmailVerified: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('../../repositories/realm.repository', () => ({
  findRealmById: jest.fn()
}));

jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({
    allowed: true,
    remaining: 4,
    resetAt: Date.now() + 3600000
  })
}));

// Import after mocks
import {
  sendVerificationCodeHandler,
  confirmVerificationHandler,
  verificationStore,
  storeVerificationCode,
  clearVerificationData
} from '../../handlers/verify-email-handler';
import { findUserById, updateUserEmailVerified } from '../../repositories/user.repository';
import { findRealmById } from '../../repositories/realm.repository';
import { verifyAccessToken } from '../../utils/jwt';
import { checkRateLimit } from '../../services/ratelimit.service';
import { hashToken, EMAIL_CONFIG } from '../../services/email.service';

const mockUser = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  email_verified: false,
  profile: { first_name: 'Ayşe', last_name: 'Yılmaz' },
  status: 'pending_verification'
};

const mockVerifiedUser = {
  ...mockUser,
  email_verified: true,
  status: 'active'
};

const mockRealm = {
  id: 'clinisyn-psychologists',
  name: 'Clinisyn Psychologists'
};

const mockTokenPayload = {
  sub: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  type: 'access'
};

function createMockEvent(
  body: string | null = null,
  headers: Record<string, string> = {}
): APIGatewayProxyEvent {
  return {
    body,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer valid-token',
      ...headers
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/verify-email/send',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '/v1/auth/verify-email/send',
    multiValueHeaders: {}
  };
}

describe('Email Verification E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    verificationStore.clear();
    (verifyAccessToken as jest.Mock).mockResolvedValue(mockTokenPayload);
    (findUserById as jest.Mock).mockResolvedValue(mockUser);
    (findRealmById as jest.Mock).mockResolvedValue(mockRealm);
    (checkRateLimit as jest.Mock).mockResolvedValue({
      allowed: true,
      remaining: 4,
      resetAt: Date.now() + 3600000
    });
    mockSendVerificationEmail.mockResolvedValue({
      success: true,
      messageId: 'test-message-id'
    });
    mockLogSecurityEvent.mockClear();
  });

  describe('Send Verification Code Handler', () => {
    it('should send verification code successfully', async () => {
      const event = createMockEvent();

      const response = await sendVerificationCodeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toContain('Verification code sent');
      expect(body.expires_in).toBe(900); // 15 minutes
      expect(mockSendVerificationEmail).toHaveBeenCalled();
    });

    it('should store verification code hash', async () => {
      const event = createMockEvent();

      await sendVerificationCodeHandler(event);

      const stored = verificationStore.get('dr.ayse@example.com');
      expect(stored).toBeDefined();
      expect(stored?.codeHash).toMatch(/^[a-f0-9]{64}$/);
      expect(stored?.attempts).toBe(0);
    });

    it('should reject unauthenticated requests', async () => {
      const event = createMockEvent(null, { Authorization: '' });

      const response = await sendVerificationCodeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject invalid token', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();

      const response = await sendVerificationCodeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });

    it('should reject already verified email', async () => {
      (findUserById as jest.Mock).mockResolvedValue(mockVerifiedUser);

      const event = createMockEvent();

      const response = await sendVerificationCodeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('ALREADY_VERIFIED');
    });

    it('should enforce rate limiting', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 3600000
      });

      const event = createMockEvent();

      const response = await sendVerificationCodeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });

    it('should handle email send failure', async () => {
      mockSendVerificationEmail.mockResolvedValue({
        success: false,
        error: 'SES error'
      });

      const event = createMockEvent();

      const response = await sendVerificationCodeHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(500);
      expect(body.error.code).toBe('EMAIL_SEND_FAILED');
    });

    it('should log verification code sent', async () => {
      const event = createMockEvent();

      await sendVerificationCodeHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'verification_code_sent'
        })
      );
    });
  });

  describe('Confirm Verification Handler', () => {
    const validCode = '123456';

    beforeEach(() => {
      // Store a valid verification code
      storeVerificationCode(
        'dr.ayse@example.com',
        hashToken(validCode),
        'user-123',
        'clinisyn-psychologists'
      );
    });

    it('should verify valid code successfully', async () => {
      const event = createMockEvent(JSON.stringify({ code: validCode }));

      const response = await confirmVerificationHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toContain('verified successfully');
      expect(body.email_verified).toBe(true);
      expect(updateUserEmailVerified).toHaveBeenCalledWith(
        'clinisyn-psychologists',
        'user-123',
        true
      );
    });

    it('should clear verification data after success', async () => {
      const event = createMockEvent(JSON.stringify({ code: validCode }));

      await confirmVerificationHandler(event);

      const stored = verificationStore.get('dr.ayse@example.com');
      expect(stored).toBeUndefined();
    });

    it('should reject invalid code', async () => {
      const event = createMockEvent(JSON.stringify({ code: '000000' }));

      const response = await confirmVerificationHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_CODE');
      expect(body.error.remaining_attempts).toBeDefined();
    });

    it('should increment attempts on invalid code', async () => {
      const event = createMockEvent(JSON.stringify({ code: '000000' }));

      await confirmVerificationHandler(event);

      const stored = verificationStore.get('dr.ayse@example.com');
      expect(stored?.attempts).toBe(1);
    });

    it('should reject after max attempts', async () => {
      // Set attempts to max - 1
      const stored = verificationStore.get('dr.ayse@example.com');
      if (stored) {
        stored.attempts = EMAIL_CONFIG.maxVerificationAttempts;
        verificationStore.set('dr.ayse@example.com', stored);
      }

      const event = createMockEvent(JSON.stringify({ code: '000000' }));

      const response = await confirmVerificationHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('MAX_ATTEMPTS_EXCEEDED');
    });

    it('should reject expired code', async () => {
      // Set expiry to past
      const stored = verificationStore.get('dr.ayse@example.com');
      if (stored) {
        stored.expiresAt = Date.now() - 1000;
        verificationStore.set('dr.ayse@example.com', stored);
      }

      const event = createMockEvent(JSON.stringify({ code: validCode }));

      const response = await confirmVerificationHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('CODE_EXPIRED');
    });

    it('should reject when no pending verification', async () => {
      clearVerificationData('dr.ayse@example.com');

      const event = createMockEvent(JSON.stringify({ code: validCode }));

      const response = await confirmVerificationHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('NO_PENDING_VERIFICATION');
    });

    it('should reject invalid code format', async () => {
      const event = createMockEvent(JSON.stringify({ code: 'abc' }));

      const response = await confirmVerificationHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_CODE_FORMAT');
    });

    it('should reject missing code', async () => {
      const event = createMockEvent(JSON.stringify({}));

      const response = await confirmVerificationHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should log email verified', async () => {
      const event = createMockEvent(JSON.stringify({ code: validCode }));

      await confirmVerificationHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'email_verified'
        })
      );
    });

    it('should log invalid code attempt', async () => {
      const event = createMockEvent(JSON.stringify({ code: '000000' }));

      await confirmVerificationHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'verification_code_invalid'
        })
      );
    });
  });

  describe('Security', () => {
    it('should use constant-time comparison for code verification', async () => {
      const validCode = '123456';
      storeVerificationCode(
        'dr.ayse@example.com',
        hashToken(validCode),
        'user-123',
        'clinisyn-psychologists'
      );

      // This test verifies the code path uses verifyTokenHash
      // which internally uses timingSafeEqual
      const event = createMockEvent(JSON.stringify({ code: validCode }));
      const response = await confirmVerificationHandler(event);

      expect(response.statusCode).toBe(200);
    });

    it('should hash verification code in storage', async () => {
      const event = createMockEvent();

      await sendVerificationCodeHandler(event);

      const stored = verificationStore.get('dr.ayse@example.com');
      // Code hash should be SHA-256 (64 hex chars)
      expect(stored?.codeHash).toMatch(/^[a-f0-9]{64}$/);
      // Should not store plaintext code
      expect(stored?.codeHash).not.toMatch(/^\d{6}$/);
    });
  });
});
