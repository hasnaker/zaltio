/**
 * Password Reset E2E Tests
 * 
 * Task 5.3: Password Reset Handler
 * Validates: Requirements 5.3 (Password Reset)
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
const mockSendPasswordResetEmail = jest.fn().mockResolvedValue({
  success: true,
  messageId: 'test-message-id'
});
jest.mock('../../services/email.service', () => {
  const actual = jest.requireActual('../../services/email.service');
  return {
    ...actual,
    sendPasswordResetEmail: mockSendPasswordResetEmail
  };
});

// Mock dependencies
jest.mock('../../repositories/user.repository', () => ({
  findUserByEmail: jest.fn(),
  updateUserPassword: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('../../repositories/session.repository', () => ({
  deleteUserSessions: jest.fn().mockResolvedValue(3)
}));

jest.mock('../../repositories/realm.repository', () => ({
  findRealmById: jest.fn()
}));

jest.mock('../../utils/password', () => ({
  hashPassword: jest.fn().mockResolvedValue('$argon2id$hashed'),
  validatePasswordPolicy: jest.fn().mockReturnValue({ valid: true }),
  checkPasswordPwned: jest.fn().mockResolvedValue(0)
}));

jest.mock('../../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({
    allowed: true,
    remaining: 2,
    resetAt: Date.now() + 3600000
  })
}));

// Import after mocks
import {
  requestPasswordResetHandler,
  confirmPasswordResetHandler,
  resetTokenStore,
  storeResetToken,
  clearResetToken
} from '../../handlers/password-reset-handler';
import { findUserByEmail, updateUserPassword } from '../../repositories/user.repository';
import { deleteUserSessions } from '../../repositories/session.repository';
import { findRealmById } from '../../repositories/realm.repository';
import { validatePasswordPolicy, checkPasswordPwned } from '../../utils/password';
import { checkRateLimit } from '../../services/ratelimit.service';
import { hashToken, EMAIL_CONFIG } from '../../services/email.service';

const mockUser = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  email_verified: true,
  password_hash: '$argon2id$old-hash',
  profile: { first_name: 'Ayşe', last_name: 'Yılmaz' },
  status: 'active'
};

const mockRealm = {
  id: 'clinisyn-psychologists',
  name: 'Clinisyn Psychologists',
  domain: 'clinisyn.zalt.io'
};

function createMockEvent(
  body: string | null = null
): APIGatewayProxyEvent {
  return {
    body,
    headers: {
      'Content-Type': 'application/json'
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/password-reset/request',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '/v1/auth/password-reset/request',
    multiValueHeaders: {}
  };
}

describe('Password Reset E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetTokenStore.clear();
    (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);
    (findRealmById as jest.Mock).mockResolvedValue(mockRealm);
    (checkRateLimit as jest.Mock).mockResolvedValue({
      allowed: true,
      remaining: 2,
      resetAt: Date.now() + 3600000
    });
    (validatePasswordPolicy as jest.Mock).mockReturnValue({ valid: true });
    (checkPasswordPwned as jest.Mock).mockResolvedValue(0);
    mockSendPasswordResetEmail.mockResolvedValue({
      success: true,
      messageId: 'test-message-id'
    });
    mockLogSecurityEvent.mockClear();
  });

  describe('Request Password Reset Handler', () => {
    it('should send reset email for valid user', async () => {
      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com'
      }));

      const response = await requestPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toContain('password reset link has been sent');
      expect(mockSendPasswordResetEmail).toHaveBeenCalled();
    });

    it('should return same response for non-existent user (no enumeration)', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        email: 'nonexistent@example.com'
      }));

      const response = await requestPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toContain('password reset link has been sent');
      // Email should NOT be sent for non-existent user
      expect(mockSendPasswordResetEmail).not.toHaveBeenCalled();
    });

    it('should store reset token hash', async () => {
      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com'
      }));

      await requestPasswordResetHandler(event);

      expect(resetTokenStore.size).toBe(1);
      const stored = Array.from(resetTokenStore.values())[0];
      expect(stored.tokenHash).toMatch(/^[a-f0-9]{64}$/);
      expect(stored.used).toBe(false);
    });

    it('should enforce rate limiting', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 3600000
      });

      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com'
      }));

      const response = await requestPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      // Still returns 200 to prevent enumeration
      expect(response.statusCode).toBe(200);
      expect(mockSendPasswordResetEmail).not.toHaveBeenCalled();
    });

    it('should reject invalid email format', async () => {
      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        email: 'invalid-email'
      }));

      const response = await requestPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_EMAIL');
    });

    it('should reject missing fields', async () => {
      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists'
      }));

      const response = await requestPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should log password reset request', async () => {
      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com'
      }));

      await requestPasswordResetHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'password_reset_requested'
        })
      );
    });
  });

  describe('Confirm Password Reset Handler', () => {
    const validToken = 'a'.repeat(64);

    beforeEach(() => {
      // Store a valid reset token
      storeResetToken(
        validToken,
        hashToken(validToken),
        'user-123',
        'clinisyn-psychologists',
        'dr.ayse@example.com'
      );
    });

    it('should reset password with valid token', async () => {
      const event = createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'NewSecurePassword123!'
      }));

      const response = await confirmPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toContain('reset successfully');
      expect(body.sessions_invalidated).toBe(true);
      expect(updateUserPassword).toHaveBeenCalled();
    });

    it('should invalidate all sessions after password reset', async () => {
      const event = createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'NewSecurePassword123!'
      }));

      await confirmPasswordResetHandler(event);

      expect(deleteUserSessions).toHaveBeenCalledWith(
        'clinisyn-psychologists',
        'user-123'
      );
    });

    it('should mark token as used', async () => {
      const event = createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'NewSecurePassword123!'
      }));

      await confirmPasswordResetHandler(event);

      const stored = resetTokenStore.get(validToken);
      expect(stored?.used).toBe(true);
    });

    it('should reject already used token', async () => {
      // First use
      await confirmPasswordResetHandler(createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'NewSecurePassword123!'
      })));

      // Second use
      const response = await confirmPasswordResetHandler(createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'AnotherPassword123!'
      })));
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('TOKEN_ALREADY_USED');
    });

    it('should reject invalid token', async () => {
      const event = createMockEvent(JSON.stringify({
        token: 'b'.repeat(64),
        new_password: 'NewSecurePassword123!'
      }));

      const response = await confirmPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });

    it('should reject expired token', async () => {
      // Set token to expired
      const stored = resetTokenStore.get(validToken);
      if (stored) {
        stored.expiresAt = Date.now() - 1000;
        resetTokenStore.set(validToken, stored);
      }

      const event = createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'NewSecurePassword123!'
      }));

      const response = await confirmPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('TOKEN_EXPIRED');
    });

    it('should reject invalid token format', async () => {
      const event = createMockEvent(JSON.stringify({
        token: 'short-token',
        new_password: 'NewSecurePassword123!'
      }));

      const response = await confirmPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_TOKEN_FORMAT');
    });

    it('should reject weak password', async () => {
      (validatePasswordPolicy as jest.Mock).mockReturnValue({
        valid: false,
        errors: ['Password must be at least 12 characters']
      });

      const event = createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'weak'
      }));

      const response = await confirmPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('WEAK_PASSWORD');
    });

    it('should reject compromised password (HaveIBeenPwned)', async () => {
      (checkPasswordPwned as jest.Mock).mockResolvedValue(1000);

      const event = createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'Password123!'
      }));

      const response = await confirmPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('PASSWORD_COMPROMISED');
      expect(body.details.breach_count).toBe(1000);
      expect(body.details.recommendation).toBe('Use a unique password with at least 12 characters');
      expect(body.error.timestamp).toBeDefined();
    });

    it('should reject missing fields', async () => {
      const event = createMockEvent(JSON.stringify({
        token: validToken
      }));

      const response = await confirmPasswordResetHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should log password reset success', async () => {
      const event = createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'NewSecurePassword123!'
      }));

      await confirmPasswordResetHandler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'password_reset_success'
        })
      );
    });
  });

  describe('Security', () => {
    it('should use constant-time comparison for token verification', async () => {
      const validToken = 'c'.repeat(64);
      storeResetToken(
        validToken,
        hashToken(validToken),
        'user-123',
        'clinisyn-psychologists',
        'dr.ayse@example.com'
      );

      const event = createMockEvent(JSON.stringify({
        token: validToken,
        new_password: 'NewSecurePassword123!'
      }));

      const response = await confirmPasswordResetHandler(event);
      expect(response.statusCode).toBe(200);
    });

    it('should hash reset token in storage', async () => {
      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com'
      }));

      await requestPasswordResetHandler(event);

      const stored = Array.from(resetTokenStore.values())[0];
      // Token hash should be SHA-256 (64 hex chars)
      expect(stored.tokenHash).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should generate 64-character hex token', async () => {
      const event = createMockEvent(JSON.stringify({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com'
      }));

      await requestPasswordResetHandler(event);

      const token = Array.from(resetTokenStore.keys())[0];
      expect(token).toMatch(/^[a-f0-9]{64}$/);
    });
  });
});
