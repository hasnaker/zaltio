/**
 * WebAuthn Handler E2E Tests
 * 
 * Task 2.6: WebAuthn Handler
 * Validates: Requirements 2.2 (MFA - WebAuthn)
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
  findUserByEmail: jest.fn(),
  updateUserWebAuthn: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('../../repositories/realm.repository', () => ({
  getRealmSettings: jest.fn().mockResolvedValue({
    session_timeout: 900,
    mfa_policy: 'optional'
  })
}));

jest.mock('../../repositories/session.repository', () => ({
  createSession: jest.fn().mockResolvedValue({ id: 'session-123' })
}));

jest.mock('../../utils/password', () => ({
  verifyPassword: jest.fn().mockResolvedValue(true)
}));

jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

// Import handlers AFTER mocks
import {
  webauthnRegisterOptionsHandler,
  webauthnRegisterVerifyHandler,
  webauthnListCredentialsHandler,
  webauthnDeleteCredentialHandler,
  webauthnAuthenticateOptionsHandler
} from '../../handlers/webauthn-handler';
import { verifyAccessToken } from '../../utils/jwt';
import { findUserById, findUserByEmail, updateUserWebAuthn } from '../../repositories/user.repository';
import { verifyPassword } from '../../utils/password';

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
  profile: { first_name: 'Ayşe', last_name: 'Yılmaz' },
  status: 'active',
  webauthn_credentials: []
};

const mockCredential = {
  id: 'credential-id-123',
  credentialId: Buffer.from('credential-id-123'),
  publicKey: Buffer.from('public-key-data'),
  counter: 5,
  transports: ['internal'],
  createdAt: '2026-01-15T00:00:00.000Z',
  deviceName: 'MacBook Pro Touch ID'
};

function createMockEvent(
  body: object | null = null,
  accessToken: string = 'valid-access-token',
  pathParameters: Record<string, string> | null = null
): APIGatewayProxyEvent {
  return {
    body: body ? JSON.stringify(body) : null,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
      'User-Agent': 'Test-Agent/1.0'
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/webauthn/register/options',
    pathParameters,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '/v1/auth/webauthn/register/options',
    multiValueHeaders: {}
  };
}

describe('WebAuthn Handler E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (verifyAccessToken as jest.Mock).mockResolvedValue(mockPayload);
    (findUserById as jest.Mock).mockResolvedValue(mockUser);
    (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);
  });

  describe('Register Options Handler', () => {
    it('should return registration options', async () => {
      const event = createMockEvent();

      const response = await webauthnRegisterOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.options).toBeDefined();
      expect(body.options.challenge).toBeDefined();
      expect(body.options.rp).toBeDefined();
      expect(body.options.user).toBeDefined();
      expect(body.expires_in).toBe(300);
    });

    it('should include RP information', async () => {
      const event = createMockEvent();

      const response = await webauthnRegisterOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(body.options.rp.name).toBe('Zalt.io');
      expect(body.options.rp.id).toBe('zalt.io');
    });

    it('should include user information', async () => {
      const event = createMockEvent();

      const response = await webauthnRegisterOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(body.options.user.name).toBe('dr.ayse@example.com');
      expect(body.options.user.displayName).toBe('Ayşe Yılmaz');
    });

    it('should reject without authorization', async () => {
      const event = {
        ...createMockEvent(),
        headers: { 'Content-Type': 'application/json' }
      };

      const response = await webauthnRegisterOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject when max credentials reached', async () => {
      const maxCredentials = Array(10).fill(mockCredential);
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        webauthn_credentials: maxCredentials
      });

      const event = createMockEvent();

      const response = await webauthnRegisterOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('MAX_CREDENTIALS_REACHED');
    });

    it('should exclude existing credentials', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        webauthn_credentials: [mockCredential]
      });

      const event = createMockEvent();

      const response = await webauthnRegisterOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(body.options.excludeCredentials).toBeDefined();
      expect(body.options.excludeCredentials).toHaveLength(1);
    });
  });

  describe('List Credentials Handler', () => {
    it('should return empty list when no credentials', async () => {
      const event = createMockEvent();

      const response = await webauthnListCredentialsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.credentials).toEqual([]);
      expect(body.count).toBe(0);
      expect(body.max_allowed).toBe(10);
    });

    it('should return credentials list', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        webauthn_credentials: [mockCredential]
      });

      const event = createMockEvent();

      const response = await webauthnListCredentialsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.credentials).toHaveLength(1);
      expect(body.credentials[0].id).toBe('credential-id-123');
      expect(body.credentials[0].deviceName).toBe('MacBook Pro Touch ID');
    });

    it('should not expose public keys', async () => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        webauthn_credentials: [mockCredential]
      });

      const event = createMockEvent();

      const response = await webauthnListCredentialsHandler(event);
      const body = JSON.parse(response.body);

      expect(body.credentials[0].publicKey).toBeUndefined();
      expect(body.credentials[0].credentialId).toBeUndefined();
    });

    it('should reject without authorization', async () => {
      const event = {
        ...createMockEvent(),
        headers: { 'Content-Type': 'application/json' }
      };

      const response = await webauthnListCredentialsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('Delete Credential Handler', () => {
    beforeEach(() => {
      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        webauthn_credentials: [mockCredential]
      });
    });

    it('should delete credential with valid password', async () => {
      const event = createMockEvent(
        { password: 'ValidPassword123!' },
        'valid-token',
        { id: 'credential-id-123' }
      );

      const response = await webauthnDeleteCredentialHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Credential deleted successfully');
      expect(updateUserWebAuthn).toHaveBeenCalled();
    });

    it('should reject invalid password', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent(
        { password: 'WrongPassword!' },
        'valid-token',
        { id: 'credential-id-123' }
      );

      const response = await webauthnDeleteCredentialHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });

    it('should reject missing password', async () => {
      const event = createMockEvent(
        {},
        'valid-token',
        { id: 'credential-id-123' }
      );

      const response = await webauthnDeleteCredentialHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject non-existent credential', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(true);
      
      const event = createMockEvent(
        { password: 'ValidPassword123!' },
        'valid-token',
        { id: 'non-existent-credential' }
      );

      const response = await webauthnDeleteCredentialHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('CREDENTIAL_NOT_FOUND');
    });
  });

  describe('Authenticate Options Handler', () => {
    it('should return authentication options', async () => {
      (findUserByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        webauthn_credentials: [mockCredential]
      });

      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com'
      });

      const response = await webauthnAuthenticateOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.options).toBeDefined();
      expect(body.options.challenge).toBeDefined();
      expect(body.options.allowCredentials).toHaveLength(1);
    });

    it('should return null options when no credentials', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists',
        email: 'dr.ayse@example.com'
      });

      const response = await webauthnAuthenticateOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.options).toBeNull();
      expect(body.message).toBe('No WebAuthn credentials registered');
    });

    it('should reject missing realm_id', async () => {
      const event = createMockEvent({
        email: 'dr.ayse@example.com'
      });

      const response = await webauthnAuthenticateOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject missing email', async () => {
      const event = createMockEvent({
        realm_id: 'clinisyn-psychologists'
      });

      const response = await webauthnAuthenticateOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });
  });

  describe('Security Logging', () => {
    it('should log registration options request', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');

      const event = createMockEvent();
      await webauthnRegisterOptionsHandler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'webauthn_register_options'
        })
      );
    });
  });

  describe('Security: Max Credentials Limit', () => {
    it('should enforce 10 credential limit', async () => {
      const maxCredentials = Array(10).fill(mockCredential).map((c, i) => ({
        ...c,
        id: `credential-${i}`
      }));

      (findUserById as jest.Mock).mockResolvedValue({
        ...mockUser,
        webauthn_credentials: maxCredentials
      });

      const event = createMockEvent();

      const response = await webauthnRegisterOptionsHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('MAX_CREDENTIALS_REACHED');
    });
  });
});
