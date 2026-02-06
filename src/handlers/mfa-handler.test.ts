/**
 * MFA Handler Tests
 * Tests for backup codes regeneration and status endpoints
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { 
  regenerateBackupCodesHandler, 
  getBackupCodesStatusHandler,
  verifyMFACode
} from './mfa-handler';

// Mock dependencies
jest.mock('../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../repositories/user.repository', () => ({
  findUserById: jest.fn(),
  updateUserMFA: jest.fn()
}));

jest.mock('../utils/password', () => ({
  verifyPassword: jest.fn()
}));

jest.mock('../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('../services/encryption.service', () => ({
  encryptData: jest.fn().mockResolvedValue({ encrypted: 'data' }),
  decryptData: jest.fn().mockResolvedValue('JBSWY3DPEHPK3PXP')
}));

import { verifyAccessToken } from '../utils/jwt';
import { findUserById, updateUserMFA } from '../repositories/user.repository';
import { verifyPassword } from '../utils/password';

const mockVerifyAccessToken = verifyAccessToken as jest.Mock;
const mockFindUserById = findUserById as jest.Mock;
const mockUpdateUserMFA = updateUserMFA as jest.Mock;
const mockVerifyPassword = verifyPassword as jest.Mock;

describe('MFA Handler - Backup Codes', () => {
  const mockEvent = (body: object, authHeader = 'Bearer valid-token'): APIGatewayProxyEvent => ({
    body: JSON.stringify(body),
    headers: { Authorization: authHeader },
    requestContext: { requestId: 'test-request-id' } as any,
    httpMethod: 'POST',
    path: '/v1/auth/mfa/backup-codes/regenerate',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    resource: '',
    multiValueHeaders: {},
    isBase64Encoded: false
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'user-123',
      realm_id: 'test-realm',
      email: 'test@example.com'
    });
  });

  describe('regenerateBackupCodesHandler', () => {
    it('should regenerate backup codes with valid password', async () => {
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: true,
        mfa_secret: JSON.stringify({ encrypted: 'secret' }),
        password_hash: 'hashed-password',
        backup_codes: ['old-code-hash-1', 'old-code-hash-2']
      });
      mockVerifyPassword.mockResolvedValue(true);
      mockUpdateUserMFA.mockResolvedValue(undefined);

      const event = mockEvent({ password: 'correct-password' });
      const result = await regenerateBackupCodesHandler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.backup_codes).toHaveLength(8);
      expect(body.message).toContain('regenerated successfully');
      expect(body.warning).toContain('previous backup codes have been invalidated');
      expect(mockUpdateUserMFA).toHaveBeenCalled();
    });

    it('should reject without authorization', async () => {
      const event = mockEvent({ password: 'test' }, '');
      const result = await regenerateBackupCodesHandler(event);

      expect(result.statusCode).toBe(401);
      expect(JSON.parse(result.body).error.code).toBe('UNAUTHORIZED');
    });

    it('should reject without password', async () => {
      const event = mockEvent({});
      const result = await regenerateBackupCodesHandler(event);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).error.code).toBe('INVALID_REQUEST');
    });

    it('should reject if MFA not enabled', async () => {
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: false,
        password_hash: 'hashed-password'
      });

      const event = mockEvent({ password: 'test' });
      const result = await regenerateBackupCodesHandler(event);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).error.code).toBe('MFA_NOT_ENABLED');
    });

    it('should reject with invalid password', async () => {
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: true,
        mfa_secret: JSON.stringify({ encrypted: 'secret' }),
        password_hash: 'hashed-password'
      });
      mockVerifyPassword.mockResolvedValue(false);

      const event = mockEvent({ password: 'wrong-password' });
      const result = await regenerateBackupCodesHandler(event);

      expect(result.statusCode).toBe(401);
      expect(JSON.parse(result.body).error.code).toBe('INVALID_PASSWORD');
    });
  });

  describe('getBackupCodesStatusHandler', () => {
    const mockGetEvent = (authHeader = 'Bearer valid-token'): APIGatewayProxyEvent => ({
      body: null,
      headers: { Authorization: authHeader },
      requestContext: { requestId: 'test-request-id' } as any,
      httpMethod: 'GET',
      path: '/v1/auth/mfa/backup-codes/status',
      pathParameters: null,
      queryStringParameters: null,
      multiValueQueryStringParameters: null,
      stageVariables: null,
      resource: '',
      multiValueHeaders: {},
      isBase64Encoded: false
    });

    it('should return backup codes status', async () => {
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: true,
        backup_codes: ['code1', 'code2', 'code3', 'code4', 'code5']
      });

      const event = mockGetEvent();
      const result = await getBackupCodesStatusHandler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.remaining_codes).toBe(5);
      expect(body.total_codes).toBe(8);
      expect(body.warning).toBeNull();
      expect(body.should_regenerate).toBe(false);
    });

    it('should warn when 2 or fewer codes remain', async () => {
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: true,
        backup_codes: ['code1', 'code2']
      });

      const event = mockGetEvent();
      const result = await getBackupCodesStatusHandler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.remaining_codes).toBe(2);
      expect(body.warning).toContain('Only 2 backup codes remaining');
    });

    it('should indicate regeneration needed when no codes remain', async () => {
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: true,
        backup_codes: []
      });

      const event = mockGetEvent();
      const result = await getBackupCodesStatusHandler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.remaining_codes).toBe(0);
      expect(body.should_regenerate).toBe(true);
    });

    it('should reject if MFA not enabled', async () => {
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: false
      });

      const event = mockGetEvent();
      const result = await getBackupCodesStatusHandler(event);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).error.code).toBe('MFA_NOT_ENABLED');
    });
  });

  describe('verifyMFACode - backup codes warning', () => {
    it('should return warning when backup codes are low after use', async () => {
      // Mock user with 3 backup codes (will be 2 after use)
      const codeToUse = 'TESTCODE';
      const codeHash = require('crypto').createHash('sha256').update(codeToUse).digest('hex');
      
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: true,
        mfa_secret: JSON.stringify({ encrypted: 'secret' }),
        backup_codes: [codeHash, 'other-hash-1', 'other-hash-2']
      });
      mockUpdateUserMFA.mockResolvedValue(undefined);

      const result = await verifyMFACode('user-123', 'test-realm', codeToUse);

      expect(result.valid).toBe(true);
      expect(result.usedBackupCode).toBe(true);
      expect(result.remainingBackupCodes).toBe(2);
      expect(result.backupCodesWarning).toContain('Only 2 backup codes remaining');
    });

    it('should return critical warning when last backup code is used', async () => {
      const codeToUse = 'LASTCODE';
      const codeHash = require('crypto').createHash('sha256').update(codeToUse).digest('hex');
      
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'test@example.com',
        mfa_enabled: true,
        mfa_secret: JSON.stringify({ encrypted: 'secret' }),
        backup_codes: [codeHash]
      });
      mockUpdateUserMFA.mockResolvedValue(undefined);

      const result = await verifyMFACode('user-123', 'test-realm', codeToUse);

      expect(result.valid).toBe(true);
      expect(result.usedBackupCode).toBe(true);
      expect(result.remainingBackupCodes).toBe(0);
      expect(result.backupCodesWarning).toContain('All backup codes have been used');
    });
  });
});
