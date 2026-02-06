/**
 * Tediyat Login Handler Tests
 * Property 4: Login Returns Complete Tenant List
 * Property 5: No Email Enumeration
 * 
 * Validates: Requirements 2.1-2.8
 */

import * as fc from 'fast-check';

// Mock dependencies before importing handler
jest.mock('../../../repositories/user.repository');
jest.mock('../../../repositories/session.repository');
jest.mock('../../../services/ratelimit.service');
jest.mock('../../../services/security-logger.service');
jest.mock('../../../utils/password');
jest.mock('../../../utils/jwt');
jest.mock('../../../services/tediyat/tenant.service');
jest.mock('../../../services/tediyat/membership.service');

import { handler } from '../login.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as userRepo from '../../../repositories/user.repository';
import * as sessionRepo from '../../../repositories/session.repository';
import * as rateLimitService from '../../../services/ratelimit.service';
import * as securityLogger from '../../../services/security-logger.service';
import * as passwordUtils from '../../../utils/password';
import * as jwtUtils from '../../../utils/jwt';
import * as tenantService from '../../../services/tediyat/tenant.service';
import * as membershipService from '../../../services/tediyat/membership.service';

// Type assertions for mocks
const mockFindUserByEmail = userRepo.findUserByEmail as jest.Mock;
const mockUpdateUserLoginAttempts = userRepo.updateUserLoginAttempts as jest.Mock;
const mockCreateSession = sessionRepo.createSession as jest.Mock;
const mockCreateMfaSession = sessionRepo.createMfaSession as jest.Mock;
const mockCheckRateLimit = rateLimitService.checkRateLimit as jest.Mock;
const mockLogSecurityEvent = securityLogger.logSecurityEvent as jest.Mock;
const mockVerifyPassword = passwordUtils.verifyPassword as jest.Mock;
const mockGenerateTokenPair = jwtUtils.generateTokenPair as jest.Mock;
const mockListUserTenants = tenantService.listUserTenants as jest.Mock;
const mockListUserMemberships = membershipService.listUserMemberships as jest.Mock;

function createMockEvent(body: unknown): APIGatewayProxyEvent {
  return {
    body: typeof body === 'string' ? body : JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'test-agent',
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/tediyat/login',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: '127.0.0.1',
      },
    } as any,
    resource: '',
    multiValueHeaders: {},
  };
}

function createMockUser(overrides: Partial<any> = {}) {
  return {
    id: 'user_' + Math.random().toString(36).substr(2, 9),
    email: 'test@example.com',
    realm_id: 'tediyat',
    password_hash: 'hashed_password',
    email_verified: true,
    status: 'active',
    profile: {
      first_name: 'Test',
      last_name: 'User',
    },
    failed_login_attempts: 0,
    mfa_enabled: false,
    ...overrides,
  };
}

describe('Tediyat Login Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    // Default mock implementations
    mockCheckRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 4,
      resetAt: Date.now() + 900000,
    });

    mockFindUserByEmail.mockResolvedValue(createMockUser());
    mockVerifyPassword.mockResolvedValue(true);
    mockUpdateUserLoginAttempts.mockResolvedValue(undefined);

    mockListUserMemberships.mockResolvedValue({
      success: true,
      data: [
        {
          user_id: 'user_xxx',
          tenant_id: 'ten_xxx',
          role_id: 'role_owner',
          role_name: 'Şirket Sahibi',
          status: 'active',
          is_default: true,
        },
      ],
    });

    mockListUserTenants.mockResolvedValue({
      success: true,
      data: [
        {
          id: 'ten_xxx',
          name: 'Test Company',
          slug: 'test-company',
          role: 'role_owner',
          role_name: 'Şirket Sahibi',
          is_default: true,
        },
      ],
    });

    mockGenerateTokenPair.mockResolvedValue({
      access_token: 'access_token_xxx',
      refresh_token: 'refresh_token_xxx',
      expires_in: 3600,
    });

    mockCreateSession.mockResolvedValue({});
    mockCreateMfaSession.mockResolvedValue({});
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Property 4: Login Returns Complete Tenant List', () => {
    it('should return all tenants user belongs to', async () => {
      const tenants = [
        { id: 'ten_1', name: 'Company 1', slug: 'company-1', role: 'role_owner', role_name: 'Şirket Sahibi', is_default: true },
        { id: 'ten_2', name: 'Company 2', slug: 'company-2', role: 'role_admin', role_name: 'Yönetici', is_default: false },
        { id: 'ten_3', name: 'Company 3', slug: 'company-3', role: 'role_accountant', role_name: 'Muhasebeci', is_default: false },
      ];

      mockListUserTenants.mockResolvedValue({
        success: true,
        data: tenants,
      });

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.success).toBe(true);
      expect(body.data.tenants).toHaveLength(3);
      
      // Verify each tenant has required fields
      body.data.tenants.forEach((tenant: any) => {
        expect(tenant).toHaveProperty('id');
        expect(tenant).toHaveProperty('name');
        expect(tenant).toHaveProperty('slug');
        expect(tenant).toHaveProperty('role');
        expect(tenant).toHaveProperty('role_name');
        expect(tenant).toHaveProperty('is_default');
      });
    });

    it('should identify default tenant', async () => {
      const tenants = [
        { id: 'ten_1', name: 'Company 1', slug: 'company-1', role: 'role_admin', role_name: 'Yönetici', is_default: false },
        { id: 'ten_2', name: 'Company 2', slug: 'company-2', role: 'role_owner', role_name: 'Şirket Sahibi', is_default: true },
      ];

      mockListUserTenants.mockResolvedValue({
        success: true,
        data: tenants,
      });

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.defaultTenant).toBeDefined();
      expect(body.data.defaultTenant.id).toBe('ten_2');
      expect(body.data.defaultTenant.is_default).toBe(true);
    });

    it('should use first tenant as default if none marked', async () => {
      const tenants = [
        { id: 'ten_1', name: 'Company 1', slug: 'company-1', role: 'role_owner', role_name: 'Şirket Sahibi', is_default: false },
        { id: 'ten_2', name: 'Company 2', slug: 'company-2', role: 'role_admin', role_name: 'Yönetici', is_default: false },
      ];

      mockListUserTenants.mockResolvedValue({
        success: true,
        data: tenants,
      });

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.defaultTenant.id).toBe('ten_1');
    });

    it('should include role information for each tenant', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.tenants[0].role).toBe('role_owner');
      expect(body.data.tenants[0].role_name).toBe('Şirket Sahibi');
    });
  });

  describe('Property 5: No Email Enumeration', () => {
    it('should return same error for invalid email and invalid password', async () => {
      // Test with non-existent user
      mockFindUserByEmail.mockResolvedValue(null);

      const eventInvalidEmail = createMockEvent({
        email: 'nonexistent@example.com',
        password: 'SecurePass123!',
      });

      const responseInvalidEmail = await handler(eventInvalidEmail);
      const bodyInvalidEmail = JSON.parse(responseInvalidEmail.body);

      // Test with wrong password
      mockFindUserByEmail.mockResolvedValue(createMockUser());
      mockVerifyPassword.mockResolvedValue(false);

      const eventInvalidPassword = createMockEvent({
        email: 'test@example.com',
        password: 'WrongPassword123!',
      });

      const responseInvalidPassword = await handler(eventInvalidPassword);
      const bodyInvalidPassword = JSON.parse(responseInvalidPassword.body);

      // Both should return 401 with same error code
      expect(responseInvalidEmail.statusCode).toBe(401);
      expect(responseInvalidPassword.statusCode).toBe(401);
      expect(bodyInvalidEmail.error.code).toBe('INVALID_CREDENTIALS');
      expect(bodyInvalidPassword.error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should apply progressive delay for non-existent users', async () => {
      mockFindUserByEmail.mockResolvedValue(null);

      const startTime = Date.now();
      const event = createMockEvent({
        email: 'nonexistent@example.com',
        password: 'SecurePass123!',
      });

      await handler(event);
      const elapsed = Date.now() - startTime;

      // Should have applied at least 1 second delay
      expect(elapsed).toBeGreaterThanOrEqual(900); // Allow some tolerance
    });
  });

  describe('Input Validation', () => {
    it('should reject invalid email', async () => {
      const event = createMockEvent({
        email: 'invalid-email',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_EMAIL');
    });

    it('should reject missing password', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: '',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limiting', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 900000,
        retryAfter: 900,
      });

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });
  });

  describe('Account Lockout', () => {
    it('should lock account after max failed attempts', async () => {
      mockFindUserByEmail.mockResolvedValue(
        createMockUser({ failed_login_attempts: 4 })
      );
      mockVerifyPassword.mockResolvedValue(false);

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'WrongPassword!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(423);
      expect(body.error.code).toBe('ACCOUNT_LOCKED');
      expect(mockUpdateUserLoginAttempts).toHaveBeenCalledWith(
        expect.any(String),
        5,
        expect.any(String)
      );
    }, 20000); // Increase timeout for progressive delay

    it('should reject login for locked account', async () => {
      mockFindUserByEmail.mockResolvedValue(
        createMockUser({
          locked_until: new Date(Date.now() + 900000).toISOString(),
        })
      );

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(423);
      expect(body.error.code).toBe('ACCOUNT_LOCKED');
    });

    it('should reject login for suspended account', async () => {
      mockFindUserByEmail.mockResolvedValue(
        createMockUser({ status: 'suspended' })
      );

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(423);
      expect(body.error.code).toBe('ACCOUNT_SUSPENDED');
    });
  });

  describe('MFA Flow', () => {
    it('should return MFA challenge when MFA is enabled', async () => {
      mockFindUserByEmail.mockResolvedValue(
        createMockUser({ mfa_enabled: true })
      );

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.mfa_required).toBe(true);
      expect(body.data.mfa_session_id).toBeDefined();
      expect(body.data.mfa_expires_in).toBe(300);
      expect(body.data.allowed_methods).toContain('totp');
    });
  });

  describe('Token Generation', () => {
    it('should generate tokens with tenant context', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      await handler(event);

      expect(mockGenerateTokenPair).toHaveBeenCalledWith(
        expect.any(String),
        'tediyat',
        'test@example.com',
        expect.objectContaining({
          accessTokenExpiry: 3600,
          orgId: 'ten_xxx',
          orgIds: ['ten_xxx'],
          roles: ['role_owner'],
        })
      );
    });

    it('should return tokens in response', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.tokens.accessToken).toBeDefined();
      expect(body.data.tokens.refreshToken).toBeDefined();
      expect(body.data.tokens.expiresIn).toBe(3600);
    });
  });

  describe('User Info', () => {
    it('should return user info in response', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.data.user).toBeDefined();
      expect(body.data.user.id).toBeDefined();
      expect(body.data.user.email).toBe('test@example.com');
      expect(body.data.user.firstName).toBeDefined();
      expect(body.data.user.lastName).toBeDefined();
      expect(body.data.user.email_verified).toBeDefined();
    });
  });

  describe('Security Logging', () => {
    it('should log successful login', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      await handler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'login_success',
          realm_id: 'tediyat',
        })
      );
    });

    it('should log failed login', async () => {
      mockVerifyPassword.mockResolvedValue(false);

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'WrongPassword!',
      });

      await handler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'login_failure',
        })
      );
    });
  });

  describe('Reset Failed Attempts', () => {
    it('should reset failed attempts on successful login', async () => {
      mockFindUserByEmail.mockResolvedValue(
        createMockUser({ failed_login_attempts: 3 })
      );

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
      });

      await handler(event);

      expect(mockUpdateUserLoginAttempts).toHaveBeenCalledWith(
        expect.any(String),
        0,
        undefined
      );
    }, 10000); // Increase timeout for progressive delay
  });
});
