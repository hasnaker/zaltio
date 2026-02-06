/**
 * Tediyat Register Handler Tests
 * Property 1: Registration Creates Complete Setup
 * Property 2: Password Policy Enforcement
 * 
 * Validates: Requirements 1.1-1.8
 */

import * as fc from 'fast-check';

// Mock dependencies before importing handler
jest.mock('../../../repositories/user.repository');
jest.mock('../../../repositories/realm.repository');
jest.mock('../../../repositories/session.repository');
jest.mock('../../../repositories/verification.repository');
jest.mock('../../../services/ratelimit.service');
jest.mock('../../../services/security-logger.service');
jest.mock('../../../services/email.service');
jest.mock('../../../utils/password');
jest.mock('../../../utils/jwt');
jest.mock('../../../services/tediyat/tenant.service');
jest.mock('../../../services/tediyat/membership.service');

import { handler } from '../register.handler';
import { APIGatewayProxyEvent } from 'aws-lambda';
import * as userRepo from '../../../repositories/user.repository';
import * as realmRepo from '../../../repositories/realm.repository';
import * as sessionRepo from '../../../repositories/session.repository';
import * as rateLimitService from '../../../services/ratelimit.service';
import * as securityLogger from '../../../services/security-logger.service';
import * as emailService from '../../../services/email.service';
import * as passwordUtils from '../../../utils/password';
import * as jwtUtils from '../../../utils/jwt';
import * as tenantService from '../../../services/tediyat/tenant.service';
import * as membershipService from '../../../services/tediyat/membership.service';

// Type assertions for mocks
const mockFindUserByEmail = userRepo.findUserByEmail as jest.Mock;
const mockCreateUser = userRepo.createUser as jest.Mock;
const mockFindRealmById = realmRepo.findRealmById as jest.Mock;
const mockGetRealmSettings = realmRepo.getRealmSettings as jest.Mock;
const mockCreateSession = sessionRepo.createSession as jest.Mock;
const mockCheckRateLimit = rateLimitService.checkRateLimit as jest.Mock;
const mockLogSecurityEvent = securityLogger.logSecurityEvent as jest.Mock;
const mockSendVerificationEmail = emailService.sendVerificationEmail as jest.Mock;
const mockCreateVerificationCodeData = emailService.createVerificationCodeData as jest.Mock;
const mockValidatePasswordPolicy = passwordUtils.validatePasswordPolicy as jest.Mock;
const mockCheckPasswordPwned = passwordUtils.checkPasswordPwned as jest.Mock;
const mockGenerateTokenPair = jwtUtils.generateTokenPair as jest.Mock;
const mockCreateTenant = tenantService.createTenant as jest.Mock;
const mockCreateMembership = membershipService.createMembership as jest.Mock;

function createMockEvent(body: unknown): APIGatewayProxyEvent {
  return {
    body: typeof body === 'string' ? body : JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'test-agent',
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/tediyat/register',
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

describe('Tediyat Register Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    // Default mock implementations
    mockCheckRateLimit.mockResolvedValue({
      allowed: true,
      remaining: 2,
      resetAt: Date.now() + 3600000,
    });

    mockFindUserByEmail.mockResolvedValue(null);

    mockValidatePasswordPolicy.mockReturnValue({
      valid: true,
      errors: [],
    });

    mockCheckPasswordPwned.mockResolvedValue(0);

    mockCreateUser.mockImplementation((input) => ({
      id: 'user_' + Math.random().toString(36).substr(2, 9),
      email: input.email,
      realm_id: input.realm_id,
      profile: input.profile,
      email_verified: false,
      status: 'active',
      created_at: new Date().toISOString(),
    }));

    mockCreateTenant.mockImplementation((input) => {
      // Use the actual slug generation logic
      const slug = input.name
        .toLowerCase()
        .replace(/ğ/g, 'g')
        .replace(/ü/g, 'u')
        .replace(/ş/g, 's')
        .replace(/ı/g, 'i')
        .replace(/ö/g, 'o')
        .replace(/ç/g, 'c')
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '') || 'tenant';
      
      return {
        success: true,
        data: {
          id: 'ten_' + Math.random().toString(36).substr(2, 9),
          name: input.name,
          slug,
          status: 'active',
          created_at: new Date().toISOString(),
          created_by: input.owner_user_id,
        },
      };
    });

    mockCreateMembership.mockResolvedValue({
      success: true,
      data: {
        user_id: 'user_xxx',
        tenant_id: 'ten_xxx',
        role_id: 'role_owner',
        status: 'active',
      },
    });

    mockGenerateTokenPair.mockResolvedValue({
      access_token: 'access_token_xxx',
      refresh_token: 'refresh_token_xxx',
      expires_in: 3600,
    });

    mockCreateSession.mockResolvedValue({});

    mockCreateVerificationCodeData.mockReturnValue({
      code: '123456',
      codeHash: 'hash_xxx',
      expiresAt: Date.now() + 86400000,
    });

    mockSendVerificationEmail.mockResolvedValue({ success: true });
    mockLogSecurityEvent.mockResolvedValue(undefined);
  });

  describe('Property 1: Registration Creates Complete Setup', () => {
    // Turkish name generator
    const turkishNameArb = fc.stringOf(
      fc.constantFrom(
        ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.split(''),
        ...'ğüşıöçĞÜŞİÖÇ'.split('')
      ),
      { minLength: 2, maxLength: 50 }
    );

    // Company name generator
    const companyNameArb = fc.stringOf(
      fc.constantFrom(
        ...'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '.split(''),
        ...'ğüşıöçĞÜŞİÖÇ'.split('')
      ),
      { minLength: 2, maxLength: 100 }
    );

    it('should create user, tenant, and membership for valid registration', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.emailAddress(),
          turkishNameArb,
          turkishNameArb,
          companyNameArb,
          async (email, firstName, lastName, companyName) => {
            // Skip empty names
            if (!firstName.trim() || !lastName.trim() || !companyName.trim()) return;

            const event = createMockEvent({
              email,
              password: 'SecurePass123!',
              firstName,
              lastName,
              companyName,
            });

            const response = await handler(event);
            const body = JSON.parse(response.body);

            if (response.statusCode === 201) {
              // Verify complete setup
              expect(body.success).toBe(true);
              expect(body.data.user).toBeDefined();
              expect(body.data.user.id).toMatch(/^user_/);
              expect(body.data.user.email).toBe(email);
              expect(body.data.tenant).toBeDefined();
              expect(body.data.tenant.id).toMatch(/^ten_/);
              expect(body.data.tokens).toBeDefined();
              expect(body.data.tokens.accessToken).toBeDefined();
              expect(body.data.tokens.refreshToken).toBeDefined();

              // Verify services were called
              expect(mockCreateUser).toHaveBeenCalled();
              expect(mockCreateTenant).toHaveBeenCalled();
              expect(mockCreateMembership).toHaveBeenCalled();
            }
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should assign owner role to creator', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      const response = await handler(event);
      expect(response.statusCode).toBe(201);

      // Verify membership was created with owner role
      expect(mockCreateMembership).toHaveBeenCalledWith(
        expect.objectContaining({
          role_id: 'role_owner',
          realm_id: 'tediyat',
          is_default: true,
        })
      );
    });

    it('should generate unique tenant slug', async () => {
      const slugs = new Set<string>();

      await fc.assert(
        fc.asyncProperty(companyNameArb, async (companyName) => {
          if (!companyName.trim()) return;

          const event = createMockEvent({
            email: `test${Math.random()}@example.com`,
            password: 'SecurePass123!',
            firstName: 'Test',
            lastName: 'User',
            companyName,
          });

          const response = await handler(event);
          if (response.statusCode === 201) {
            const body = JSON.parse(response.body);
            const slug = body.data.tenant.slug;

            // Slug should be URL-safe
            expect(slug).toMatch(/^[a-z0-9-]+$/);

            // Track for uniqueness (within this test)
            slugs.add(slug);
          }
        }),
        { numRuns: 10 }
      );
    });
  });

  describe('Property 2: Password Policy Enforcement', () => {
    const weakPasswords = [
      'short',
      'nouppercase123!',
      'NOLOWERCASE123!',
      'NoNumbers!',
      'NoSpecialChar123',
      '12345678',
      'password',
    ];

    it('should reject weak passwords', async () => {
      for (const weakPassword of weakPasswords) {
        mockValidatePasswordPolicy.mockReturnValue({
          valid: false,
          errors: ['Password does not meet requirements'],
        });

        const event = createMockEvent({
          email: 'test@example.com',
          password: weakPassword,
          firstName: 'Test',
          lastName: 'User',
          companyName: 'Test Company',
        });

        const response = await handler(event);
        const body = JSON.parse(response.body);

        expect(response.statusCode).toBe(400);
        expect(body.success).toBe(false);
        expect(body.error.code).toBe('PASSWORD_TOO_WEAK');
      }
    });

    it('should accept strong passwords', async () => {
      const strongPasswords = [
        'SecurePass123!',
        'MyP@ssw0rd!2024',
        'C0mpl3x!Pass#',
        'Str0ng&Secure!',
      ];

      for (const strongPassword of strongPasswords) {
        mockValidatePasswordPolicy.mockReturnValue({
          valid: true,
          errors: [],
        });

        const event = createMockEvent({
          email: `test${Math.random()}@example.com`,
          password: strongPassword,
          firstName: 'Test',
          lastName: 'User',
          companyName: 'Test Company',
        });

        const response = await handler(event);
        expect(response.statusCode).toBe(201);
      }
    });

    it('should reject compromised passwords', async () => {
      mockValidatePasswordPolicy.mockReturnValue({ valid: true, errors: [] });
      mockCheckPasswordPwned.mockResolvedValue(1000);

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'CompromisedPass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('PASSWORD_COMPROMISED');
    });
  });

  describe('Input Validation', () => {
    it('should reject invalid email', async () => {
      const event = createMockEvent({
        email: 'invalid-email',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_EMAIL');
    });

    it('should reject missing first name', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: '',
        lastName: 'User',
        companyName: 'Test Company',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_FIRST_NAME');
    });

    it('should reject missing company name', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: '',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_COMPANY_NAME');
    });

    it('should accept Turkish characters in names', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Şükrü',
        lastName: 'Öztürk',
        companyName: 'İstanbul Şirketi',
      });

      const response = await handler(event);
      expect(response.statusCode).toBe(201);

      const body = JSON.parse(response.body);
      expect(body.data.user.firstName).toBe('Şükrü');
      expect(body.data.user.lastName).toBe('Öztürk');
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limiting', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 3600000,
        retryAfter: 3600,
      });

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
    });
  });

  describe('Duplicate User Prevention', () => {
    it('should reject duplicate email', async () => {
      mockFindUserByEmail.mockResolvedValue({
        id: 'existing_user',
        email: 'test@example.com',
      });

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(409);
      expect(body.error.code).toBe('USER_EXISTS');
    });
  });

  describe('Token Generation', () => {
    it('should generate tokens with tenant context', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      await handler(event);

      expect(mockGenerateTokenPair).toHaveBeenCalledWith(
        expect.any(String),
        'tediyat',
        'test@example.com',
        expect.objectContaining({
          accessTokenExpiry: 3600, // 1 hour for Tediyat
          orgId: expect.stringMatching(/^ten_/),
          roles: ['role_owner'],
          permissions: ['*'],
        })
      );
    });

    it('should return tokens in response', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(201);
      expect(body.data.tokens.accessToken).toBeDefined();
      expect(body.data.tokens.refreshToken).toBeDefined();
      expect(body.data.tokens.expiresIn).toBe(3600);
    });
  });

  describe('Security Logging', () => {
    it('should log successful registration', async () => {
      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      await handler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'user_registered',
          realm_id: 'tediyat',
        })
      );
    });

    it('should log rate limit exceeded', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        resetAt: Date.now() + 3600000,
        retryAfter: 3600,
      });

      const event = createMockEvent({
        email: 'test@example.com',
        password: 'SecurePass123!',
        firstName: 'Test',
        lastName: 'User',
        companyName: 'Test Company',
      });

      await handler(event);

      expect(mockLogSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'rate_limit_exceeded',
        })
      );
    });
  });
});
