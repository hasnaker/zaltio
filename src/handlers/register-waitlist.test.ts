/**
 * Integration tests for Waitlist Mode in Registration
 * Validates: Requirements 5.1, 5.9 (Waitlist mode blocks registration)
 */

// Mock dependencies BEFORE importing handler
const mockFindRealmById = jest.fn();
const mockGetRealmSettings = jest.fn();
const mockFindUserByEmail = jest.fn();
const mockCreateUser = jest.fn();
const mockCheckRateLimit = jest.fn();
const mockCheckPasswordPwned = jest.fn();
const mockLogSecurityEvent = jest.fn();
const mockSendVerificationEmail = jest.fn();
const mockSaveVerificationCode = jest.fn();

jest.mock('../repositories/realm.repository', () => ({
  findRealmById: (...args: unknown[]) => mockFindRealmById(...args),
  getRealmSettings: (...args: unknown[]) => mockGetRealmSettings(...args)
}));

jest.mock('../repositories/user.repository', () => ({
  findUserByEmail: (...args: unknown[]) => mockFindUserByEmail(...args),
  createUser: (...args: unknown[]) => mockCreateUser(...args)
}));

jest.mock('../services/ratelimit.service', () => ({
  checkRateLimit: (...args: unknown[]) => mockCheckRateLimit(...args)
}));

jest.mock('../utils/password', () => ({
  checkPasswordPwned: (...args: unknown[]) => mockCheckPasswordPwned(...args),
  validatePasswordPolicy: jest.fn().mockReturnValue({ valid: true, errors: [] })
}));

jest.mock('../services/security-logger.service', () => ({
  logSecurityEvent: (...args: unknown[]) => mockLogSecurityEvent(...args)
}));

jest.mock('../services/email.service', () => ({
  sendVerificationEmail: (...args: unknown[]) => mockSendVerificationEmail(...args),
  createVerificationCodeData: jest.fn().mockReturnValue({
    code: '123456',
    codeHash: 'hash123',
    expiresAt: Date.now() + 3600000
  })
}));

jest.mock('../repositories/verification.repository', () => ({
  saveVerificationCode: (...args: unknown[]) => mockSaveVerificationCode(...args)
}));

// Import handler AFTER mocks are set up
import { handler } from './register-handler';
import { APIGatewayProxyEvent } from 'aws-lambda';

// Use valid realm ID format (alphanumeric with hyphens, 3-64 chars)
const TEST_REALM_ID = 'test-realm-123';

function createMockEvent(body: Record<string, unknown>): APIGatewayProxyEvent {
  return {
    httpMethod: 'POST',
    path: '/register',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    queryStringParameters: null,
    pathParameters: null,
    isBase64Encoded: false,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '',
    stageVariables: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null
  } as APIGatewayProxyEvent;
}

describe('Register Handler - Waitlist Mode', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockCheckRateLimit.mockResolvedValue({ allowed: true, remaining: 10, resetAt: Date.now() + 3600000 });
    mockCheckPasswordPwned.mockResolvedValue(0);
    mockGetRealmSettings.mockResolvedValue({
      password_policy: {
        min_length: 8,
        require_uppercase: true,
        require_lowercase: true,
        require_numbers: true,
        require_special_chars: false
      }
    });
  });

  it('should block registration when waitlist mode is enabled', async () => {
    mockFindRealmById.mockResolvedValue({
      id: TEST_REALM_ID,
      name: 'Test Realm',
      settings: {
        waitlist_mode_enabled: true,
        waitlist_url: '/join-waitlist',
        password_policy: {
          min_length: 8,
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true
        }
      }
    });

    const event = createMockEvent({
      realm_id: TEST_REALM_ID,
      email: 'test@example.com',
      password: 'SecurePass123'
    });

    const response = await handler(event);

    expect(response.statusCode).toBe(403);
    const body = JSON.parse(response.body);
    expect(body.error.code).toBe('WAITLIST_MODE_ACTIVE');
    expect(body.error.details.waitlist_url).toBe('/join-waitlist');
  });

  it('should allow registration when waitlist mode is disabled', async () => {
    mockFindRealmById.mockResolvedValue({
      id: TEST_REALM_ID,
      name: 'Test Realm',
      settings: {
        waitlist_mode_enabled: false,
        password_policy: {
          min_length: 8,
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true
        }
      }
    });
    mockFindUserByEmail.mockResolvedValue(null);
    mockCreateUser.mockResolvedValue({
      id: 'user-123',
      email: 'test@example.com',
      email_verified: false,
      created_at: new Date().toISOString()
    });
    mockSendVerificationEmail.mockResolvedValue({ success: true });

    const event = createMockEvent({
      realm_id: TEST_REALM_ID,
      email: 'test@example.com',
      password: 'SecurePass123'
    });

    const response = await handler(event);

    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.body);
    expect(body.user.id).toBe('user-123');
  });

  it('should allow registration when waitlist_mode_enabled is not set', async () => {
    mockFindRealmById.mockResolvedValue({
      id: TEST_REALM_ID,
      name: 'Test Realm',
      settings: {
        password_policy: {
          min_length: 8,
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true
        }
      }
    });
    mockFindUserByEmail.mockResolvedValue(null);
    mockCreateUser.mockResolvedValue({
      id: 'user-123',
      email: 'test@example.com',
      email_verified: false,
      created_at: new Date().toISOString()
    });
    mockSendVerificationEmail.mockResolvedValue({ success: true });

    const event = createMockEvent({
      realm_id: TEST_REALM_ID,
      email: 'test@example.com',
      password: 'SecurePass123'
    });

    const response = await handler(event);

    expect(response.statusCode).toBe(201);
  });

  it('should log security event when registration is blocked by waitlist', async () => {
    mockFindRealmById.mockResolvedValue({
      id: TEST_REALM_ID,
      name: 'Test Realm',
      settings: {
        waitlist_mode_enabled: true,
        password_policy: {
          min_length: 8,
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true
        }
      }
    });

    const event = createMockEvent({
      realm_id: TEST_REALM_ID,
      email: 'test@example.com',
      password: 'SecurePass123'
    });

    await handler(event);

    expect(mockLogSecurityEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: 'registration_blocked_waitlist',
        realm_id: TEST_REALM_ID
      })
    );
  });

  it('should use default waitlist URL when not configured', async () => {
    mockFindRealmById.mockResolvedValue({
      id: TEST_REALM_ID,
      name: 'Test Realm',
      settings: {
        waitlist_mode_enabled: true,
        password_policy: {
          min_length: 8,
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true
        }
      }
    });

    const event = createMockEvent({
      realm_id: TEST_REALM_ID,
      email: 'test@example.com',
      password: 'SecurePass123'
    });

    const response = await handler(event);

    expect(response.statusCode).toBe(403);
    const body = JSON.parse(response.body);
    expect(body.error.details.waitlist_url).toBe('/waitlist');
  });
});
