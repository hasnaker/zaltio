/**
 * Impersonation Handler Tests
 * Task 11.3: Impersonation Handler (Lambda)
 * 
 * Validates: Requirements 6.1, 6.9 (User Impersonation)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  handler,
  startImpersonationHandler,
  endImpersonationHandler,
  getImpersonationStatusHandler
} from './impersonation.handler';

// Mock dependencies
jest.mock('../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({ allowed: true }),
  RateLimitEndpoint: {
    API_GENERAL: 'api_general',
    LOGIN: 'login'
  }
}));

jest.mock('../services/audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue(undefined),
  AuditEventType: {
    ADMIN_ACTION: 'admin_action',
    LOGIN_SUCCESS: 'login_success'
  },
  AuditResult: {
    SUCCESS: 'success',
    FAILURE: 'failure'
  }
}));

jest.mock('../repositories/user.repository', () => ({
  findUserById: jest.fn()
}));

jest.mock('../services/impersonation.service', () => {
  const mockService = {
    startImpersonation: jest.fn(),
    endImpersonation: jest.fn(),
    getStatus: jest.fn(),
    getActiveSessionByAdmin: jest.fn(),
    validateToken: jest.fn(),
    clearAllSessions: jest.fn()
  };
  
  return {
    ImpersonationService: jest.fn(() => mockService),
    ImpersonationError: class ImpersonationError extends Error {
      code: string;
      statusCode: number;
      constructor(code: string, message: string, statusCode: number = 403) {
        super(message);
        this.code = code;
        this.statusCode = statusCode;
      }
    }
  };
});

import { verifyAccessToken } from '../utils/jwt';
import { checkRateLimit } from '../services/ratelimit.service';
import { logAuditEvent } from '../services/audit.service';
import { findUserById } from '../repositories/user.repository';
import { ImpersonationService, ImpersonationError } from '../services/impersonation.service';

const mockVerifyAccessToken = verifyAccessToken as jest.Mock;
const mockCheckRateLimit = checkRateLimit as jest.Mock;
const mockLogAuditEvent = logAuditEvent as jest.Mock;
const mockFindUserById = findUserById as jest.Mock;

// Get mock service instance
const mockImpersonationService = new ImpersonationService() as jest.Mocked<ImpersonationService>;

/**
 * Create mock API Gateway event
 */
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'POST',
    path: '/admin/users/user-123/impersonate',
    pathParameters: { id: 'user-123' },
    queryStringParameters: null,
    headers: {
      Authorization: 'Bearer valid-admin-token',
      'User-Agent': 'Test Agent'
    },
    body: JSON.stringify({
      reason: 'Debugging user login issue - ticket #12345'
    }),
    requestContext: {
      identity: {
        sourceIp: '192.168.1.100'
      }
    } as APIGatewayProxyEvent['requestContext'],
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    stageVariables: null,
    resource: '',
    isBase64Encoded: false,
    ...overrides
  };
}

describe('Impersonation Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mock implementations
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'admin-001',
      email: 'admin@example.com',
      realm_id: 'test-realm-123',
      is_admin: true,
      can_impersonate: true
    });
    
    mockCheckRateLimit.mockResolvedValue({ allowed: true });
    mockLogAuditEvent.mockResolvedValue(undefined);
    
    mockFindUserById.mockResolvedValue({
      id: 'user-123',
      email: 'user@example.com',
      is_admin: false
    });
    
    mockImpersonationService.startImpersonation.mockResolvedValue({
      session: {
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        target_user_id: 'user-123',
        status: 'active',
        restricted_actions: ['change_password', 'delete_account'],
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        reason: 'Debugging user login issue'
      },
      access_token: 'imp-access-token',
      refresh_token: 'imp-refresh-token',
      expires_in: 3600
    });
    
    mockImpersonationService.endImpersonation.mockResolvedValue({
      id: 'imp_test123',
      realm_id: 'test-realm-123',
      admin_id: 'admin-001',
      target_user_id: 'user-123',
      status: 'ended',
      restricted_actions: [],
      started_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      ended_at: new Date().toISOString(),
      reason: 'Test'
    });
    
    mockImpersonationService.getStatus.mockResolvedValue({
      is_impersonating: true,
      session: {
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        target_user_id: 'user-123',
        status: 'active',
        restricted_actions: [],
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        reason: 'Test'
      },
      remaining_seconds: 3500
    });
    
    mockImpersonationService.validateToken.mockResolvedValue(null);
    mockImpersonationService.getActiveSessionByAdmin.mockResolvedValue(null);
  });

  describe('startImpersonationHandler', () => {
    it('should start impersonation with valid admin token', async () => {
      const event = createMockEvent();
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.data.session).toBeDefined();
      expect(body.data.access_token).toBeDefined();
      expect(body.data.refresh_token).toBeDefined();
      expect(body.data.expires_in).toBeGreaterThan(0);
      expect(body.data.message).toBe('Impersonation session started');
    });

    it('should reject without authorization header', async () => {
      const event = createMockEvent({
        headers: {}
      });
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject non-admin users', async () => {
      mockVerifyAccessToken.mockResolvedValue({
        sub: 'user-001',
        email: 'user@example.com',
        realm_id: 'test-realm-123',
        is_admin: false
      });
      
      const event = createMockEvent();
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.error.message).toContain('Admin');
    });

    it('should reject without user ID', async () => {
      const event = createMockEvent({
        pathParameters: {}
      });
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toContain('User ID');
    });

    it('should reject without reason', async () => {
      const event = createMockEvent({
        body: JSON.stringify({})
      });
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toContain('Reason');
    });

    it('should reject invalid JSON body', async () => {
      const event = createMockEvent({
        body: 'invalid json'
      });
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should reject when user not found', async () => {
      mockFindUserById.mockResolvedValue(null);
      
      const event = createMockEvent();
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });

    it('should reject impersonating admin users', async () => {
      mockFindUserById.mockResolvedValue({
        id: 'user-123',
        email: 'admin2@example.com',
        is_admin: true
      });
      
      const event = createMockEvent();
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('CANNOT_IMPERSONATE');
    });

    it('should reject when rate limited', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        retryAfter: 60
      });
      
      const event = createMockEvent();
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMITED');
      expect(body.error.retry_after).toBe(60);
    });

    it('should handle service errors', async () => {
      const ImpersonationErrorClass = (ImpersonationError as unknown as new (code: string, message: string, statusCode?: number) => Error);
      mockImpersonationService.startImpersonation.mockRejectedValue(
        new ImpersonationErrorClass('ACTIVE_SESSION_EXISTS', 'Already impersonating', 409)
      );
      
      const event = createMockEvent();
      
      const result = await startImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(409);
      expect(body.error.code).toBe('ACTIVE_SESSION_EXISTS');
    });

    it('should log audit event on success', async () => {
      const event = createMockEvent();
      
      await startImpersonationHandler(event);
      
      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'impersonation_started',
          result: 'success'
        })
      );
    });

    it('should include custom duration when provided', async () => {
      const event = createMockEvent({
        body: JSON.stringify({
          reason: 'Debugging user login issue - ticket #12345',
          duration_minutes: 30
        })
      });
      
      await startImpersonationHandler(event);
      
      expect(mockImpersonationService.startImpersonation).toHaveBeenCalledWith(
        expect.objectContaining({
          duration_minutes: 30
        })
      );
    });

    it('should include metadata when provided', async () => {
      const event = createMockEvent({
        body: JSON.stringify({
          reason: 'Debugging user login issue - ticket #12345',
          metadata: {
            ticket_id: 'TICKET-123',
            case_id: 'CASE-456'
          }
        })
      });
      
      await startImpersonationHandler(event);
      
      expect(mockImpersonationService.startImpersonation).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: {
            ticket_id: 'TICKET-123',
            case_id: 'CASE-456'
          }
        })
      );
    });
  });

  describe('endImpersonationHandler', () => {
    beforeEach(() => {
      mockImpersonationService.validateToken.mockResolvedValue({
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-123',
        target_user_email: 'user@example.com',
        reason: 'Test',
        status: 'active',
        restricted_actions: [],
        access_token: 'imp-token',
        refresh_token_hash: 'hash',
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
    });

    it('should end impersonation with valid token', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/impersonation/end',
        pathParameters: null,
        body: null
      });
      
      const result = await endImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.data.session).toBeDefined();
      expect(body.data.message).toBe('Impersonation session ended');
    });

    it('should allow admin to end specific session', async () => {
      mockImpersonationService.validateToken.mockResolvedValue(null);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/impersonation/end',
        pathParameters: null,
        body: JSON.stringify({ session_id: 'imp_specific123' })
      });
      
      const result = await endImpersonationHandler(event);
      
      expect(result.statusCode).toBe(200);
      expect(mockImpersonationService.endImpersonation).toHaveBeenCalledWith(
        expect.objectContaining({
          session_id: 'imp_specific123'
        })
      );
    });

    it('should reject without valid token', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Invalid token'));
      mockImpersonationService.validateToken.mockResolvedValue(null);
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/impersonation/end',
        pathParameters: null,
        headers: { Authorization: 'Bearer invalid-token' },
        body: null
      });
      
      const result = await endImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should handle service errors', async () => {
      const ImpersonationErrorClass = (ImpersonationError as unknown as new (code: string, message: string, statusCode?: number) => Error);
      mockImpersonationService.endImpersonation.mockRejectedValue(
        new ImpersonationErrorClass('SESSION_NOT_FOUND', 'Session not found', 404)
      );
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/impersonation/end',
        pathParameters: null,
        body: null
      });
      
      const result = await endImpersonationHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('SESSION_NOT_FOUND');
    });

    it('should log audit event on success', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/impersonation/end',
        pathParameters: null,
        body: null
      });
      
      await endImpersonationHandler(event);
      
      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'impersonation_ended',
          result: 'success'
        })
      );
    });
  });

  describe('getImpersonationStatusHandler', () => {
    beforeEach(() => {
      mockImpersonationService.validateToken.mockResolvedValue({
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-123',
        target_user_email: 'user@example.com',
        reason: 'Test',
        status: 'active',
        restricted_actions: [],
        access_token: 'imp-token',
        refresh_token_hash: 'hash',
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
    });

    it('should return status for impersonation token', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/impersonation/status',
        pathParameters: null,
        body: null
      });
      
      const result = await getImpersonationStatusHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.data.is_impersonating).toBe(true);
      expect(body.data.session).toBeDefined();
      expect(body.data.remaining_seconds).toBeGreaterThan(0);
    });

    it('should return status for admin with session_id query', async () => {
      mockImpersonationService.validateToken.mockResolvedValue(null);
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/impersonation/status',
        pathParameters: null,
        queryStringParameters: { session_id: 'imp_query123' },
        body: null
      });
      
      const result = await getImpersonationStatusHandler(event);
      
      expect(result.statusCode).toBe(200);
      expect(mockImpersonationService.getStatus).toHaveBeenCalledWith('imp_query123');
    });

    it('should return not impersonating when no session', async () => {
      mockImpersonationService.validateToken.mockResolvedValue(null);
      mockImpersonationService.getActiveSessionByAdmin.mockResolvedValue(null);
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/impersonation/status',
        pathParameters: null,
        body: null
      });
      
      const result = await getImpersonationStatusHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(200);
      expect(body.data.is_impersonating).toBe(false);
    });

    it('should reject without valid token', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Invalid token'));
      mockImpersonationService.validateToken.mockResolvedValue(null);
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/impersonation/status',
        pathParameters: null,
        headers: { Authorization: 'Bearer invalid-token' },
        body: null
      });
      
      const result = await getImpersonationStatusHandler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('handler (router)', () => {
    it('should route to startImpersonationHandler', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/admin/users/user-123/impersonate'
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
    });

    it('should route to endImpersonationHandler', async () => {
      mockImpersonationService.validateToken.mockResolvedValue({
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-123',
        target_user_email: 'user@example.com',
        reason: 'Test',
        status: 'active',
        restricted_actions: [],
        access_token: 'imp-token',
        refresh_token_hash: 'hash',
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/impersonation/end',
        pathParameters: null,
        body: null
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
    });

    it('should route to getImpersonationStatusHandler', async () => {
      mockImpersonationService.validateToken.mockResolvedValue({
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-123',
        target_user_email: 'user@example.com',
        reason: 'Test',
        status: 'active',
        restricted_actions: [],
        access_token: 'imp-token',
        refresh_token_hash: 'hash',
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/impersonation/status',
        pathParameters: null,
        body: null
      });
      
      const result = await handler(event);
      
      expect(result.statusCode).toBe(200);
    });

    it('should return 404 for unknown routes', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/unknown/route',
        pathParameters: null
      });
      
      const result = await handler(event);
      const body = JSON.parse(result.body);
      
      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in response', async () => {
      const event = createMockEvent();
      
      const result = await startImpersonationHandler(event);
      
      expect(result.headers).toMatchObject({
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Strict-Transport-Security': expect.stringContaining('max-age'),
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      });
    });
  });
});
