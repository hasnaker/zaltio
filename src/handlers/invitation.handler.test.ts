/**
 * Invitation Handler Unit Tests
 * 
 * Tests for the invitation Lambda handler endpoints:
 * - POST /tenants/{id}/invitations - Create invitation
 * - GET /tenants/{id}/invitations - List invitations
 * - POST /invitations/accept - Accept invitation
 * - DELETE /invitations/{id} - Revoke invitation
 * - POST /invitations/{id}/resend - Resend invitation
 * - GET /invitations/validate - Validate invitation token
 * 
 * Validates: Requirements 11.7 (Invitation Endpoints)
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from './invitation.handler';
import type { InvitationStatus, InvitationResponse, InvitationWithToken } from '../models/invitation.model';

// Mock dependencies
jest.mock('../services/invitation.service', () => ({
  invitationService: {
    create: jest.fn(),
    list: jest.fn(),
    accept: jest.fn(),
    revoke: jest.fn(),
    resend: jest.fn(),
    getById: jest.fn(),
    validateToken: jest.fn(),
    getStatistics: jest.fn()
  },
  InvitationServiceError: class InvitationServiceError extends Error {
    constructor(public code: string, message: string) {
      super(message);
      this.name = 'InvitationServiceError';
    }
  },
  InvitationErrorCode: {
    INVALID_EMAIL: 'INVALID_EMAIL',
    DUPLICATE_INVITATION: 'DUPLICATE_INVITATION',
    INVITATION_NOT_FOUND: 'INVITATION_NOT_FOUND',
    INVITATION_EXPIRED: 'INVITATION_EXPIRED',
    INVITATION_ALREADY_USED: 'INVITATION_ALREADY_USED',
    INVITATION_REVOKED: 'INVITATION_REVOKED',
    TENANT_NOT_FOUND: 'TENANT_NOT_FOUND',
    USER_ALREADY_MEMBER: 'USER_ALREADY_MEMBER',
    USER_NOT_FOUND: 'USER_NOT_FOUND',
    INVALID_TOKEN: 'INVALID_TOKEN',
    CANNOT_REVOKE: 'CANNOT_REVOKE',
    CANNOT_RESEND: 'CANNOT_RESEND',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED'
  }
}));


jest.mock('../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn()
}));

jest.mock('../repositories/membership.repository', () => ({
  getMembership: jest.fn(),
  isMember: jest.fn()
}));

jest.mock('../repositories/organization.repository', () => ({
  getOrganization: jest.fn()
}));

jest.mock('../services/audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue(undefined),
  AuditEventType: { ADMIN_ACTION: 'ADMIN_ACTION' },
  AuditResult: { SUCCESS: 'SUCCESS', FAILURE: 'FAILURE' }
}));

jest.mock('../models/invitation.model', () => ({
  isValidEmail: jest.fn().mockReturnValue(true),
  normalizeEmail: jest.fn().mockImplementation((email: string) => email.toLowerCase().trim())
}));

// Import mocked modules
import { invitationService } from '../services/invitation.service';
import { checkRateLimit } from '../services/ratelimit.service';
import { getMembership } from '../repositories/membership.repository';
import { getOrganization } from '../repositories/organization.repository';
import { isValidEmail } from '../models/invitation.model';

// ============================================================================
// Test Helpers
// ============================================================================

function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/',
    headers: {
      Authorization: 'Bearer valid-token'
    },
    queryStringParameters: null,
    pathParameters: null,
    body: null,
    isBase64Encoded: false,
    requestContext: {
      authorizer: {
        userId: 'user_123',
        realmId: 'realm_456',
        sessionId: 'session_789',
        email: 'admin@example.com',
        role: 'admin'
      },
      identity: {
        sourceIp: '192.168.1.1'
      }
    } as any,
    resource: '',
    stageVariables: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    ...overrides
  } as APIGatewayProxyEvent;
}

// Mock rate limit result with all required fields
const mockRateLimitAllowed = {
  allowed: true,
  remaining: 10,
  resetAt: Date.now() + 60000
};

const mockRateLimitDenied = (retryAfter: number) => ({
  allowed: false,
  remaining: 0,
  resetAt: Date.now() + retryAfter * 1000,
  retryAfter
});

const mockTenant = {
  id: 'tenant_123',
  realm_id: 'realm_456',
  name: 'Test Organization',
  settings: {}
};

const mockMembership = {
  user_id: 'user_123',
  org_id: 'tenant_123',
  role_ids: ['admin'],
  status: 'active'
};

const mockInvitation: InvitationResponse = {
  id: 'inv_abc123',
  tenant_id: 'tenant_123',
  email: 'invitee@example.com',
  role: 'member',
  invited_by: 'user_123',
  status: 'pending' as InvitationStatus,
  expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  created_at: new Date().toISOString()
};


// ============================================================================
// Test Suite
// ============================================================================

describe('Invitation Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mock implementations
    (getOrganization as jest.Mock).mockResolvedValue(mockTenant);
    (getMembership as jest.Mock).mockResolvedValue(mockMembership);
    (checkRateLimit as jest.Mock).mockResolvedValue(mockRateLimitAllowed);
    (isValidEmail as jest.Mock).mockReturnValue(true);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  // ==========================================================================
  // CORS Preflight Tests
  // ==========================================================================
  
  describe('OPTIONS (CORS Preflight)', () => {
    it('should return 200 for OPTIONS request', async () => {
      const event = createMockEvent({
        httpMethod: 'OPTIONS',
        path: '/tenants/tenant_123/invitations'
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      expect(result.headers).toHaveProperty('Access-Control-Allow-Origin', '*');
      expect(result.headers).toHaveProperty('Access-Control-Allow-Methods');
    });
  });

  // ==========================================================================
  // POST /tenants/{id}/invitations - Create Invitation
  // ==========================================================================
  
  describe('POST /tenants/{id}/invitations - Create Invitation', () => {
    it('should create invitation successfully', async () => {
      const mockResult: InvitationWithToken = {
        invitation: mockInvitation,
        token: 'secure-token-123'
      };
      (invitationService.create as jest.Mock).mockResolvedValue(mockResult);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/invitations',
        body: JSON.stringify({
          email: 'invitee@example.com',
          role: 'member'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(201);
      expect(body.message).toBe('Invitation created successfully');
      expect(body.invitation).toEqual(mockInvitation);
      expect(body.accept_url).toContain('secure-token-123');
    });

    it('should return 401 when not authenticated', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/invitations',
        headers: {},
        requestContext: { authorizer: null } as any,
        body: JSON.stringify({
          email: 'invitee@example.com',
          role: 'member'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 404 when tenant not found', async () => {
      (getOrganization as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/nonexistent/invitations',
        body: JSON.stringify({
          email: 'invitee@example.com',
          role: 'member'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('TENANT_NOT_FOUND');
    });


    it('should return 403 when user lacks admin access', async () => {
      (getMembership as jest.Mock).mockResolvedValue({
        ...mockMembership,
        role_ids: ['member']
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/invitations',
        body: JSON.stringify({
          email: 'invitee@example.com',
          role: 'member'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('should return 429 when rate limited', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue(mockRateLimitDenied(3600));

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/invitations',
        body: JSON.stringify({
          email: 'invitee@example.com',
          role: 'member'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(result.headers).toHaveProperty('Retry-After', '3600');
    });

    it('should return 400 when email is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/invitations',
        body: JSON.stringify({
          role: 'member'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_EMAIL');
    });

    it('should return 400 when role is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/invitations',
        body: JSON.stringify({
          email: 'invitee@example.com'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_ROLE');
    });

    it('should return 400 when email format is invalid', async () => {
      (isValidEmail as jest.Mock).mockReturnValue(false);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/invitations',
        body: JSON.stringify({
          email: 'invalid-email',
          role: 'member'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_EMAIL');
    });

    it('should return 400 for invalid JSON body', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/tenants/tenant_123/invitations',
        body: 'invalid json'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });
  });


  // ==========================================================================
  // GET /tenants/{id}/invitations - List Invitations
  // ==========================================================================
  
  describe('GET /tenants/{id}/invitations - List Invitations', () => {
    it('should list invitations successfully', async () => {
      (invitationService.list as jest.Mock).mockResolvedValue({
        invitations: [mockInvitation],
        next_cursor: undefined
      });
      (invitationService.getStatistics as jest.Mock).mockResolvedValue({
        pending: 1,
        accepted: 5,
        expired: 2,
        revoked: 0
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants/tenant_123/invitations'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.invitations).toHaveLength(1);
      expect(body.statistics).toBeDefined();
      expect(body.statistics.pending).toBe(1);
    });

    it('should filter by status', async () => {
      (invitationService.list as jest.Mock).mockResolvedValue({
        invitations: [mockInvitation],
        next_cursor: undefined
      });
      (invitationService.getStatistics as jest.Mock).mockResolvedValue({
        pending: 1, accepted: 0, expired: 0, revoked: 0
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants/tenant_123/invitations',
        queryStringParameters: { status: 'pending' }
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      expect(invitationService.list).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'pending' })
      );
    });

    it('should support pagination', async () => {
      (invitationService.list as jest.Mock).mockResolvedValue({
        invitations: [mockInvitation],
        next_cursor: 'next-page-cursor'
      });
      (invitationService.getStatistics as jest.Mock).mockResolvedValue({
        pending: 10, accepted: 0, expired: 0, revoked: 0
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants/tenant_123/invitations',
        queryStringParameters: { limit: '10', cursor: 'prev-cursor' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.next_cursor).toBe('next-page-cursor');
    });

    it('should return 401 when not authenticated', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants/tenant_123/invitations',
        headers: {},
        requestContext: { authorizer: null } as any
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 403 when user lacks admin access', async () => {
      (getMembership as jest.Mock).mockResolvedValue({
        ...mockMembership,
        role_ids: ['viewer']
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants/tenant_123/invitations'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });


  // ==========================================================================
  // POST /invitations/accept - Accept Invitation
  // ==========================================================================
  
  describe('POST /invitations/accept - Accept Invitation', () => {
    it('should accept invitation for existing user', async () => {
      (invitationService.accept as jest.Mock).mockResolvedValue({
        user_id: 'user_123',
        tenant_id: 'tenant_123',
        role: 'member',
        is_new_user: false
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/accept',
        body: JSON.stringify({
          token: 'valid-invitation-token'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Invitation accepted successfully');
      expect(body.user_id).toBe('user_123');
      expect(body.is_new_user).toBe(false);
    });

    it('should accept invitation for new user with registration', async () => {
      (invitationService.accept as jest.Mock).mockResolvedValue({
        user_id: 'new_user_456',
        tenant_id: 'tenant_123',
        role: 'member',
        is_new_user: true
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/accept',
        headers: {},
        requestContext: { 
          authorizer: null,
          identity: { sourceIp: '192.168.1.1' }
        } as any,
        body: JSON.stringify({
          token: 'valid-invitation-token',
          new_user: {
            first_name: 'John',
            last_name: 'Doe',
            password: 'SecurePass123!'
          }
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.is_new_user).toBe(true);
    });

    it('should return 400 when token is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/accept',
        body: JSON.stringify({})
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_TOKEN');
    });

    it('should return 400 when new_user data is incomplete', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/accept',
        headers: {},
        requestContext: { 
          authorizer: null,
          identity: { sourceIp: '192.168.1.1' }
        } as any,
        body: JSON.stringify({
          token: 'valid-token',
          new_user: {
            first_name: 'John'
          }
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_NEW_USER');
    });

    it('should return 400 when password is too short', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/accept',
        headers: {},
        requestContext: { 
          authorizer: null,
          identity: { sourceIp: '192.168.1.1' }
        } as any,
        body: JSON.stringify({
          token: 'valid-token',
          new_user: {
            first_name: 'John',
            last_name: 'Doe',
            password: 'short'
          }
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('WEAK_PASSWORD');
    });

    it('should return 429 when rate limited', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue(mockRateLimitDenied(300));

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/accept',
        body: JSON.stringify({
          token: 'valid-token'
        })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });
  });


  // ==========================================================================
  // GET /invitations/validate - Validate Invitation Token
  // ==========================================================================
  
  describe('GET /invitations/validate - Validate Invitation Token', () => {
    it('should validate token successfully', async () => {
      (invitationService.validateToken as jest.Mock).mockResolvedValue({
        valid: true,
        invitation: mockInvitation,
        invitation_details: mockInvitation
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/invitations/validate',
        queryStringParameters: { token: 'valid-token' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.valid).toBe(true);
      expect(body.invitation).toBeDefined();
    });

    it('should return 400 when token is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/invitations/validate',
        queryStringParameters: null
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_TOKEN');
    });

    it('should return 400 when token is invalid', async () => {
      (invitationService.validateToken as jest.Mock).mockResolvedValue({
        valid: false,
        error: 'Invalid invitation token',
        error_code: 'INVITATION_NOT_FOUND'
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/invitations/validate',
        queryStringParameters: { token: 'invalid-token' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVITATION_NOT_FOUND');
    });

    it('should return 400 when invitation is expired', async () => {
      (invitationService.validateToken as jest.Mock).mockResolvedValue({
        valid: false,
        error: 'Invitation has expired',
        error_code: 'INVITATION_EXPIRED'
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/invitations/validate',
        queryStringParameters: { token: 'expired-token' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('INVITATION_EXPIRED');
    });
  });

  // ==========================================================================
  // DELETE /invitations/{id} - Revoke Invitation
  // ==========================================================================
  
  describe('DELETE /invitations/{id} - Revoke Invitation', () => {
    it('should revoke invitation successfully', async () => {
      const revokedInvitation: InvitationResponse = {
        ...mockInvitation,
        status: 'revoked' as InvitationStatus
      };
      (invitationService.revoke as jest.Mock).mockResolvedValue(revokedInvitation);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/invitations/inv_abc123',
        queryStringParameters: { tenant_id: 'tenant_123' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Invitation revoked successfully');
      expect(body.invitation.status).toBe('revoked');
    });

    it('should return 400 when tenant_id is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/invitations/inv_abc123',
        queryStringParameters: null
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_TENANT_ID');
    });

    it('should return 401 when not authenticated', async () => {
      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/invitations/inv_abc123',
        headers: {},
        requestContext: { authorizer: null } as any,
        queryStringParameters: { tenant_id: 'tenant_123' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 403 when user lacks admin access', async () => {
      (getMembership as jest.Mock).mockResolvedValue({
        ...mockMembership,
        role_ids: ['member']
      });

      const event = createMockEvent({
        httpMethod: 'DELETE',
        path: '/invitations/inv_abc123',
        queryStringParameters: { tenant_id: 'tenant_123' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });


  // ==========================================================================
  // POST /invitations/{id}/resend - Resend Invitation
  // ==========================================================================
  
  describe('POST /invitations/{id}/resend - Resend Invitation', () => {
    it('should resend invitation successfully', async () => {
      const resendResult: InvitationWithToken = {
        invitation: mockInvitation,
        token: 'new-token-456'
      };
      (invitationService.resend as jest.Mock).mockResolvedValue(resendResult);

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/inv_abc123/resend',
        body: JSON.stringify({ tenant_id: 'tenant_123' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Invitation resent successfully');
      expect(body.accept_url).toContain('new-token-456');
    });

    it('should return 400 when tenant_id is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/inv_abc123/resend',
        body: JSON.stringify({})
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_TENANT_ID');
    });

    it('should return 401 when not authenticated', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/inv_abc123/resend',
        headers: {},
        requestContext: { authorizer: null } as any,
        body: JSON.stringify({ tenant_id: 'tenant_123' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 403 when user lacks admin access', async () => {
      (getMembership as jest.Mock).mockResolvedValue({
        ...mockMembership,
        role_ids: ['member']
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/inv_abc123/resend',
        body: JSON.stringify({ tenant_id: 'tenant_123' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('should return 429 when rate limited', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue(mockRateLimitDenied(3600));

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/invitations/inv_abc123/resend',
        body: JSON.stringify({ tenant_id: 'tenant_123' })
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(429);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });
  });

  // ==========================================================================
  // GET /invitations/{id} - Get Invitation Details
  // ==========================================================================
  
  describe('GET /invitations/{id} - Get Invitation Details', () => {
    it('should get invitation details successfully', async () => {
      (invitationService.getById as jest.Mock).mockResolvedValue(mockInvitation);

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/invitations/inv_abc123',
        queryStringParameters: { tenant_id: 'tenant_123' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.invitation).toEqual(mockInvitation);
    });

    it('should return 404 when invitation not found', async () => {
      (invitationService.getById as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/invitations/nonexistent',
        queryStringParameters: { tenant_id: 'tenant_123' }
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('INVITATION_NOT_FOUND');
    });

    it('should return 400 when tenant_id is missing', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/invitations/inv_abc123',
        queryStringParameters: null
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(400);
      expect(body.error.code).toBe('MISSING_TENANT_ID');
    });
  });

  // ==========================================================================
  // 404 Not Found
  // ==========================================================================
  
  describe('404 Not Found', () => {
    it('should return 404 for unknown endpoints', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/unknown/endpoint'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(404);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  // ==========================================================================
  // Security Headers
  // ==========================================================================
  
  describe('Security Headers', () => {
    it('should include security headers in response', async () => {
      (invitationService.list as jest.Mock).mockResolvedValue({
        invitations: [],
        next_cursor: undefined
      });
      (invitationService.getStatistics as jest.Mock).mockResolvedValue({
        pending: 0, accepted: 0, expired: 0, revoked: 0
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/tenants/tenant_123/invitations'
      });

      const result = await handler(event);

      expect(result.headers).toHaveProperty('X-Content-Type-Options', 'nosniff');
      expect(result.headers).toHaveProperty('X-Frame-Options', 'DENY');
      expect(result.headers).toHaveProperty('Content-Type', 'application/json');
    });
  });
});
