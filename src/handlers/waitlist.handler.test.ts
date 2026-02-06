/**
 * Waitlist Handler Tests
 * 
 * Tests for waitlist Lambda handler endpoints:
 * - POST /waitlist - Join waitlist
 * - GET /waitlist - List entries (admin)
 * - POST /waitlist/{id}/approve - Approve entry
 * - POST /waitlist/{id}/reject - Reject entry
 * - POST /waitlist/bulk-approve - Bulk approve
 * - GET /waitlist/position/{id} - Get position
 * - GET /waitlist/stats - Get statistics
 * - DELETE /waitlist/{id} - Delete entry
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from './waitlist.handler';

// Mock dependencies
const mockJoin = jest.fn();
const mockApprove = jest.fn();
const mockReject = jest.fn();
const mockBulkApprove = jest.fn();
const mockGetPosition = jest.fn();
const mockList = jest.fn();
const mockGetStats = jest.fn();
const mockGetEntry = jest.fn();
const mockDeleteEntry = jest.fn();
const mockIsWaitlistModeEnabled = jest.fn();

jest.mock('../services/waitlist.service', () => ({
  createWaitlistService: jest.fn(() => ({
    join: (...args: unknown[]) => mockJoin(...args),
    approve: (...args: unknown[]) => mockApprove(...args),
    reject: (...args: unknown[]) => mockReject(...args),
    bulkApprove: (...args: unknown[]) => mockBulkApprove(...args),
    getPosition: (...args: unknown[]) => mockGetPosition(...args),
    list: (...args: unknown[]) => mockList(...args),
    getStats: (...args: unknown[]) => mockGetStats(...args),
    getEntry: (...args: unknown[]) => mockGetEntry(...args),
    deleteEntry: (...args: unknown[]) => mockDeleteEntry(...args),
    isWaitlistModeEnabled: () => mockIsWaitlistModeEnabled()
  })),
  WaitlistError: class WaitlistError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.code = code;
    }
  }
}));

const mockCheckRateLimit = jest.fn();
jest.mock('../services/ratelimit.service', () => ({
  checkRateLimit: (...args: unknown[]) => mockCheckRateLimit(...args)
}));

const mockLogAuditEvent = jest.fn();
jest.mock('../services/audit.service', () => ({
  logAuditEvent: (...args: unknown[]) => mockLogAuditEvent(...args),
  AuditEventType: { ADMIN_ACTION: 'admin_action' },
  AuditResult: { SUCCESS: 'success', FAILURE: 'failure' }
}));

jest.mock('../repositories/realm.repository', () => ({
  findRealmById: jest.fn().mockResolvedValue({
    id: 'realm_123',
    name: 'Test Realm',
    settings: { waitlist_mode_enabled: true }
  })
}));

// Helper to create mock event
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/waitlist',
    headers: {
      'Content-Type': 'application/json'
    },
    queryStringParameters: {
      realm_id: 'realm_123'
    },
    pathParameters: null,
    body: null,
    isBase64Encoded: false,
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: '192.168.1.1'
      },
      authorizer: null
    } as any,
    resource: '',
    stageVariables: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    ...overrides
  } as APIGatewayProxyEvent;
}

// Helper to create authenticated event
function createAuthenticatedEvent(
  overrides: Partial<APIGatewayProxyEvent> = {},
  isAdmin = true
): APIGatewayProxyEvent {
  return createMockEvent({
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer test-token'
    },
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: '192.168.1.1'
      },
      authorizer: {
        userId: 'user_123',
        realmId: 'realm_123',
        email: 'admin@test.com',
        role: isAdmin ? 'admin' : 'member'
      }
    } as any,
    ...overrides
  });
}

describe('Waitlist Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockCheckRateLimit.mockResolvedValue({ allowed: true, remaining: 10 });
  });

  describe('POST /waitlist - Join Waitlist', () => {
    it('should successfully join waitlist with valid email', async () => {
      const mockEntry = {
        id: 'entry_123',
        email: 'test@example.com',
        position: 42,
        status: 'pending'
      };

      mockJoin.mockResolvedValue({
        entry: mockEntry,
        referral_code: 'ABC12345',
        already_exists: false
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/waitlist',
        body: JSON.stringify({
          email: 'test@example.com',
          metadata: {
            first_name: 'Test',
            last_name: 'User'
          }
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.data.entry_id).toBe('entry_123');
      expect(body.data.position).toBe(42);
      expect(body.data.referral_code).toBe('ABC12345');
    });

    it('should return 400 for missing email', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/waitlist',
        body: JSON.stringify({})
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('MISSING_EMAIL');
    });

    it('should return 400 for invalid email format', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/waitlist',
        body: JSON.stringify({
          email: 'invalid-email'
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('INVALID_EMAIL');
    });

    it('should return 400 for missing realm_id', async () => {
      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/waitlist',
        queryStringParameters: null,
        body: JSON.stringify({
          email: 'test@example.com'
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('MISSING_REALM_ID');
    });

    it('should return 429 when rate limited', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        retryAfter: 60
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/waitlist',
        body: JSON.stringify({
          email: 'test@example.com'
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(429);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should handle referral code', async () => {
      const mockEntry = {
        id: 'entry_123',
        email: 'test@example.com',
        position: 10,
        status: 'pending'
      };

      mockJoin.mockResolvedValue({
        entry: mockEntry,
        referral_code: 'NEW12345',
        already_exists: false
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/waitlist',
        body: JSON.stringify({
          email: 'test@example.com',
          referral_code: 'EXISTING1'
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(201);
      expect(mockJoin).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'test@example.com',
          referralCode: 'EXISTING1'
        })
      );
    });
  });

  describe('GET /waitlist - List Entries (Admin)', () => {
    it('should list entries for admin user', async () => {
      const mockEntries = [
        { id: 'entry_1', email: 'user1@test.com', position: 1, status: 'pending' },
        { id: 'entry_2', email: 'user2@test.com', position: 2, status: 'pending' }
      ];

      mockList.mockResolvedValue({
        entries: mockEntries,
        nextCursor: null
      });

      const event = createAuthenticatedEvent({
        httpMethod: 'GET',
        path: '/waitlist'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.entries).toHaveLength(2);
      expect(body.data.count).toBe(2);
    });

    it('should return 401 for unauthenticated request', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/waitlist'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 403 for non-admin user', async () => {
      const event = createAuthenticatedEvent(
        {
          httpMethod: 'GET',
          path: '/waitlist'
        },
        false // not admin
      );

      const response = await handler(event);

      expect(response.statusCode).toBe(403);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('should filter by status', async () => {
      mockList.mockResolvedValue({
        entries: [],
        nextCursor: null
      });

      const event = createAuthenticatedEvent({
        httpMethod: 'GET',
        path: '/waitlist',
        queryStringParameters: {
          realm_id: 'realm_123',
          status: 'approved'
        }
      });

      await handler(event);

      expect(mockList).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'approved'
        })
      );
    });

    it('should support pagination', async () => {
      mockList.mockResolvedValue({
        entries: [],
        nextCursor: 'next_cursor_123'
      });

      const event = createAuthenticatedEvent({
        httpMethod: 'GET',
        path: '/waitlist',
        queryStringParameters: {
          realm_id: 'realm_123',
          limit: '10',
          cursor: 'prev_cursor'
        }
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.next_cursor).toBe('next_cursor_123');
    });
  });

  describe('POST /waitlist/{id}/approve - Approve Entry', () => {
    it('should approve entry successfully', async () => {
      const mockEntry = {
        id: 'entry_123',
        email: 'test@example.com',
        status: 'approved',
        approved_at: new Date().toISOString(),
        approved_by: 'user_123'
      };

      mockApprove.mockResolvedValue(mockEntry);

      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/entry_123/approve',
        body: JSON.stringify({
          send_invitation: true,
          invitation_role: 'member'
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.entry.status).toBe('approved');
      expect(mockApprove).toHaveBeenCalledWith(
        'entry_123',
        'user_123',
        expect.objectContaining({
          sendInvitation: true,
          invitationRole: 'member'
        })
      );
    });

    it('should return 404 for non-existent entry', async () => {
      mockApprove.mockResolvedValue(null);

      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/nonexistent/approve',
        body: JSON.stringify({})
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('ENTRY_NOT_FOUND');
    });

    it('should return 403 for non-admin user', async () => {
      const event = createAuthenticatedEvent(
        {
          httpMethod: 'POST',
          path: '/waitlist/entry_123/approve',
          body: JSON.stringify({})
        },
        false
      );

      const response = await handler(event);

      expect(response.statusCode).toBe(403);
    });
  });

  describe('POST /waitlist/{id}/reject - Reject Entry', () => {
    it('should reject entry successfully', async () => {
      const mockEntry = {
        id: 'entry_123',
        email: 'test@example.com',
        status: 'rejected',
        rejected_at: new Date().toISOString(),
        rejected_by: 'user_123'
      };

      mockReject.mockResolvedValue(mockEntry);

      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/entry_123/reject',
        body: JSON.stringify({
          reason: 'Not eligible',
          send_notification: true
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.entry.status).toBe('rejected');
      expect(mockReject).toHaveBeenCalledWith(
        'entry_123',
        'user_123',
        expect.objectContaining({
          reason: 'Not eligible',
          sendNotification: true
        })
      );
    });

    it('should return 404 for non-existent entry', async () => {
      mockReject.mockResolvedValue(null);

      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/nonexistent/reject',
        body: JSON.stringify({})
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(404);
    });
  });

  describe('POST /waitlist/bulk-approve - Bulk Approve', () => {
    it('should bulk approve entries successfully', async () => {
      mockBulkApprove.mockResolvedValue({
        approved: ['entry_1', 'entry_2', 'entry_3'],
        failed: []
      });

      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/bulk-approve',
        body: JSON.stringify({
          entry_ids: ['entry_1', 'entry_2', 'entry_3'],
          send_invitation: true
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.approved_count).toBe(3);
      expect(body.data.failed_count).toBe(0);
    });

    it('should return 400 for missing entry_ids', async () => {
      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/bulk-approve',
        body: JSON.stringify({})
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('MISSING_ENTRY_IDS');
    });

    it('should return 400 for too many entries', async () => {
      const tooManyIds = Array.from({ length: 101 }, (_, i) => `entry_${i}`);

      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/bulk-approve',
        body: JSON.stringify({
          entry_ids: tooManyIds
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('TOO_MANY_ENTRIES');
    });

    it('should handle partial failures', async () => {
      mockBulkApprove.mockResolvedValue({
        approved: ['entry_1', 'entry_2'],
        failed: ['entry_3']
      });

      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/bulk-approve',
        body: JSON.stringify({
          entry_ids: ['entry_1', 'entry_2', 'entry_3']
        })
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.approved_count).toBe(2);
      expect(body.data.failed_count).toBe(1);
      expect(body.data.failed).toContain('entry_3');
    });
  });

  describe('GET /waitlist/position/{id} - Get Position', () => {
    it('should return position for valid entry', async () => {
      mockGetPosition.mockResolvedValue({
        position: 42,
        total: 100
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/waitlist/position/entry_123'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.position).toBe(42);
      expect(body.data.total).toBe(100);
    });

    it('should return 404 for non-existent entry', async () => {
      mockGetPosition.mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/waitlist/position/nonexistent'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(404);
    });

    it('should be rate limited', async () => {
      mockCheckRateLimit.mockResolvedValue({
        allowed: false,
        remaining: 0,
        retryAfter: 30
      });

      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/waitlist/position/entry_123'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(429);
    });
  });

  describe('GET /waitlist/stats - Get Statistics', () => {
    it('should return statistics for admin', async () => {
      mockGetStats.mockResolvedValue({
        total: 500,
        pending: 400,
        approved: 80,
        rejected: 20,
        invited: 75
      });

      const event = createAuthenticatedEvent({
        httpMethod: 'GET',
        path: '/waitlist/stats'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.stats.total).toBe(500);
      expect(body.data.stats.pending).toBe(400);
    });

    it('should return 403 for non-admin', async () => {
      const event = createAuthenticatedEvent(
        {
          httpMethod: 'GET',
          path: '/waitlist/stats'
        },
        false
      );

      const response = await handler(event);

      expect(response.statusCode).toBe(403);
    });
  });

  describe('GET /waitlist/{id} - Get Entry Details', () => {
    it('should return entry details for admin', async () => {
      const mockEntry = {
        id: 'entry_123',
        email: 'test@example.com',
        position: 42,
        status: 'pending',
        metadata: { first_name: 'Test' }
      };

      mockGetEntry.mockResolvedValue(mockEntry);

      const event = createAuthenticatedEvent({
        httpMethod: 'GET',
        path: '/waitlist/entry_123'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.entry.id).toBe('entry_123');
    });

    it('should return 404 for non-existent entry', async () => {
      mockGetEntry.mockResolvedValue(null);

      const event = createAuthenticatedEvent({
        httpMethod: 'GET',
        path: '/waitlist/nonexistent'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(404);
    });
  });

  describe('DELETE /waitlist/{id} - Delete Entry', () => {
    it('should delete entry successfully', async () => {
      mockDeleteEntry.mockResolvedValue(true);

      const event = createAuthenticatedEvent({
        httpMethod: 'DELETE',
        path: '/waitlist/entry_123'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.data.entry_id).toBe('entry_123');
    });

    it('should return 404 for non-existent entry', async () => {
      mockDeleteEntry.mockResolvedValue(false);

      const event = createAuthenticatedEvent({
        httpMethod: 'DELETE',
        path: '/waitlist/nonexistent'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(404);
    });

    it('should return 403 for non-admin', async () => {
      const event = createAuthenticatedEvent(
        {
          httpMethod: 'DELETE',
          path: '/waitlist/entry_123'
        },
        false
      );

      const response = await handler(event);

      expect(response.statusCode).toBe(403);
    });
  });

  describe('CORS Preflight', () => {
    it('should handle OPTIONS request', async () => {
      const event = createMockEvent({
        httpMethod: 'OPTIONS',
        path: '/waitlist',
        headers: {
          'Origin': 'https://app.zalt.io',
          'Access-Control-Request-Method': 'POST'
        }
      });

      const response = await handler(event);

      // handlePreflight returns 204 for valid preflight requests
      expect([200, 204]).toContain(response.statusCode);
    });
  });

  describe('404 Not Found', () => {
    it('should return 404 for unknown endpoint', async () => {
      const event = createMockEvent({
        httpMethod: 'GET',
        path: '/waitlist/unknown/endpoint/here'
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('Audit Logging', () => {
    it('should log audit event on join', async () => {
      mockJoin.mockResolvedValue({
        entry: { id: 'entry_123', email: 'test@example.com', position: 1 },
        referral_code: 'ABC123',
        already_exists: false
      });

      const event = createMockEvent({
        httpMethod: 'POST',
        path: '/waitlist',
        body: JSON.stringify({ email: 'test@example.com' })
      });

      await handler(event);

      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'waitlist_join',
          realmId: 'realm_123'
        })
      );
    });

    it('should log audit event on approve', async () => {
      mockApprove.mockResolvedValue({
        id: 'entry_123',
        email: 'test@example.com',
        status: 'approved'
      });

      const event = createAuthenticatedEvent({
        httpMethod: 'POST',
        path: '/waitlist/entry_123/approve',
        body: JSON.stringify({})
      });

      await handler(event);

      expect(mockLogAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'waitlist_approve',
          userId: 'user_123'
        })
      );
    });
  });
});
