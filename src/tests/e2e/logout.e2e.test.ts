/**
 * User Logout E2E Tests
 * 
 * Task 1.6: Logout Handler
 * Validates: Requirements 2.1, 9.5
 * 
 * @e2e-test
 * @phase Phase 1
 * @security-critical
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies - must be before handler import
jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../../repositories/session.repository', () => ({
  findSessionByRefreshToken: jest.fn(),
  deleteSession: jest.fn().mockResolvedValue(undefined),
  deleteUserSessions: jest.fn().mockResolvedValue(3)
}));

// Import handler AFTER mocks
import { handler } from '../../handlers/logout-handler';
import { verifyAccessToken } from '../../utils/jwt';
import { 
  findSessionByRefreshToken, 
  deleteSession, 
  deleteUserSessions 
} from '../../repositories/session.repository';

const mockPayload = {
  sub: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  type: 'access',
  jti: 'token-jti-123'
};

const mockSession = {
  id: 'session-123',
  user_id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  refresh_token_hash: 'hashed-token',
  created_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
};

function createMockEvent(
  body: object | null = null,
  accessToken: string = 'valid-access-token'
): APIGatewayProxyEvent {
  return {
    body: body ? JSON.stringify(body) : null,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`
    },
    httpMethod: 'POST',
    isBase64Encoded: false,
    path: '/v1/auth/logout',
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: '192.168.1.1'
      }
    } as any,
    resource: '/v1/auth/logout',
    multiValueHeaders: {}
  };
}

describe('User Logout E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (verifyAccessToken as jest.Mock).mockResolvedValue(mockPayload);
    (findSessionByRefreshToken as jest.Mock).mockResolvedValue(mockSession);
  });

  describe('Basic Logout', () => {
    it('should logout successfully without refresh token', async () => {
      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Logout successful. Please discard your tokens.');
    });

    it('should logout and terminate specific session with refresh token', async () => {
      const event = createMockEvent({
        refresh_token: 'valid-refresh-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Session terminated successfully');
      expect(deleteSession).toHaveBeenCalledWith(
        'session-123',
        'clinisyn-psychologists',
        'user-123'
      );
    });

    it('should handle non-existent session gracefully', async () => {
      (findSessionByRefreshToken as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        refresh_token: 'non-existent-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Session terminated successfully');
      expect(deleteSession).not.toHaveBeenCalled();
    });
  });

  describe('Logout All Devices', () => {
    it('should terminate all sessions when logout_all is true', async () => {
      const event = createMockEvent({
        logout_all: true
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('All sessions terminated successfully');
      expect(body.sessions_terminated).toBe(3);
      expect(deleteUserSessions).toHaveBeenCalledWith(
        'clinisyn-psychologists',
        'user-123'
      );
    });

    it('should not call deleteUserSessions when logout_all is false', async () => {
      const event = createMockEvent({
        logout_all: false
      });

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
      expect(deleteUserSessions).not.toHaveBeenCalled();
    });
  });

  describe('Authorization Validation', () => {
    it('should reject request without Authorization header', async () => {
      const event = {
        ...createMockEvent(),
        headers: { 'Content-Type': 'application/json' }
      };

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
      expect(body.error.message).toBe('Authorization header with Bearer token is required');
    });

    it('should reject request with invalid Bearer format', async () => {
      const event = {
        ...createMockEvent(),
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': 'InvalidFormat token123'
        }
      };

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject expired access token', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Token expired'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('TOKEN_EXPIRED');
    });

    it('should reject invalid access token', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('Session Ownership Validation', () => {
    it('should reject terminating session belonging to another user', async () => {
      (findSessionByRefreshToken as jest.Mock).mockResolvedValue({
        ...mockSession,
        user_id: 'different-user-456'
      });

      const event = createMockEvent({
        refresh_token: 'other-users-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
      expect(body.error.message).toBe('Cannot terminate session belonging to another user');
      expect(deleteSession).not.toHaveBeenCalled();
    });

    it('should reject terminating session from different realm', async () => {
      (findSessionByRefreshToken as jest.Mock).mockResolvedValue({
        ...mockSession,
        realm_id: 'different-realm'
      });

      const event = createMockEvent({
        refresh_token: 'different-realm-token'
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(403);
      expect(body.error.code).toBe('FORBIDDEN');
    });
  });

  describe('Request Body Validation', () => {
    it('should handle invalid JSON body', async () => {
      const event = {
        ...createMockEvent(),
        body: 'invalid-json{'
      };

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_JSON');
    });

    it('should handle empty body', async () => {
      const event = createMockEvent();

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
    });
  });

  describe('Response Headers', () => {
    it('should include CORS headers', async () => {
      const event = createMockEvent();

      const response = await handler(event);

      expect(response.headers).toHaveProperty('Access-Control-Allow-Origin', '*');
      expect(response.headers).toHaveProperty('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    });

    it('should include Content-Type header', async () => {
      const event = createMockEvent();

      const response = await handler(event);

      expect(response.headers).toHaveProperty('Content-Type', 'application/json');
    });
  });

  describe('Error Response Format', () => {
    it('should include timestamp in error response', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.error.timestamp).toBeDefined();
      expect(new Date(body.error.timestamp).getTime()).not.toBeNaN();
    });

    it('should include request_id in error response', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(body.error.request_id).toBe('test-request-id');
    });
  });

  describe('Internal Error Handling', () => {
    it('should handle unexpected errors gracefully', async () => {
      (verifyAccessToken as jest.Mock).mockResolvedValue(mockPayload);
      (deleteUserSessions as jest.Mock).mockRejectedValue(new Error('Database error'));

      const event = createMockEvent({
        logout_all: true
      });

      const response = await handler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(500);
      expect(body.error.code).toBe('INTERNAL_ERROR');
      expect(body.error.message).toBe('An unexpected error occurred');
    });
  });

  describe('Case Insensitive Authorization Header', () => {
    it('should accept lowercase authorization header', async () => {
      const event = {
        ...createMockEvent(),
        headers: {
          'Content-Type': 'application/json',
          'authorization': 'Bearer valid-token'
        }
      };

      const response = await handler(event);

      expect(response.statusCode).toBe(200);
    });
  });
});
