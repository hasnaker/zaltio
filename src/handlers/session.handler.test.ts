/**
 * Session Handler Tests
 * Validates: Requirements 13.1, 13.2, 13.3, 13.4
 * 
 * Tests for:
 * - GET /sessions - List all active sessions
 * - GET /sessions/{id} - Get session details
 * - DELETE /sessions/{id} - Revoke specific session
 * - DELETE /sessions - Revoke all sessions except current
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies before importing handler
jest.mock('../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../repositories/session.repository', () => ({
  getUserSessions: jest.fn(),
  findSessionById: jest.fn(),
  deleteSession: jest.fn(),
  deleteUserSessions: jest.fn(),
  updateSessionLastActivity: jest.fn()
}));

jest.mock('../services/ratelimit.service', () => ({
  checkRateLimit: jest.fn()
}));

jest.mock('../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn()
}));

jest.mock('../services/webhook-events.service', () => ({
  dispatchSessionRevoked: jest.fn()
}));

jest.mock('../services/geo-velocity.service', () => ({
  lookupIpLocation: jest.fn(),
  checkGeoVelocity: jest.fn(),
  getRealmVelocityConfig: jest.fn()
}));

import { handler } from './session.handler';
import { verifyAccessToken } from '../utils/jwt';
import {
  getUserSessions,
  findSessionById,
  deleteSession,
  updateSessionLastActivity
} from '../repositories/session.repository';
import { checkRateLimit } from '../services/ratelimit.service';
import { logSecurityEvent } from '../services/security-logger.service';
import { dispatchSessionRevoked } from '../services/webhook-events.service';
import { lookupIpLocation, checkGeoVelocity, getRealmVelocityConfig } from '../services/geo-velocity.service';

// Test data
const TEST_USER_ID = 'user_test123';
const TEST_REALM_ID = 'realm_test123';
const TEST_SESSION_ID = 'session_test123';
const TEST_CURRENT_SESSION_ID = 'session_current123';

const mockJwtPayload = {
  sub: TEST_USER_ID,
  realm_id: TEST_REALM_ID,
  email: 'test@example.com',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 900,
  type: 'access' as const
};

const mockSession = {
  id: TEST_SESSION_ID,
  user_id: TEST_USER_ID,
  realm_id: TEST_REALM_ID,
  access_token: 'mock_access_token',
  refresh_token: 'mock_refresh_token',
  refresh_token_hash: 'mock_hash',
  expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  created_at: new Date().toISOString(),
  last_used_at: new Date().toISOString(),
  ip_address: '192.168.1.100',
  user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
  revoked: false
};

const mockCurrentSession = {
  ...mockSession,
  id: TEST_CURRENT_SESSION_ID
};

function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/sessions',
    pathParameters: null,
    queryStringParameters: null,
    headers: {
      Authorization: 'Bearer mock_access_token'
    },
    body: null,
    isBase64Encoded: false,
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: '127.0.0.1'
      }
    } as any,
    resource: '',
    stageVariables: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    ...overrides
  };
}

describe('Session Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mock implementations
    (verifyAccessToken as jest.Mock).mockResolvedValue(mockJwtPayload);
    (checkRateLimit as jest.Mock).mockResolvedValue({
      allowed: true,
      remaining: 99,
      resetAt: Date.now() + 60000
    });
    (logSecurityEvent as jest.Mock).mockResolvedValue(undefined);
    (dispatchSessionRevoked as jest.Mock).mockResolvedValue({ webhooks_triggered: 1, delivery_ids: [] });
    (updateSessionLastActivity as jest.Mock).mockResolvedValue(true);
    // Default: no geolocation data (returns null)
    (lookupIpLocation as jest.Mock).mockResolvedValue(null);
    // Default: no impossible travel detected
    (checkGeoVelocity as jest.Mock).mockResolvedValue({
      isImpossibleTravel: false,
      isSuspicious: false,
      riskLevel: 'low',
      distanceKm: 0,
      timeElapsedHours: 0,
      speedKmh: 0,
      currentLocation: { latitude: 0, longitude: 0 },
      requiresMfa: false,
      requiresVerification: false,
      blocked: false
    });
    // Default velocity config (non-blocking)
    (getRealmVelocityConfig as jest.Mock).mockReturnValue({
      maxSpeedKmh: 1000,
      suspiciousSpeedKmh: 500,
      minTimeBetweenChecks: 60,
      sameCityToleranceKm: 50,
      blockOnImpossibleTravel: false,
      requireMfaOnSuspicious: true,
      sendAlertOnDetection: true
    });
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Authentication', () => {
    it('should return 401 when no Authorization header is provided', async () => {
      const event = createMockEvent({
        headers: {}
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 when Authorization header is malformed', async () => {
      const event = createMockEvent({
        headers: {
          Authorization: 'InvalidToken'
        }
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 when access token is expired', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Token expired'));

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('TOKEN_EXPIRED');
    });

    it('should return 401 when access token is invalid', async () => {
      (verifyAccessToken as jest.Mock).mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('Rate Limiting', () => {
    it('should return 429 when rate limit is exceeded', async () => {
      (checkRateLimit as jest.Mock).mockResolvedValue({
        allowed: false,
        remaining: 0,
        retryAfter: 60,
        resetAt: Date.now() + 60000
      });

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(429);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('RATE_LIMITED');
      expect(body.error.details.retry_after).toBe(60);
    });
  });

  describe('GET /sessions - List Sessions', () => {
    /**
     * Validates: Requirement 13.1
     * WHEN user requests sessions THEN THE Zalt_Platform SHALL return all active sessions
     */
    it('should return all active sessions for the user', async () => {
      const sessions = [mockSession, mockCurrentSession];
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.sessions).toHaveLength(2);
      expect(body.total).toBe(2);
      expect(getUserSessions).toHaveBeenCalledWith(TEST_REALM_ID, TEST_USER_ID);
    });

    it('should return empty array when user has no sessions', async () => {
      (getUserSessions as jest.Mock).mockResolvedValue([]);

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.sessions).toHaveLength(0);
      expect(body.total).toBe(0);
    });

    it('should filter out revoked sessions', async () => {
      const revokedSession = { ...mockSession, id: 'revoked_session', revoked: true };
      (getUserSessions as jest.Mock).mockResolvedValue([mockSession, revokedSession]);

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.sessions).toHaveLength(1);
      expect(body.sessions[0].id).toBe(TEST_SESSION_ID);
    });

    /**
     * Validates: Requirement 13.2
     * THE session info SHALL include: device, browser, IP, location, last_activity, is_current
     */
    it('should include required session info fields', async () => {
      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      const session = body.sessions[0];
      
      expect(session).toHaveProperty('id');
      expect(session).toHaveProperty('device');
      expect(session).toHaveProperty('browser');
      expect(session).toHaveProperty('ip_address');
      expect(session).toHaveProperty('last_activity');
      expect(session).toHaveProperty('created_at');
      expect(session).toHaveProperty('is_current');
      expect(session).toHaveProperty('user_agent');
    });

    it('should correctly parse device type from user agent', async () => {
      const mobileSession = {
        ...mockSession,
        user_agent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)'
      };
      (getUserSessions as jest.Mock).mockResolvedValue([mobileSession]);

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.sessions[0].device).toBe('Mobile');
    });

    it('should correctly parse browser name from user agent', async () => {
      const firefoxSession = {
        ...mockSession,
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0'
      };
      (getUserSessions as jest.Mock).mockResolvedValue([firefoxSession]);

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.sessions[0].browser).toBe('Firefox 119');
    });

    it('should mask IP address for privacy', async () => {
      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.sessions[0].ip_address).toBe('192.168.*.*');
    });

    it('should log session list request', async () => {
      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);

      const event = createMockEvent();
      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'sessions_listed',
          realm_id: TEST_REALM_ID,
          user_id: TEST_USER_ID
        })
      );
    });

    /**
     * Session Info Enrichment Tests
     * Validates: Requirement 13.2 - Device type, browser, IP geolocation, last activity
     */
    describe('Session Info Enrichment', () => {
      /**
       * Validates: Requirement 13.2 - IP geolocation (city, country, country_code)
       */
      it('should enrich session with geolocation data when available', async () => {
        (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
        (lookupIpLocation as jest.Mock).mockResolvedValue({
          city: 'Istanbul',
          country: 'Turkey',
          countryCode: 'TR',
          latitude: 41.0082,
          longitude: 28.9784
        });

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].location).toEqual({
          city: 'Istanbul',
          country: 'Turkey',
          country_code: 'TR'
        });
      });

      it('should handle missing geolocation data gracefully', async () => {
        (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
        (lookupIpLocation as jest.Mock).mockResolvedValue(null);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].location).toBeUndefined();
      });

      it('should handle geolocation lookup errors gracefully', async () => {
        (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
        (lookupIpLocation as jest.Mock).mockRejectedValue(new Error('Geolocation service unavailable'));

        const event = createMockEvent();
        const result = await handler(event);

        // Should still succeed, just without location data
        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].location).toBeUndefined();
      });

      /**
       * Validates: Requirement 13.2 - Device type detection (Desktop, Mobile, Tablet, Unknown)
       */
      it('should detect tablet device type', async () => {
        const tabletSession = {
          ...mockSession,
          user_agent: 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([tabletSession]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].device).toBe('Tablet');
      });

      it('should detect Android tablet device type', async () => {
        const tabletSession = {
          ...mockSession,
          user_agent: 'Mozilla/5.0 (Linux; Android 10; SM-T510) AppleWebKit/537.36'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([tabletSession]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].device).toBe('Tablet');
      });

      it('should detect desktop device type', async () => {
        const desktopSession = {
          ...mockSession,
          user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([desktopSession]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].device).toBe('Desktop');
      });

      it('should return Unknown for unrecognized user agents', async () => {
        const unknownSession = {
          ...mockSession,
          user_agent: 'CustomBot/1.0'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([unknownSession]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].device).toBe('Unknown');
      });

      /**
       * Validates: Requirement 13.2 - Browser detection with version
       */
      it('should detect Chrome browser with version', async () => {
        const chromeSession = {
          ...mockSession,
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.6099.130'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([chromeSession]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].browser).toBe('Chrome 120');
      });

      it('should detect Edge browser', async () => {
        const edgeSession = {
          ...mockSession,
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([edgeSession]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].browser).toBe('Edge 120');
      });

      it('should detect Safari browser', async () => {
        const safariSession = {
          ...mockSession,
          user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([safariSession]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].browser).toBe('Safari 17');
      });

      it('should detect Opera browser', async () => {
        const operaSession = {
          ...mockSession,
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([operaSession]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].browser).toBe('Opera 106');
      });

      /**
       * Validates: Requirement 13.2 - Last activity tracking
       */
      it('should update last activity for current session', async () => {
        // Create a token that includes the current session ID in jti
        const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
          Buffer.from(JSON.stringify({ 
            ...mockJwtPayload, 
            jti: TEST_SESSION_ID 
          })).toString('base64url') + 
          '.signature';

        (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);

        const event = createMockEvent({
          headers: {
            Authorization: `Bearer ${tokenWithJti}`
          }
        });
        await handler(event);

        expect(updateSessionLastActivity).toHaveBeenCalledWith(
          TEST_SESSION_ID,
          TEST_REALM_ID,
          TEST_USER_ID
        );
      });

      it('should not fail if last activity update fails', async () => {
        const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
          Buffer.from(JSON.stringify({ 
            ...mockJwtPayload, 
            jti: TEST_SESSION_ID 
          })).toString('base64url') + 
          '.signature';

        (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
        (updateSessionLastActivity as jest.Mock).mockRejectedValue(new Error('Update failed'));

        const event = createMockEvent({
          headers: {
            Authorization: `Bearer ${tokenWithJti}`
          }
        });
        const result = await handler(event);

        // Should still succeed
        expect(result.statusCode).toBe(200);
      });

      it('should include last_activity timestamp in session info', async () => {
        const sessionWithActivity = {
          ...mockSession,
          last_used_at: '2026-01-25T10:30:00Z'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([sessionWithActivity]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].last_activity).toBe('2026-01-25T10:30:00Z');
      });

      it('should use created_at as fallback when last_used_at is not set', async () => {
        const sessionWithoutActivity = {
          ...mockSession,
          last_used_at: undefined,
          created_at: '2026-01-24T08:00:00Z'
        };
        (getUserSessions as jest.Mock).mockResolvedValue([sessionWithoutActivity]);

        const event = createMockEvent();
        const result = await handler(event);

        expect(result.statusCode).toBe(200);
        const body = JSON.parse(result.body);
        expect(body.sessions[0].last_activity).toBe('2026-01-24T08:00:00Z');
      });
    });
  });

  describe('GET /sessions/{id} - Get Session Details', () => {
    /**
     * Validates: Requirement 13.2
     * THE session info SHALL include: device, browser, IP, location, last_activity, is_current
     */
    it('should return session details for valid session ID', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(mockSession);

      const event = createMockEvent({
        pathParameters: { id: TEST_SESSION_ID }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.session.id).toBe(TEST_SESSION_ID);
      expect(findSessionById).toHaveBeenCalledWith(TEST_SESSION_ID, TEST_REALM_ID, TEST_USER_ID);
    });

    it('should return 404 when session is not found', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        pathParameters: { id: 'nonexistent_session' }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('SESSION_NOT_FOUND');
    });

    it('should return 403 when session belongs to another user', async () => {
      const otherUserSession = { ...mockSession, user_id: 'other_user' };
      (findSessionById as jest.Mock).mockResolvedValue(otherUserSession);

      const event = createMockEvent({
        pathParameters: { id: TEST_SESSION_ID }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(403);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('should return 404 when session is revoked', async () => {
      const revokedSession = { ...mockSession, revoked: true };
      (findSessionById as jest.Mock).mockResolvedValue(revokedSession);

      const event = createMockEvent({
        pathParameters: { id: TEST_SESSION_ID }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('SESSION_NOT_FOUND');
    });

    it('should log session detail view', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(mockSession);

      const event = createMockEvent({
        pathParameters: { id: TEST_SESSION_ID }
      });
      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_details_viewed',
          details: expect.objectContaining({
            session_id: TEST_SESSION_ID
          })
        })
      );
    });

    /**
     * Session Details Enrichment Tests
     * Validates: Requirement 13.2 - Full session info enrichment
     */
    it('should enrich session details with geolocation data', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(mockSession);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        city: 'New York',
        country: 'United States',
        countryCode: 'US',
        latitude: 40.7128,
        longitude: -74.0060
      });

      const event = createMockEvent({
        pathParameters: { id: TEST_SESSION_ID }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.session.location).toEqual({
        city: 'New York',
        country: 'United States',
        country_code: 'US'
      });
    });

    it('should update last activity when viewing current session details', async () => {
      // Create a token that includes the session ID in jti
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (findSessionById as jest.Mock).mockResolvedValue(mockSession);

      const event = createMockEvent({
        pathParameters: { id: TEST_SESSION_ID },
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      await handler(event);

      expect(updateSessionLastActivity).toHaveBeenCalledWith(
        TEST_SESSION_ID,
        TEST_REALM_ID,
        TEST_USER_ID
      );
    });
  });

  describe('DELETE /sessions/{id} - Revoke Specific Session', () => {
    /**
     * Validates: Requirement 13.3
     * WHEN user revokes session THEN THE Zalt_Platform SHALL invalidate immediately
     */
    it('should revoke a specific session', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(mockSession);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: TEST_SESSION_ID }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.message).toBe('Session revoked successfully');
      expect(body.session_id).toBe(TEST_SESSION_ID);
      expect(deleteSession).toHaveBeenCalledWith(TEST_SESSION_ID, TEST_REALM_ID, TEST_USER_ID);
    });

    it('should return 404 when session to revoke is not found', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(null);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: 'nonexistent_session' }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('SESSION_NOT_FOUND');
    });

    it('should return 403 when trying to revoke another user\'s session', async () => {
      const otherUserSession = { ...mockSession, user_id: 'other_user' };
      (findSessionById as jest.Mock).mockResolvedValue(otherUserSession);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: TEST_SESSION_ID }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(403);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('FORBIDDEN');
    });

    it('should return 500 when session deletion fails', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(mockSession);
      (deleteSession as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: TEST_SESSION_ID }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(500);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('REVOKE_FAILED');
    });

    it('should log session revocation', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(mockSession);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: TEST_SESSION_ID }
      });
      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_revoked',
          details: expect.objectContaining({
            session_id: TEST_SESSION_ID
          })
        })
      );
    });

    /**
     * Validates: Requirement 13.8
     * THE Zalt_Platform SHALL trigger session.revoked webhook
     */
    it('should trigger session.revoked webhook', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(mockSession);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: TEST_SESSION_ID }
      });
      await handler(event);

      expect(dispatchSessionRevoked).toHaveBeenCalledWith(
        TEST_REALM_ID,
        expect.objectContaining({
          session_id: TEST_SESSION_ID,
          user_id: TEST_USER_ID,
          realm_id: TEST_REALM_ID
        })
      );
    });

    it('should not fail if webhook dispatch fails', async () => {
      (findSessionById as jest.Mock).mockResolvedValue(mockSession);
      (deleteSession as jest.Mock).mockResolvedValue(true);
      (dispatchSessionRevoked as jest.Mock).mockRejectedValue(new Error('Webhook failed'));

      const event = createMockEvent({
        httpMethod: 'DELETE',
        pathParameters: { id: TEST_SESSION_ID }
      });
      const result = await handler(event);

      // Should still succeed even if webhook fails
      expect(result.statusCode).toBe(200);
    });
  });

  describe('DELETE /sessions - Revoke All Sessions Except Current', () => {
    /**
     * Validates: Requirement 13.4
     * WHEN user revokes all sessions THEN THE Zalt_Platform SHALL keep current session only
     */
    it('should revoke all sessions except current', async () => {
      const sessions = [
        mockSession,
        mockCurrentSession,
        { ...mockSession, id: 'session_other' }
      ];
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      // Create a token that includes the current session ID in jti
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_CURRENT_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      const event = createMockEvent({
        httpMethod: 'DELETE',
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.revoked_count).toBe(2); // All except current
      
      // Should not delete the current session
      expect(deleteSession).not.toHaveBeenCalledWith(
        TEST_CURRENT_SESSION_ID,
        expect.anything(),
        expect.anything()
      );
    });

    it('should return success with 0 count when no other sessions exist', async () => {
      (getUserSessions as jest.Mock).mockResolvedValue([]);

      const event = createMockEvent({
        httpMethod: 'DELETE'
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.revoked_count).toBe(0);
      expect(body.message).toBe('No other sessions to revoke');
    });

    it('should log bulk session revocation', async () => {
      const sessions = [mockSession, { ...mockSession, id: 'session_other' }];
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'DELETE'
      });
      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'sessions_revoked_all',
          details: expect.objectContaining({
            revoked_count: 2
          })
        })
      );
    });

    it('should trigger webhook for each revoked session', async () => {
      const sessions = [mockSession, { ...mockSession, id: 'session_other' }];
      (getUserSessions as jest.Mock).mockResolvedValue(sessions);
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const event = createMockEvent({
        httpMethod: 'DELETE'
      });
      await handler(event);

      expect(dispatchSessionRevoked).toHaveBeenCalledTimes(2);
    });
  });

  describe('Method Not Allowed', () => {
    it('should return 405 for unsupported HTTP methods', async () => {
      const event = createMockEvent({
        httpMethod: 'POST'
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(405);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('METHOD_NOT_ALLOWED');
    });

    it('should return 405 for PUT method', async () => {
      const event = createMockEvent({
        httpMethod: 'PUT'
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(405);
    });

    it('should return 405 for PATCH method', async () => {
      const event = createMockEvent({
        httpMethod: 'PATCH'
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(405);
    });
  });

  describe('Error Handling', () => {
    it('should handle internal errors gracefully', async () => {
      (getUserSessions as jest.Mock).mockRejectedValue(new Error('Database error'));

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(500);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INTERNAL_ERROR');
    });

    it('should return 500 for database errors', async () => {
      (getUserSessions as jest.Mock).mockRejectedValue(new Error('Database error'));

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(500);
      const body = JSON.parse(result.body);
      expect(body.error.message).toBe('Failed to retrieve sessions');
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in response', async () => {
      (getUserSessions as jest.Mock).mockResolvedValue([]);

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.headers).toHaveProperty('X-Content-Type-Options', 'nosniff');
      expect(result.headers).toHaveProperty('X-Frame-Options', 'DENY');
      expect(result.headers).toHaveProperty('Content-Type', 'application/json');
    });
  });

  /**
   * Impossible Travel Detection Tests
   * Validates: Requirement 13.5 - Calculate geo-velocity, alert on impossible travel, optionally revoke session
   */
  describe('Impossible Travel Detection', () => {
    const mockImpossibleTravelResult = {
      isImpossibleTravel: true,
      isSuspicious: true,
      riskLevel: 'critical' as const,
      distanceKm: 8000,
      timeElapsedHours: 1,
      speedKmh: 8000,
      previousLocation: {
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'United States',
        countryCode: 'US'
      },
      currentLocation: {
        latitude: 35.6762,
        longitude: 139.6503,
        city: 'Tokyo',
        country: 'Japan',
        countryCode: 'JP'
      },
      reason: 'Impossible travel detected: 8000km in 1.00h (8000km/h)',
      requiresMfa: true,
      requiresVerification: true,
      blocked: false
    };

    const mockSuspiciousTravelResult = {
      isImpossibleTravel: false,
      isSuspicious: true,
      riskLevel: 'high' as const,
      distanceKm: 2000,
      timeElapsedHours: 3,
      speedKmh: 667,
      previousLocation: {
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'United States',
        countryCode: 'US'
      },
      currentLocation: {
        latitude: 51.5074,
        longitude: -0.1278,
        city: 'London',
        country: 'United Kingdom',
        countryCode: 'GB'
      },
      reason: 'Suspicious travel speed: 667km/h',
      requiresMfa: true,
      requiresVerification: false,
      blocked: false
    };

    /**
     * Validates: Requirement 13.5 - Calculate geo-velocity
     */
    it('should detect impossible travel when listing sessions', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 35.6762,
        longitude: 139.6503,
        city: 'Tokyo',
        country: 'Japan',
        countryCode: 'JP'
      });
      (checkGeoVelocity as jest.Mock).mockResolvedValue(mockImpossibleTravelResult);

      const event = createMockEvent({
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.impossible_travel_detected).toBe(true);
      expect(body.sessions[0].impossible_travel).toBeDefined();
      expect(body.sessions[0].impossible_travel.detected).toBe(true);
      expect(body.sessions[0].impossible_travel.risk_level).toBe('critical');
    });

    /**
     * Validates: Requirement 13.5 - Alert on impossible travel
     */
    it('should alert admin when impossible travel is detected', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 35.6762,
        longitude: 139.6503,
        city: 'Tokyo',
        country: 'Japan',
        countryCode: 'JP'
      });
      (checkGeoVelocity as jest.Mock).mockResolvedValue(mockImpossibleTravelResult);

      const event = createMockEvent({
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      await handler(event);

      // Should log impossible travel alert
      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'impossible_travel_alert',
          realm_id: TEST_REALM_ID,
          user_id: TEST_USER_ID,
          details: expect.objectContaining({
            session_id: TEST_SESSION_ID,
            risk_level: 'critical',
            action_taken: 'alert_only'
          })
        })
      );
    });

    /**
     * Validates: Requirement 13.5 - Optionally revoke session based on realm policy
     */
    it('should revoke session when realm policy enables blocking on impossible travel', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 35.6762,
        longitude: 139.6503,
        city: 'Tokyo',
        country: 'Japan',
        countryCode: 'JP'
      });
      (checkGeoVelocity as jest.Mock).mockResolvedValue(mockImpossibleTravelResult);
      // Healthcare realm with blocking enabled
      (getRealmVelocityConfig as jest.Mock).mockReturnValue({
        maxSpeedKmh: 800,
        suspiciousSpeedKmh: 300,
        minTimeBetweenChecks: 60,
        sameCityToleranceKm: 30,
        blockOnImpossibleTravel: true, // Blocking enabled
        requireMfaOnSuspicious: true,
        sendAlertOnDetection: true
      });
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const event = createMockEvent({
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      const result = await handler(event);

      // Should return 403 with session revoked error
      expect(result.statusCode).toBe(403);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('SESSION_REVOKED_IMPOSSIBLE_TRAVEL');
      expect(body.error.details.reason).toContain('Impossible travel');

      // Should have deleted the session
      expect(deleteSession).toHaveBeenCalledWith(TEST_SESSION_ID, TEST_REALM_ID, TEST_USER_ID);

      // Should have dispatched session.revoked webhook
      expect(dispatchSessionRevoked).toHaveBeenCalledWith(
        TEST_REALM_ID,
        expect.objectContaining({
          session_id: TEST_SESSION_ID,
          reason: 'impossible_travel'
        })
      );
    });

    it('should not revoke session when realm policy disables blocking', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 35.6762,
        longitude: 139.6503,
        city: 'Tokyo',
        country: 'Japan',
        countryCode: 'JP'
      });
      (checkGeoVelocity as jest.Mock).mockResolvedValue(mockImpossibleTravelResult);
      // Default realm with blocking disabled
      (getRealmVelocityConfig as jest.Mock).mockReturnValue({
        maxSpeedKmh: 1000,
        suspiciousSpeedKmh: 500,
        minTimeBetweenChecks: 60,
        sameCityToleranceKm: 50,
        blockOnImpossibleTravel: false, // Blocking disabled
        requireMfaOnSuspicious: true,
        sendAlertOnDetection: true
      });

      const event = createMockEvent({
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      const result = await handler(event);

      // Should return 200 with sessions (not blocked)
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.impossible_travel_detected).toBe(true);
      
      // Should NOT have deleted the session
      expect(deleteSession).not.toHaveBeenCalled();
    });

    it('should detect suspicious travel (high risk but not impossible)', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 51.5074,
        longitude: -0.1278,
        city: 'London',
        country: 'United Kingdom',
        countryCode: 'GB'
      });
      (checkGeoVelocity as jest.Mock).mockResolvedValue(mockSuspiciousTravelResult);

      const event = createMockEvent({
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.impossible_travel_detected).toBe(true);
      expect(body.sessions[0].impossible_travel).toBeDefined();
      expect(body.sessions[0].impossible_travel.detected).toBe(false);
      expect(body.sessions[0].impossible_travel.risk_level).toBe('high');
    });

    it('should not flag normal travel patterns', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'United States',
        countryCode: 'US'
      });
      // Normal travel - no suspicious activity
      (checkGeoVelocity as jest.Mock).mockResolvedValue({
        isImpossibleTravel: false,
        isSuspicious: false,
        riskLevel: 'low',
        distanceKm: 50,
        timeElapsedHours: 2,
        speedKmh: 25,
        currentLocation: {
          latitude: 40.7128,
          longitude: -74.0060,
          city: 'New York',
          country: 'United States'
        },
        requiresMfa: false,
        requiresVerification: false,
        blocked: false
      });

      const event = createMockEvent({
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.impossible_travel_detected).toBe(false);
      expect(body.sessions[0].impossible_travel).toBeUndefined();
    });

    it('should handle geo-velocity check errors gracefully', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'United States',
        countryCode: 'US'
      });
      // Geo-velocity check fails
      (checkGeoVelocity as jest.Mock).mockRejectedValue(new Error('Geo service unavailable'));

      const event = createMockEvent({
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      const result = await handler(event);

      // Should still succeed - geo check failure shouldn't block the request
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.sessions).toHaveLength(1);
    });

    it('should include impossible travel info in session details', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (findSessionById as jest.Mock).mockResolvedValue(mockSession);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 35.6762,
        longitude: 139.6503,
        city: 'Tokyo',
        country: 'Japan',
        countryCode: 'JP'
      });
      (checkGeoVelocity as jest.Mock).mockResolvedValue(mockImpossibleTravelResult);

      const event = createMockEvent({
        httpMethod: 'GET',
        pathParameters: { id: TEST_SESSION_ID },
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.session.impossible_travel).toBeDefined();
      expect(body.session.impossible_travel.detected).toBe(true);
      expect(body.session.impossible_travel.distance_km).toBe(8000);
      expect(body.session.impossible_travel.speed_kmh).toBe(8000);
    });

    it('should log session auto-revocation on impossible travel', async () => {
      const tokenWithJti = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + 
        Buffer.from(JSON.stringify({ 
          ...mockJwtPayload, 
          jti: TEST_SESSION_ID 
        })).toString('base64url') + 
        '.signature';

      (getUserSessions as jest.Mock).mockResolvedValue([mockSession]);
      (lookupIpLocation as jest.Mock).mockResolvedValue({
        latitude: 35.6762,
        longitude: 139.6503,
        city: 'Tokyo',
        country: 'Japan',
        countryCode: 'JP'
      });
      (checkGeoVelocity as jest.Mock).mockResolvedValue(mockImpossibleTravelResult);
      // Healthcare realm with blocking enabled
      (getRealmVelocityConfig as jest.Mock).mockReturnValue({
        maxSpeedKmh: 800,
        suspiciousSpeedKmh: 300,
        minTimeBetweenChecks: 60,
        sameCityToleranceKm: 30,
        blockOnImpossibleTravel: true,
        requireMfaOnSuspicious: true,
        sendAlertOnDetection: true
      });
      (deleteSession as jest.Mock).mockResolvedValue(true);

      const event = createMockEvent({
        headers: {
          Authorization: `Bearer ${tokenWithJti}`
        }
      });
      await handler(event);

      // Should log auto-revocation event
      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'session_auto_revoked_impossible_travel',
          realm_id: TEST_REALM_ID,
          user_id: TEST_USER_ID,
          details: expect.objectContaining({
            session_id: TEST_SESSION_ID
          })
        })
      );
    });
  });
});
