/**
 * Analytics Handler Tests
 * Tests for GET /platform/analytics endpoints
 * 
 * Validates: Requirements 9.1, 9.2, 9.3
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from './analytics.handler';

// Mock dependencies
jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: jest.fn(),
}));

jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../../services/analytics.service', () => ({
  getDailyActiveUsersChart: jest.fn(),
  getLoginMetricsChart: jest.fn(),
  getMFAAdoptionChart: jest.fn(),
  getFullAnalyticsSummary: jest.fn(),
}));

import { verifyAccessToken } from '../../utils/jwt';
import {
  getDailyActiveUsersChart,
  getLoginMetricsChart,
  getMFAAdoptionChart,
  getFullAnalyticsSummary,
} from '../../services/analytics.service';

const mockVerifyAccessToken = verifyAccessToken as jest.Mock;
const mockGetDAU = getDailyActiveUsersChart as jest.Mock;
const mockGetLogins = getLoginMetricsChart as jest.Mock;
const mockGetMFA = getMFAAdoptionChart as jest.Mock;
const mockGetSummary = getFullAnalyticsSummary as jest.Mock;

function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'GET',
    path: '/platform/analytics',
    headers: {
      Authorization: 'Bearer valid-token',
    },
    queryStringParameters: null,
    pathParameters: null,
    body: null,
    isBase64Encoded: false,
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: '127.0.0.1',
      },
    } as any,
    resource: '/platform/analytics',
    stageVariables: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    ...overrides,
  };
}

describe('Analytics Handler', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'customer_123',
      email: 'test@example.com',
    });
  });

  describe('Authentication', () => {
    it('should return 401 when no authorization header', async () => {
      const event = createMockEvent({
        headers: {},
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 401 when token is invalid', async () => {
      mockVerifyAccessToken.mockRejectedValue(new Error('Invalid token'));

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.statusCode).toBe(401);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('Date Validation', () => {
    it('should return 400 for invalid start_date format', async () => {
      const event = createMockEvent({
        queryStringParameters: {
          start_date: 'invalid-date',
        },
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_DATE');
    });

    it('should return 400 for invalid end_date format', async () => {
      const event = createMockEvent({
        queryStringParameters: {
          start_date: '2026-01-01',
          end_date: '01-31-2026',
        },
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('INVALID_DATE');
    });

    it('should accept valid date format', async () => {
      mockGetSummary.mockResolvedValue({
        success: true,
        data: { customer_id: 'customer_123' },
      });

      const event = createMockEvent({
        queryStringParameters: {
          start_date: '2026-01-01',
          end_date: '2026-01-31',
        },
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      expect(mockGetSummary).toHaveBeenCalledWith(
        'customer_123',
        '2026-01-01',
        '2026-01-31',
        undefined
      );
    });
  });

  describe('GET /platform/analytics/dau', () => {
    it('should return daily active users data', async () => {
      const mockData = [
        { date: '2026-01-01', dau: 100, logins: 150, registrations: 10 },
        { date: '2026-01-02', dau: 120, logins: 180, registrations: 15 },
      ];

      mockGetDAU.mockResolvedValue({
        success: true,
        data: mockData,
      });

      const event = createMockEvent({
        path: '/platform/analytics/dau',
        resource: '/platform/analytics/dau',
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.chart_type).toBe('daily_active_users');
      expect(body.data).toEqual(mockData);
    });

    it('should filter by realm_id when provided', async () => {
      mockGetDAU.mockResolvedValue({
        success: true,
        data: [],
      });

      const event = createMockEvent({
        path: '/platform/analytics/dau',
        queryStringParameters: {
          realm_id: 'realm_456',
        },
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      expect(mockGetDAU).toHaveBeenCalledWith(
        'customer_123',
        undefined,
        undefined,
        'realm_456'
      );
    });

    it('should return error when service fails', async () => {
      mockGetDAU.mockResolvedValue({
        success: false,
        error: 'Date range cannot exceed 90 days',
      });

      const event = createMockEvent({
        path: '/platform/analytics/dau',
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.code).toBe('ANALYTICS_ERROR');
    });
  });

  describe('GET /platform/analytics/logins', () => {
    it('should return login metrics with summary', async () => {
      const mockData = [
        { date: '2026-01-01', success_count: 100, failure_count: 10, success_rate: 90.91, mfa_challenges: 50 },
        { date: '2026-01-02', success_count: 120, failure_count: 5, success_rate: 96, mfa_challenges: 60 },
      ];

      mockGetLogins.mockResolvedValue({
        success: true,
        data: mockData,
      });

      const event = createMockEvent({
        path: '/platform/analytics/logins',
        resource: '/platform/analytics/logins',
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.chart_type).toBe('login_metrics');
      expect(body.data).toEqual(mockData);
      expect(body.summary.total_logins).toBe(235);
      expect(body.summary.total_success).toBe(220);
      expect(body.summary.total_failure).toBe(15);
      expect(body.summary.overall_success_rate).toBeCloseTo(93.62, 1);
    });

    it('should handle empty data', async () => {
      mockGetLogins.mockResolvedValue({
        success: true,
        data: [],
      });

      const event = createMockEvent({
        path: '/platform/analytics/logins',
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.summary.total_logins).toBe(0);
      expect(body.summary.overall_success_rate).toBe(0);
    });
  });

  describe('GET /platform/analytics/mfa', () => {
    it('should return MFA adoption metrics', async () => {
      const mockData = {
        total_users: 1000,
        mfa_enabled_users: 750,
        adoption_rate: 75,
        by_method: {
          totp: 400,
          webauthn: 350,
          sms: 0,
        },
      };

      mockGetMFA.mockResolvedValue({
        success: true,
        data: mockData,
      });

      const event = createMockEvent({
        path: '/platform/analytics/mfa',
        resource: '/platform/analytics/mfa',
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.chart_type).toBe('mfa_adoption');
      expect(body.data).toEqual(mockData);
    });

    it('should filter by realm_id', async () => {
      mockGetMFA.mockResolvedValue({
        success: true,
        data: { total_users: 0, mfa_enabled_users: 0, adoption_rate: 0, by_method: { totp: 0, webauthn: 0, sms: 0 } },
      });

      const event = createMockEvent({
        path: '/platform/analytics/mfa',
        queryStringParameters: {
          realm_id: 'realm_789',
        },
      });

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      expect(mockGetMFA).toHaveBeenCalledWith('customer_123', 'realm_789');
    });
  });

  describe('GET /platform/analytics (summary)', () => {
    it('should return full analytics summary', async () => {
      const mockSummary = {
        customer_id: 'customer_123',
        period: { start: '2026-01-01', end: '2026-01-31' },
        total_mau: 500,
        total_api_calls: 10000,
        total_logins: 1500,
        total_registrations: 100,
        daily_active_users: [],
        login_metrics: [],
        mfa_adoption: {
          total_users: 500,
          mfa_enabled_users: 400,
          adoption_rate: 80,
          by_method: { totp: 200, webauthn: 200, sms: 0 },
        },
        trends: {
          mau_change: 10,
          logins_change: 5,
          registrations_change: 15,
          mfa_adoption_change: 2,
        },
      };

      mockGetSummary.mockResolvedValue({
        success: true,
        data: mockSummary,
      });

      const event = createMockEvent();

      const result = await handler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body);
      expect(body.customer_id).toBe('customer_123');
      expect(body.trends).toBeDefined();
    });

    it('should handle service error', async () => {
      mockGetSummary.mockResolvedValue({
        success: false,
        error: 'Customer not found',
      });

      const event = createMockEvent();

      const result = await handler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body);
      expect(body.error.message).toBe('Customer not found');
    });
  });

  describe('Response Headers', () => {
    it('should include security headers', async () => {
      mockGetSummary.mockResolvedValue({
        success: true,
        data: {},
      });

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(result.headers?.['X-Frame-Options']).toBe('DENY');
    });

    it('should include cache control header', async () => {
      mockGetSummary.mockResolvedValue({
        success: true,
        data: {},
      });

      const event = createMockEvent();
      const result = await handler(event);

      expect(result.headers?.['Cache-Control']).toBe('private, max-age=60');
    });
  });
});
