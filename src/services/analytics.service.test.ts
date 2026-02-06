/**
 * Analytics Service Tests
 * Tests for analytics data retrieval and tracking
 * 
 * Validates: Requirements 9.1, 9.2, 9.3
 */

import {
  getDailyActiveUsersChart,
  getLoginMetricsChart,
  getMFAAdoptionChart,
  getFullAnalyticsSummary,
  trackLoginForAnalytics,
  trackRegistrationForAnalytics,
} from './analytics.service';

// Mock dependencies
jest.mock('../repositories/customer.repository', () => ({
  getCustomerById: jest.fn(),
}));

jest.mock('../repositories/analytics.repository', () => ({
  getDailyActiveUsersData: jest.fn(),
  getLoginMetricsData: jest.fn(),
  getMFAAdoptionMetrics: jest.fn(),
  getAnalyticsSummary: jest.fn(),
  recordLoginEvent: jest.fn(),
  recordRegistrationEvent: jest.fn(),
}));

jest.mock('./security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined),
}));

import { getCustomerById } from '../repositories/customer.repository';
import {
  getDailyActiveUsersData,
  getLoginMetricsData,
  getMFAAdoptionMetrics,
  getAnalyticsSummary,
  recordLoginEvent,
  recordRegistrationEvent,
} from '../repositories/analytics.repository';

const mockGetCustomer = getCustomerById as jest.Mock;
const mockGetDAUData = getDailyActiveUsersData as jest.Mock;
const mockGetLoginData = getLoginMetricsData as jest.Mock;
const mockGetMFAData = getMFAAdoptionMetrics as jest.Mock;
const mockGetSummary = getAnalyticsSummary as jest.Mock;
const mockRecordLogin = recordLoginEvent as jest.Mock;
const mockRecordRegistration = recordRegistrationEvent as jest.Mock;

const mockCustomer = {
  id: 'customer_123',
  email: 'test@example.com',
  billing: { plan: 'pro' },
};

describe('Analytics Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGetCustomer.mockResolvedValue(mockCustomer);
  });

  describe('getDailyActiveUsersChart', () => {
    it('should return DAU data for valid customer', async () => {
      const mockData = [
        { date: '2026-01-01', dau: 100, logins: 150, registrations: 10 },
        { date: '2026-01-02', dau: 120, logins: 180, registrations: 15 },
      ];
      mockGetDAUData.mockResolvedValue(mockData);

      const result = await getDailyActiveUsersChart(
        'customer_123',
        '2026-01-01',
        '2026-01-02'
      );

      expect(result.success).toBe(true);
      expect(result.data).toEqual(mockData);
    });

    it('should return error for non-existent customer', async () => {
      mockGetCustomer.mockResolvedValue(null);

      const result = await getDailyActiveUsersChart('invalid_customer');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Customer not found');
    });

    it('should return error for date range exceeding 90 days', async () => {
      const result = await getDailyActiveUsersChart(
        'customer_123',
        '2026-01-01',
        '2026-06-01' // More than 90 days
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('Date range cannot exceed 90 days');
    });

    it('should return error when start date is after end date', async () => {
      const result = await getDailyActiveUsersChart(
        'customer_123',
        '2026-01-31',
        '2026-01-01'
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('Start date must be before end date');
    });

    it('should use default date range when not provided', async () => {
      mockGetDAUData.mockResolvedValue([]);

      const result = await getDailyActiveUsersChart('customer_123');

      expect(result.success).toBe(true);
      expect(mockGetDAUData).toHaveBeenCalled();
    });

    it('should filter by realm_id when provided', async () => {
      mockGetDAUData.mockResolvedValue([]);

      await getDailyActiveUsersChart(
        'customer_123',
        '2026-01-01',
        '2026-01-31',
        'realm_456'
      );

      expect(mockGetDAUData).toHaveBeenCalledWith(
        'customer_123',
        '2026-01-01',
        '2026-01-31',
        'realm_456'
      );
    });
  });

  describe('getLoginMetricsChart', () => {
    it('should return login metrics for valid customer', async () => {
      const mockData = [
        { date: '2026-01-01', success_count: 100, failure_count: 10, success_rate: 90.91, mfa_challenges: 50 },
      ];
      mockGetLoginData.mockResolvedValue(mockData);

      const result = await getLoginMetricsChart(
        'customer_123',
        '2026-01-01',
        '2026-01-31'
      );

      expect(result.success).toBe(true);
      expect(result.data).toEqual(mockData);
    });

    it('should return error for non-existent customer', async () => {
      mockGetCustomer.mockResolvedValue(null);

      const result = await getLoginMetricsChart('invalid_customer');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Customer not found');
    });

    it('should validate date range', async () => {
      const result = await getLoginMetricsChart(
        'customer_123',
        '2026-01-01',
        '2026-12-31' // More than 90 days
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('Date range cannot exceed 90 days');
    });
  });

  describe('getMFAAdoptionChart', () => {
    it('should return MFA adoption metrics', async () => {
      const mockData = {
        total_users: 1000,
        mfa_enabled_users: 750,
        adoption_rate: 75,
        by_method: { totp: 400, webauthn: 350, sms: 0 },
      };
      mockGetMFAData.mockResolvedValue(mockData);

      const result = await getMFAAdoptionChart('customer_123');

      expect(result.success).toBe(true);
      expect(result.data).toEqual(mockData);
    });

    it('should return error for non-existent customer', async () => {
      mockGetCustomer.mockResolvedValue(null);

      const result = await getMFAAdoptionChart('invalid_customer');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Customer not found');
    });

    it('should filter by realm_id', async () => {
      mockGetMFAData.mockResolvedValue({});

      await getMFAAdoptionChart('customer_123', 'realm_456');

      expect(mockGetMFAData).toHaveBeenCalledWith('customer_123', 'realm_456');
    });
  });

  describe('getFullAnalyticsSummary', () => {
    beforeEach(() => {
      mockGetDAUData.mockResolvedValue([]);
      mockGetLoginData.mockResolvedValue([]);
      mockGetMFAData.mockResolvedValue({
        total_users: 0,
        mfa_enabled_users: 0,
        adoption_rate: 0,
        by_method: { totp: 0, webauthn: 0, sms: 0 },
      });
      mockGetSummary.mockResolvedValue({
        total_dau_avg: 100,
        total_logins: 500,
        total_login_success: 450,
        total_login_failure: 50,
        total_registrations: 20,
        total_mfa_challenges: 200,
        success_rate: 90,
      });
    });

    it('should return full analytics summary', async () => {
      const result = await getFullAnalyticsSummary('customer_123');

      expect(result.success).toBe(true);
      expect(result.data?.customer_id).toBe('customer_123');
      expect(result.data?.trends).toBeDefined();
    });

    it('should return error for non-existent customer', async () => {
      mockGetCustomer.mockResolvedValue(null);

      const result = await getFullAnalyticsSummary('invalid_customer');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Customer not found');
    });

    it('should calculate trends compared to previous period', async () => {
      const result = await getFullAnalyticsSummary(
        'customer_123',
        '2026-01-01',
        '2026-01-31'
      );

      expect(result.success).toBe(true);
      expect(result.data?.trends).toBeDefined();
      // Summary is called twice - once for current period, once for previous
      expect(mockGetSummary).toHaveBeenCalledTimes(2);
    });
  });

  describe('trackLoginForAnalytics', () => {
    it('should record successful login', async () => {
      mockRecordLogin.mockResolvedValue(undefined);

      await trackLoginForAnalytics(
        'customer_123',
        'realm_456',
        'user_789',
        true,
        false
      );

      expect(mockRecordLogin).toHaveBeenCalledWith(
        'customer_123',
        'realm_456',
        'user_789',
        true,
        false
      );
    });

    it('should record failed login', async () => {
      mockRecordLogin.mockResolvedValue(undefined);

      await trackLoginForAnalytics(
        'customer_123',
        'realm_456',
        'user_789',
        false,
        false
      );

      expect(mockRecordLogin).toHaveBeenCalledWith(
        'customer_123',
        'realm_456',
        'user_789',
        false,
        false
      );
    });

    it('should record MFA challenge', async () => {
      mockRecordLogin.mockResolvedValue(undefined);

      await trackLoginForAnalytics(
        'customer_123',
        'realm_456',
        'user_789',
        true,
        true
      );

      expect(mockRecordLogin).toHaveBeenCalledWith(
        'customer_123',
        'realm_456',
        'user_789',
        true,
        true
      );
    });

    it('should not throw on error', async () => {
      mockRecordLogin.mockRejectedValue(new Error('DB error'));

      // Should not throw
      await expect(
        trackLoginForAnalytics('customer_123', 'realm_456', 'user_789', true)
      ).resolves.not.toThrow();
    });
  });

  describe('trackRegistrationForAnalytics', () => {
    it('should record registration', async () => {
      mockRecordRegistration.mockResolvedValue(undefined);

      await trackRegistrationForAnalytics('customer_123', 'realm_456');

      expect(mockRecordRegistration).toHaveBeenCalledWith(
        'customer_123',
        'realm_456'
      );
    });

    it('should not throw on error', async () => {
      mockRecordRegistration.mockRejectedValue(new Error('DB error'));

      await expect(
        trackRegistrationForAnalytics('customer_123', 'realm_456')
      ).resolves.not.toThrow();
    });
  });
});
