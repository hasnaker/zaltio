/**
 * Usage Service Tests
 * Tests for usage tracking, MAU calculation, and limits enforcement
 */

// Mock uuid before imports
jest.mock('uuid', () => ({
  v4: jest.fn().mockReturnValue('12345678-1234-1234-1234-123456789012'),
}));

import {
  getPlanLimits,
  getUsageSummary,
  checkApiCallLimit,
  checkMAULimit,
  checkRealmLimit,
  checkAllLimits,
} from './usage.service';
import {
  calculateUsageSummary,
  getCurrentMonthPeriod,
  getCurrentDayPeriod,
  UsageRecord,
} from '../models/usage.model';

// Mock dependencies
jest.mock('../repositories/usage.repository');
jest.mock('../repositories/customer.repository');
jest.mock('./security-logger.service');

import * as usageRepo from '../repositories/usage.repository';
import * as customerRepo from '../repositories/customer.repository';

const mockUsageRepo = usageRepo as jest.Mocked<typeof usageRepo>;
const mockCustomerRepo = customerRepo as jest.Mocked<typeof customerRepo>;

describe('Usage Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getPlanLimits', () => {
    it('should return free plan limits', () => {
      const limits = getPlanLimits('free');
      expect(limits).toEqual({
        max_mau: 1000,
        max_api_calls: 10000,
        max_realms: 1,
      });
    });

    it('should return pro plan limits', () => {
      const limits = getPlanLimits('pro');
      expect(limits).toEqual({
        max_mau: 10000,
        max_api_calls: 100000,
        max_realms: 5,
      });
    });

    it('should return enterprise plan limits', () => {
      const limits = getPlanLimits('enterprise');
      expect(limits).toEqual({
        max_mau: 100000,
        max_api_calls: 1000000,
        max_realms: 50,
      });
    });
  });

  describe('getUsageSummary', () => {
    const mockCustomer = {
      id: 'cust_123',
      email: 'test@example.com',
      billing: { plan: 'pro' },
      usage_limits: {
        max_mau: 10000,
        max_api_calls: 100000,
        max_realms: 5,
      },
    };

    it('should return usage summary for customer with usage', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 5000,
        api_calls: 50000,
        realms_count: 3,
        logins_count: 10000,
        registrations_count: 500,
        mfa_verifications: 2000,
        unique_users_count: 5000,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const summary = await getUsageSummary('cust_123');

      expect(summary).not.toBeNull();
      expect(summary?.mau).toBe(5000);
      expect(summary?.api_calls).toBe(50000);
      expect(summary?.realms).toBe(3);
      expect(summary?.mau_percentage).toBe(50);
      expect(summary?.api_calls_percentage).toBe(50);
      expect(summary?.realms_percentage).toBe(60);
    });

    it('should return zero usage for customer with no usage', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue(null);

      const summary = await getUsageSummary('cust_123');

      expect(summary).not.toBeNull();
      expect(summary?.mau).toBe(0);
      expect(summary?.api_calls).toBe(0);
      expect(summary?.realms).toBe(0);
    });

    it('should return null for non-existent customer', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(null);

      const summary = await getUsageSummary('nonexistent');

      expect(summary).toBeNull();
    });
  });

  describe('checkApiCallLimit', () => {
    const mockCustomer = {
      id: 'cust_123',
      email: 'test@example.com',
      billing: { plan: 'free' },
      usage_limits: {
        max_mau: 1000,
        max_api_calls: 10000,
        max_realms: 1,
      },
    };

    it('should allow API calls under limit', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 100,
        api_calls: 5000,
        realms_count: 1,
        logins_count: 200,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 100,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkApiCallLimit('cust_123');

      expect(result.allowed).toBe(true);
      expect(result.warning).toBeUndefined();
      expect(result.error).toBeUndefined();
    });

    it('should warn when approaching limit (80%+)', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 100,
        api_calls: 8500,
        realms_count: 1,
        logins_count: 200,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 100,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkApiCallLimit('cust_123');

      expect(result.allowed).toBe(true);
      expect(result.warning).toContain('85%');
    });

    it('should block when exceeding limit with grace period (110%+)', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 100,
        api_calls: 11500,
        realms_count: 1,
        logins_count: 200,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 100,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkApiCallLimit('cust_123');

      expect(result.allowed).toBe(false);
      expect(result.error).toContain('exceeded');
    });
  });

  describe('checkMAULimit', () => {
    const mockCustomer = {
      id: 'cust_123',
      email: 'test@example.com',
      billing: { plan: 'free' },
      usage_limits: {
        max_mau: 1000,
        max_api_calls: 10000,
        max_realms: 1,
      },
    };

    it('should allow new users under MAU limit', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 500,
        api_calls: 5000,
        realms_count: 1,
        logins_count: 1000,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 500,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkMAULimit('cust_123');

      expect(result.allowed).toBe(true);
      expect(result.warning).toBeUndefined();
    });

    it('should warn when approaching MAU limit', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 850,
        api_calls: 5000,
        realms_count: 1,
        logins_count: 1700,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 850,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkMAULimit('cust_123');

      expect(result.allowed).toBe(true);
      expect(result.warning).toContain('85%');
    });

    it('should block when MAU limit exceeded', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 1150,
        api_calls: 5000,
        realms_count: 1,
        logins_count: 2300,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 1150,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkMAULimit('cust_123');

      expect(result.allowed).toBe(false);
      expect(result.error).toContain('exceeded');
    });
  });

  describe('checkRealmLimit', () => {
    const mockCustomer = {
      id: 'cust_123',
      email: 'test@example.com',
      billing: { plan: 'free' },
      usage_limits: {
        max_mau: 1000,
        max_api_calls: 10000,
        max_realms: 1,
      },
    };

    it('should allow realm creation under limit', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 100,
        api_calls: 5000,
        realms_count: 0,
        logins_count: 200,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 100,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkRealmLimit('cust_123');

      expect(result.allowed).toBe(true);
    });

    it('should block when realm limit reached (no grace period)', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 100,
        api_calls: 5000,
        realms_count: 1,
        logins_count: 200,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 100,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkRealmLimit('cust_123');

      expect(result.allowed).toBe(false);
      expect(result.error).toContain('Realm limit');
    });
  });

  describe('checkAllLimits', () => {
    const mockCustomer = {
      id: 'cust_123',
      email: 'test@example.com',
      billing: { plan: 'pro' },
      usage_limits: {
        max_mau: 10000,
        max_api_calls: 100000,
        max_realms: 5,
      },
    };

    it('should return all clear when under all limits', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 1000,
        api_calls: 10000,
        realms_count: 2,
        logins_count: 2000,
        registrations_count: 100,
        mfa_verifications: 500,
        unique_users_count: 1000,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkAllLimits('cust_123');

      expect(result.allowed).toBe(true);
      expect(result.warnings).toHaveLength(0);
      expect(result.errors).toHaveLength(0);
    });

    it('should return warnings when approaching limits', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 8500,
        api_calls: 85000,
        realms_count: 4,
        logins_count: 17000,
        registrations_count: 500,
        mfa_verifications: 2000,
        unique_users_count: 8500,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkAllLimits('cust_123');

      expect(result.allowed).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.errors).toHaveLength(0);
    });

    it('should return errors when limits exceeded', async () => {
      mockCustomerRepo.getCustomerById.mockResolvedValue(mockCustomer as any);
      mockUsageRepo.getCurrentMonthUsage.mockResolvedValue({
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 12000,
        api_calls: 120000,
        realms_count: 6,
        logins_count: 24000,
        registrations_count: 1000,
        mfa_verifications: 5000,
        unique_users_count: 12000,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      });

      const result = await checkAllLimits('cust_123');

      expect(result.allowed).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });
});

describe('Usage Model', () => {
  describe('calculateUsageSummary', () => {
    it('should calculate percentages correctly', () => {
      const record: UsageRecord = {
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 500,
        api_calls: 5000,
        realms_count: 1,
        logins_count: 1000,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 500,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      };

      const limits = {
        max_mau: 1000,
        max_api_calls: 10000,
        max_realms: 2,
      };

      const summary = calculateUsageSummary(record, limits);

      expect(summary.mau_percentage).toBe(50);
      expect(summary.api_calls_percentage).toBe(50);
      expect(summary.realms_percentage).toBe(50);
      expect(summary.mau_warning).toBe(false);
      expect(summary.mau_exceeded).toBe(false);
    });

    it('should set warning flags at 80%', () => {
      const record: UsageRecord = {
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 850,
        api_calls: 8500,
        realms_count: 1,
        logins_count: 1700,
        registrations_count: 50,
        mfa_verifications: 100,
        unique_users_count: 850,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      };

      const limits = {
        max_mau: 1000,
        max_api_calls: 10000,
        max_realms: 2,
      };

      const summary = calculateUsageSummary(record, limits);

      expect(summary.mau_warning).toBe(true);
      expect(summary.api_calls_warning).toBe(true);
      expect(summary.mau_exceeded).toBe(false);
      expect(summary.api_calls_exceeded).toBe(false);
    });

    it('should set exceeded flags at 100%', () => {
      const record: UsageRecord = {
        customer_id: 'cust_123',
        period: 'MONTH#2026-01',
        period_type: 'month',
        mau: 1200,
        api_calls: 12000,
        realms_count: 3,
        logins_count: 2400,
        registrations_count: 100,
        mfa_verifications: 200,
        unique_users_count: 1200,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-25T00:00:00Z',
      };

      const limits = {
        max_mau: 1000,
        max_api_calls: 10000,
        max_realms: 2,
      };

      const summary = calculateUsageSummary(record, limits);

      expect(summary.mau_exceeded).toBe(true);
      expect(summary.api_calls_exceeded).toBe(true);
      expect(summary.realms_exceeded).toBe(true);
    });
  });

  describe('getCurrentMonthPeriod', () => {
    it('should return correct format', () => {
      const period = getCurrentMonthPeriod();
      expect(period).toMatch(/^MONTH#\d{4}-\d{2}$/);
    });
  });

  describe('getCurrentDayPeriod', () => {
    it('should return correct format', () => {
      const period = getCurrentDayPeriod();
      expect(period).toMatch(/^DAY#\d{4}-\d{2}-\d{2}$/);
    });
  });
});
