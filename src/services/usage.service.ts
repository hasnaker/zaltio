/**
 * Usage Service for Zalt.io Platform
 * Handles usage tracking, MAU calculation, and limits enforcement
 * 
 * Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5
 */

import {
  getCurrentMonthUsage,
  incrementApiCalls,
  recordUserLogin,
  recordUserRegistration,
  updateRealmCount,
  calculateMonthlyMAU,
  updateMonthlyMAU,
  getUsageHistory,
} from '../repositories/usage.repository';
import { getCustomerById } from '../repositories/customer.repository';
import {
  UsageRecord,
  UsageSummary,
  calculateUsageSummary,
  getCurrentMonthPeriod,
} from '../models/usage.model';
import { logSecurityEvent } from './security-logger.service';

// Plan limits configuration
const PLAN_LIMITS = {
  free: {
    max_mau: 1000,
    max_api_calls: 10000,
    max_realms: 1,
  },
  pro: {
    max_mau: 10000,
    max_api_calls: 100000,
    max_realms: 5,
  },
  enterprise: {
    max_mau: 100000,
    max_api_calls: 1000000,
    max_realms: 50,
  },
};

// Warning threshold (80%)
const WARNING_THRESHOLD = 0.8;

// Grace period percentage (allow 10% overage before hard block)
const GRACE_PERCENTAGE = 1.1;

export interface UsageLimitResult {
  allowed: boolean;
  warning?: string;
  error?: string;
  usage?: UsageSummary;
}

/**
 * Get customer's plan limits
 */
export function getPlanLimits(plan: 'free' | 'pro' | 'enterprise') {
  return PLAN_LIMITS[plan] || PLAN_LIMITS.free;
}

/**
 * Get current usage summary for a customer
 */
export async function getUsageSummary(customerId: string): Promise<UsageSummary | null> {
  const customer = await getCustomerById(customerId);
  if (!customer) {
    return null;
  }

  const limits = customer.usage_limits || getPlanLimits(customer.billing.plan as 'free' | 'pro' | 'enterprise');
  const currentUsage = await getCurrentMonthUsage(customerId);

  if (!currentUsage) {
    // No usage yet this month
    return {
      customer_id: customerId,
      period: getCurrentMonthPeriod().replace('MONTH#', ''),
      mau: 0,
      api_calls: 0,
      realms: 0,
      limits,
      mau_percentage: 0,
      api_calls_percentage: 0,
      realms_percentage: 0,
      mau_warning: false,
      api_calls_warning: false,
      realms_warning: false,
      mau_exceeded: false,
      api_calls_exceeded: false,
      realms_exceeded: false,
    };
  }

  return calculateUsageSummary(currentUsage, limits);
}

/**
 * Check if customer can perform an API call
 */
export async function checkApiCallLimit(customerId: string): Promise<UsageLimitResult> {
  const summary = await getUsageSummary(customerId);
  
  if (!summary) {
    return { allowed: false, error: 'Customer not found' };
  }

  // Check if exceeded with grace period
  if (summary.api_calls_percentage >= GRACE_PERCENTAGE * 100) {
    await logSecurityEvent({
      event_type: 'usage_limit_exceeded',
      ip_address: 'system',
      user_id: customerId,
      details: {
        limit_type: 'api_calls',
        current: summary.api_calls,
        limit: summary.limits.max_api_calls,
        percentage: summary.api_calls_percentage,
      },
    });

    return {
      allowed: false,
      error: 'API call limit exceeded. Please upgrade your plan.',
      usage: summary,
    };
  }

  // Check for warning
  if (summary.api_calls_warning) {
    return {
      allowed: true,
      warning: `You've used ${Math.round(summary.api_calls_percentage)}% of your API call limit.`,
      usage: summary,
    };
  }

  return { allowed: true, usage: summary };
}

/**
 * Check if customer can register a new user (MAU limit)
 */
export async function checkMAULimit(customerId: string): Promise<UsageLimitResult> {
  const summary = await getUsageSummary(customerId);
  
  if (!summary) {
    return { allowed: false, error: 'Customer not found' };
  }

  // Check if exceeded with grace period
  if (summary.mau_percentage >= GRACE_PERCENTAGE * 100) {
    await logSecurityEvent({
      event_type: 'usage_limit_exceeded',
      ip_address: 'system',
      user_id: customerId,
      details: {
        limit_type: 'mau',
        current: summary.mau,
        limit: summary.limits.max_mau,
        percentage: summary.mau_percentage,
      },
    });

    return {
      allowed: false,
      error: 'Monthly active user limit exceeded. Please upgrade your plan.',
      usage: summary,
    };
  }

  // Check for warning
  if (summary.mau_warning) {
    return {
      allowed: true,
      warning: `You've used ${Math.round(summary.mau_percentage)}% of your MAU limit.`,
      usage: summary,
    };
  }

  return { allowed: true, usage: summary };
}

/**
 * Check if customer can create a new realm
 */
export async function checkRealmLimit(customerId: string): Promise<UsageLimitResult> {
  const summary = await getUsageSummary(customerId);
  
  if (!summary) {
    return { allowed: false, error: 'Customer not found' };
  }

  // Check if exceeded (no grace period for realms)
  if (summary.realms_exceeded) {
    await logSecurityEvent({
      event_type: 'usage_limit_exceeded',
      ip_address: 'system',
      user_id: customerId,
      details: {
        limit_type: 'realms',
        current: summary.realms,
        limit: summary.limits.max_realms,
        percentage: summary.realms_percentage,
      },
    });

    return {
      allowed: false,
      error: 'Realm limit reached. Please upgrade your plan to create more realms.',
      usage: summary,
    };
  }

  // Check for warning
  if (summary.realms_warning) {
    return {
      allowed: true,
      warning: `You've used ${Math.round(summary.realms_percentage)}% of your realm limit.`,
      usage: summary,
    };
  }

  return { allowed: true, usage: summary };
}

/**
 * Track an API call
 */
export async function trackApiCall(customerId: string): Promise<void> {
  await incrementApiCalls(customerId, 1);
}

/**
 * Track a user login (for MAU)
 */
export async function trackUserLogin(customerId: string, userId: string): Promise<void> {
  await recordUserLogin(customerId, userId);
}

/**
 * Track a new user registration
 */
export async function trackUserRegistration(customerId: string): Promise<void> {
  await recordUserRegistration(customerId);
}

/**
 * Update realm count for a customer
 */
export async function trackRealmCount(customerId: string, count: number): Promise<void> {
  await updateRealmCount(customerId, count);
}

/**
 * Recalculate MAU for current month
 * Should be called periodically (e.g., hourly) or on-demand
 */
export async function recalculateMAU(customerId: string): Promise<number> {
  const now = new Date();
  const yearMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  
  const mau = await calculateMonthlyMAU(customerId, yearMonth);
  await updateMonthlyMAU(customerId, mau);
  
  return mau;
}

/**
 * Get usage history for dashboard
 */
export async function getCustomerUsageHistory(
  customerId: string,
  months: number = 6
): Promise<UsageRecord[]> {
  return getUsageHistory(customerId, months);
}

/**
 * Check all limits and return comprehensive status
 */
export async function checkAllLimits(customerId: string): Promise<{
  allowed: boolean;
  warnings: string[];
  errors: string[];
  usage: UsageSummary | null;
}> {
  const summary = await getUsageSummary(customerId);
  
  if (!summary) {
    return {
      allowed: false,
      warnings: [],
      errors: ['Customer not found'],
      usage: null,
    };
  }

  const warnings: string[] = [];
  const errors: string[] = [];

  // Check MAU
  if (summary.mau_exceeded) {
    errors.push('MAU limit exceeded');
  } else if (summary.mau_warning) {
    warnings.push(`MAU at ${Math.round(summary.mau_percentage)}%`);
  }

  // Check API calls
  if (summary.api_calls_exceeded) {
    errors.push('API call limit exceeded');
  } else if (summary.api_calls_warning) {
    warnings.push(`API calls at ${Math.round(summary.api_calls_percentage)}%`);
  }

  // Check realms
  if (summary.realms_exceeded) {
    errors.push('Realm limit exceeded');
  } else if (summary.realms_warning) {
    warnings.push(`Realms at ${Math.round(summary.realms_percentage)}%`);
  }

  return {
    allowed: errors.length === 0,
    warnings,
    errors,
    usage: summary,
  };
}
