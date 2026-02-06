/**
 * Analytics Service for Zalt.io Platform
 * Provides analytics data for dashboard charts
 * 
 * Validates: Requirements 9.1, 9.2, 9.3
 */

import {
  getDailyActiveUsersData,
  getLoginMetricsData,
  getMFAAdoptionMetrics,
  getAnalyticsSummary,
  recordLoginEvent,
  recordRegistrationEvent,
} from '../repositories/analytics.repository';
import { getCustomerById } from '../repositories/customer.repository';
import {
  AnalyticsSummary,
  DailyActiveUsersData,
  LoginMetrics,
  MFAAdoptionMetrics,
  getDefaultDateRange,
} from '../models/analytics.model';
import { logSecurityEvent } from './security-logger.service';

export interface AnalyticsResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Get daily active users chart data
 * Validates: Requirement 9.1
 */
export async function getDailyActiveUsersChart(
  customerId: string,
  startDate?: string,
  endDate?: string,
  realmId?: string
): Promise<AnalyticsResult<DailyActiveUsersData[]>> {
  try {
    // Validate customer exists
    const customer = await getCustomerById(customerId);
    if (!customer) {
      return { success: false, error: 'Customer not found' };
    }

    // Use default date range if not provided
    const dateRange = startDate && endDate 
      ? { start: startDate, end: endDate }
      : getDefaultDateRange();

    // Validate date range (max 90 days)
    const start = new Date(dateRange.start);
    const end = new Date(dateRange.end);
    const daysDiff = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    
    if (daysDiff > 90) {
      return { success: false, error: 'Date range cannot exceed 90 days' };
    }

    if (start > end) {
      return { success: false, error: 'Start date must be before end date' };
    }

    const data = await getDailyActiveUsersData(
      customerId,
      dateRange.start,
      dateRange.end,
      realmId
    );

    return { success: true, data };
  } catch (error) {
    console.error('Error getting DAU chart data:', error);
    return { success: false, error: 'Failed to retrieve analytics data' };
  }
}

/**
 * Get login success/failure rates chart data
 * Validates: Requirement 9.2
 */
export async function getLoginMetricsChart(
  customerId: string,
  startDate?: string,
  endDate?: string,
  realmId?: string
): Promise<AnalyticsResult<LoginMetrics[]>> {
  try {
    const customer = await getCustomerById(customerId);
    if (!customer) {
      return { success: false, error: 'Customer not found' };
    }

    const dateRange = startDate && endDate 
      ? { start: startDate, end: endDate }
      : getDefaultDateRange();

    const start = new Date(dateRange.start);
    const end = new Date(dateRange.end);
    const daysDiff = Math.ceil((end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24));
    
    if (daysDiff > 90) {
      return { success: false, error: 'Date range cannot exceed 90 days' };
    }

    if (start > end) {
      return { success: false, error: 'Start date must be before end date' };
    }

    const data = await getLoginMetricsData(
      customerId,
      dateRange.start,
      dateRange.end,
      realmId
    );

    return { success: true, data };
  } catch (error) {
    console.error('Error getting login metrics:', error);
    return { success: false, error: 'Failed to retrieve login metrics' };
  }
}

/**
 * Get MFA adoption metrics
 * Validates: Requirement 9.3
 */
export async function getMFAAdoptionChart(
  customerId: string,
  realmId?: string
): Promise<AnalyticsResult<MFAAdoptionMetrics>> {
  try {
    const customer = await getCustomerById(customerId);
    if (!customer) {
      return { success: false, error: 'Customer not found' };
    }

    const data = await getMFAAdoptionMetrics(customerId, realmId);
    return { success: true, data };
  } catch (error) {
    console.error('Error getting MFA adoption metrics:', error);
    return { success: false, error: 'Failed to retrieve MFA metrics' };
  }
}

/**
 * Get full analytics summary
 */
export async function getFullAnalyticsSummary(
  customerId: string,
  startDate?: string,
  endDate?: string,
  realmId?: string
): Promise<AnalyticsResult<AnalyticsSummary>> {
  try {
    const customer = await getCustomerById(customerId);
    if (!customer) {
      return { success: false, error: 'Customer not found' };
    }

    const dateRange = startDate && endDate 
      ? { start: startDate, end: endDate }
      : getDefaultDateRange();

    // Get all analytics data in parallel
    const [dauData, loginData, mfaData, summary] = await Promise.all([
      getDailyActiveUsersData(customerId, dateRange.start, dateRange.end, realmId),
      getLoginMetricsData(customerId, dateRange.start, dateRange.end, realmId),
      getMFAAdoptionMetrics(customerId, realmId),
      getAnalyticsSummary(customerId, dateRange.start, dateRange.end, realmId),
    ]);

    // Calculate previous period for trends
    const periodDays = Math.ceil(
      (new Date(dateRange.end).getTime() - new Date(dateRange.start).getTime()) / (1000 * 60 * 60 * 24)
    );
    
    const prevEnd = new Date(dateRange.start);
    prevEnd.setDate(prevEnd.getDate() - 1);
    const prevStart = new Date(prevEnd);
    prevStart.setDate(prevStart.getDate() - periodDays);

    const prevSummary = await getAnalyticsSummary(
      customerId,
      prevStart.toISOString().split('T')[0],
      prevEnd.toISOString().split('T')[0],
      realmId
    );

    // Calculate trends
    const calculateChange = (current: number, previous: number): number => {
      if (previous === 0) return current > 0 ? 100 : 0;
      return Math.round(((current - previous) / previous) * 10000) / 100;
    };

    const analyticsSummary: AnalyticsSummary = {
      customer_id: customerId,
      period: {
        start: dateRange.start,
        end: dateRange.end,
      },
      total_mau: summary.total_dau_avg * periodDays, // Approximate
      total_api_calls: 0, // Would need separate tracking
      total_logins: summary.total_logins,
      total_registrations: summary.total_registrations,
      daily_active_users: dauData,
      login_metrics: loginData,
      mfa_adoption: mfaData,
      trends: {
        mau_change: calculateChange(summary.total_dau_avg, prevSummary.total_dau_avg),
        logins_change: calculateChange(summary.total_logins, prevSummary.total_logins),
        registrations_change: calculateChange(summary.total_registrations, prevSummary.total_registrations),
        mfa_adoption_change: 0, // Would need historical MFA data
      },
    };

    return { success: true, data: analyticsSummary };
  } catch (error) {
    console.error('Error getting analytics summary:', error);
    return { success: false, error: 'Failed to retrieve analytics summary' };
  }
}

/**
 * Track login event for analytics
 */
export async function trackLoginForAnalytics(
  customerId: string,
  realmId: string,
  userId: string,
  success: boolean,
  mfaChallenged: boolean = false
): Promise<void> {
  try {
    await recordLoginEvent(customerId, realmId, userId, success, mfaChallenged);
  } catch (error) {
    // Log but don't fail the login
    console.error('Error tracking login for analytics:', error);
    await logSecurityEvent({
      event_type: 'analytics_tracking_error',
      ip_address: 'system',
      user_id: userId,
      details: { error: (error as Error).message, event: 'login' },
    });
  }
}

/**
 * Track registration event for analytics
 */
export async function trackRegistrationForAnalytics(
  customerId: string,
  realmId: string
): Promise<void> {
  try {
    await recordRegistrationEvent(customerId, realmId);
  } catch (error) {
    console.error('Error tracking registration for analytics:', error);
    await logSecurityEvent({
      event_type: 'analytics_tracking_error',
      ip_address: 'system',
      details: { error: (error as Error).message, event: 'registration' },
    });
  }
}
