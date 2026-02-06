/**
 * Analytics Model for Zalt.io Platform
 * Defines data structures for analytics dashboard
 * 
 * Validates: Requirements 9.1, 9.2, 9.3
 */

export interface DailyActiveUsersData {
  date: string; // YYYY-MM-DD
  dau: number; // Daily Active Users
  logins: number; // Total logins
  registrations: number; // New registrations
}

export interface LoginMetrics {
  date: string;
  success_count: number;
  failure_count: number;
  success_rate: number; // Percentage 0-100
  mfa_challenges: number;
}

export interface MFAAdoptionMetrics {
  total_users: number;
  mfa_enabled_users: number;
  adoption_rate: number; // Percentage 0-100
  by_method: {
    totp: number;
    webauthn: number;
    sms: number; // Should be low/zero
  };
}

export interface AnalyticsSummary {
  customer_id: string;
  period: {
    start: string;
    end: string;
  };
  
  // Overview metrics
  total_mau: number;
  total_api_calls: number;
  total_logins: number;
  total_registrations: number;
  
  // Daily breakdown
  daily_active_users: DailyActiveUsersData[];
  
  // Login metrics
  login_metrics: LoginMetrics[];
  
  // MFA adoption
  mfa_adoption: MFAAdoptionMetrics;
  
  // Trends (compared to previous period)
  trends: {
    mau_change: number; // Percentage change
    logins_change: number;
    registrations_change: number;
    mfa_adoption_change: number;
  };
}

export interface AnalyticsQuery {
  customer_id: string;
  realm_id?: string; // Optional: filter by realm
  start_date: string; // YYYY-MM-DD
  end_date: string; // YYYY-MM-DD
  granularity?: 'day' | 'week' | 'month';
}

export interface AnalyticsDynamoItem {
  PK: string; // CUSTOMER#{customer_id} or REALM#{realm_id}
  SK: string; // ANALYTICS#DAY#{date} or ANALYTICS#MONTH#{yyyy-mm}
  customer_id: string;
  realm_id?: string;
  date: string;
  period_type: 'day' | 'week' | 'month';
  
  // DAU metrics
  dau: number;
  unique_user_ids?: string[];
  
  // Login metrics
  login_success: number;
  login_failure: number;
  mfa_challenges: number;
  
  // Registration metrics
  registrations: number;
  
  // MFA metrics (for monthly aggregates)
  mfa_enabled_users?: number;
  mfa_totp_users?: number;
  mfa_webauthn_users?: number;
  mfa_sms_users?: number;
  
  // Timestamps
  created_at: string;
  updated_at: string;
  
  // TTL for daily records
  ttl?: number;
}

/**
 * Convert DynamoDB item to DailyActiveUsersData
 */
export function toDailyActiveUsersData(item: AnalyticsDynamoItem): DailyActiveUsersData {
  return {
    date: item.date,
    dau: item.dau,
    logins: item.login_success + item.login_failure,
    registrations: item.registrations,
  };
}

/**
 * Convert DynamoDB item to LoginMetrics
 */
export function toLoginMetrics(item: AnalyticsDynamoItem): LoginMetrics {
  const total = item.login_success + item.login_failure;
  return {
    date: item.date,
    success_count: item.login_success,
    failure_count: item.login_failure,
    success_rate: total > 0 ? Math.round((item.login_success / total) * 10000) / 100 : 0,
    mfa_challenges: item.mfa_challenges,
  };
}

/**
 * Generate date range array
 */
export function generateDateRange(startDate: string, endDate: string): string[] {
  const dates: string[] = [];
  const current = new Date(startDate);
  const end = new Date(endDate);
  
  while (current <= end) {
    dates.push(current.toISOString().split('T')[0]);
    current.setDate(current.getDate() + 1);
  }
  
  return dates;
}

/**
 * Get default date range (last 30 days)
 */
export function getDefaultDateRange(): { start: string; end: string } {
  const end = new Date();
  const start = new Date();
  start.setDate(start.getDate() - 30);
  
  return {
    start: start.toISOString().split('T')[0],
    end: end.toISOString().split('T')[0],
  };
}
