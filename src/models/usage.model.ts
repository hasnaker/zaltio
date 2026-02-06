/**
 * Usage Model for Zalt.io Platform
 * Tracks customer usage metrics (MAU, API calls, realms)
 * 
 * DynamoDB Schema:
 * - PK: CUSTOMER#{customer_id}
 * - SK: MONTH#{yyyy-mm} or DAY#{yyyy-mm-dd}
 * 
 * Validates: Requirements 7.1, 7.2, 7.3
 */

export interface UsageRecord {
  // Primary key components
  customer_id: string;
  period: string; // MONTH#2026-01 or DAY#2026-01-25
  period_type: 'month' | 'day';
  
  // Usage metrics
  mau: number; // Monthly Active Users (unique logins)
  api_calls: number; // Total API calls
  realms_count: number; // Number of active realms
  
  // Detailed breakdown
  logins_count: number; // Total login attempts
  registrations_count: number; // New user registrations
  mfa_verifications: number; // MFA verification attempts
  
  // Unique user tracking (for MAU calculation)
  unique_users?: Set<string>; // Only for daily records, not stored
  unique_users_count: number; // Count of unique users
  
  // Timestamps
  created_at: string;
  updated_at: string;
}

export interface UsageSummary {
  customer_id: string;
  period: string; // YYYY-MM format
  
  // Current usage
  mau: number;
  api_calls: number;
  realms: number;
  
  // Limits from customer plan
  limits: {
    max_mau: number;
    max_api_calls: number;
    max_realms: number;
  };
  
  // Usage percentages
  mau_percentage: number;
  api_calls_percentage: number;
  realms_percentage: number;
  
  // Warning flags
  mau_warning: boolean; // > 80%
  api_calls_warning: boolean;
  realms_warning: boolean;
  
  // Exceeded flags
  mau_exceeded: boolean; // > 100%
  api_calls_exceeded: boolean;
  realms_exceeded: boolean;
}

export interface DailyUsageRecord {
  customer_id: string;
  date: string; // YYYY-MM-DD
  
  // Daily metrics
  unique_users: string[]; // User IDs who logged in
  api_calls: number;
  logins: number;
  registrations: number;
  mfa_verifications: number;
  
  // Timestamps
  created_at: string;
  updated_at: string;
}

/**
 * DynamoDB item format for usage records
 */
export interface UsageDynamoItem {
  PK: string; // CUSTOMER#{customer_id}
  SK: string; // MONTH#{yyyy-mm} or DAY#{yyyy-mm-dd}
  customer_id: string;
  period_type: 'month' | 'day';
  mau: number;
  api_calls: number;
  realms_count: number;
  logins_count: number;
  registrations_count: number;
  mfa_verifications: number;
  unique_users_count: number;
  unique_user_ids?: string[]; // Only for daily records
  created_at: string;
  updated_at: string;
  // TTL for daily records (keep 90 days)
  ttl?: number;
}

/**
 * Convert DynamoDB item to UsageRecord
 */
export function fromDynamoItem(item: UsageDynamoItem): UsageRecord {
  return {
    customer_id: item.customer_id,
    period: item.SK,
    period_type: item.period_type,
    mau: item.mau,
    api_calls: item.api_calls,
    realms_count: item.realms_count,
    logins_count: item.logins_count,
    registrations_count: item.registrations_count,
    mfa_verifications: item.mfa_verifications,
    unique_users_count: item.unique_users_count,
    created_at: item.created_at,
    updated_at: item.updated_at,
  };
}

/**
 * Convert UsageRecord to DynamoDB item
 */
export function toDynamoItem(record: UsageRecord, uniqueUserIds?: string[]): UsageDynamoItem {
  const item: UsageDynamoItem = {
    PK: `CUSTOMER#${record.customer_id}`,
    SK: record.period,
    customer_id: record.customer_id,
    period_type: record.period_type,
    mau: record.mau,
    api_calls: record.api_calls,
    realms_count: record.realms_count,
    logins_count: record.logins_count,
    registrations_count: record.registrations_count,
    mfa_verifications: record.mfa_verifications,
    unique_users_count: record.unique_users_count,
    created_at: record.created_at,
    updated_at: record.updated_at,
  };

  // Add unique user IDs for daily records
  if (record.period_type === 'day' && uniqueUserIds) {
    item.unique_user_ids = uniqueUserIds;
    // Set TTL for 90 days
    item.ttl = Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60);
  }

  return item;
}

/**
 * Get current month period string
 */
export function getCurrentMonthPeriod(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  return `MONTH#${year}-${month}`;
}

/**
 * Get current day period string
 */
export function getCurrentDayPeriod(): string {
  const now = new Date();
  return `DAY#${now.toISOString().split('T')[0]}`;
}

/**
 * Calculate usage summary with limits and warnings
 */
export function calculateUsageSummary(
  record: UsageRecord,
  limits: { max_mau: number; max_api_calls: number; max_realms: number }
): UsageSummary {
  const mau_percentage = limits.max_mau > 0 ? (record.mau / limits.max_mau) * 100 : 0;
  const api_calls_percentage = limits.max_api_calls > 0 ? (record.api_calls / limits.max_api_calls) * 100 : 0;
  const realms_percentage = limits.max_realms > 0 ? (record.realms_count / limits.max_realms) * 100 : 0;

  return {
    customer_id: record.customer_id,
    period: record.period.replace('MONTH#', ''),
    mau: record.mau,
    api_calls: record.api_calls,
    realms: record.realms_count,
    limits,
    mau_percentage,
    api_calls_percentage,
    realms_percentage,
    mau_warning: mau_percentage >= 80 && mau_percentage < 100,
    api_calls_warning: api_calls_percentage >= 80 && api_calls_percentage < 100,
    realms_warning: realms_percentage >= 80 && realms_percentage < 100,
    mau_exceeded: mau_percentage >= 100,
    api_calls_exceeded: api_calls_percentage >= 100,
    realms_exceeded: realms_percentage >= 100,
  };
}
