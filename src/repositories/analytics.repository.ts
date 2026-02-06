/**
 * Analytics Repository for Zalt.io Platform
 * Handles DynamoDB operations for analytics data
 * 
 * Validates: Requirements 9.1, 9.2, 9.3
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  BatchGetCommand,
} from '@aws-sdk/lib-dynamodb';
import {
  AnalyticsDynamoItem,
  DailyActiveUsersData,
  LoginMetrics,
  MFAAdoptionMetrics,
  toDailyActiveUsersData,
  toLoginMetrics,
  generateDateRange,
} from '../models/analytics.model';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

const USAGE_TABLE = process.env.USAGE_TABLE || 'zalt-usage';
const USERS_TABLE = process.env.USERS_TABLE || 'zalt-users';

/**
 * Get daily analytics for a date range
 */
export async function getDailyAnalytics(
  customerId: string,
  startDate: string,
  endDate: string,
  realmId?: string
): Promise<AnalyticsDynamoItem[]> {
  const pk = realmId ? `REALM#${realmId}` : `CUSTOMER#${customerId}`;
  
  const result = await docClient.send(
    new QueryCommand({
      TableName: USAGE_TABLE,
      KeyConditionExpression: 'PK = :pk AND SK BETWEEN :start AND :end',
      ExpressionAttributeValues: {
        ':pk': pk,
        ':start': `DAY#${startDate}`,
        ':end': `DAY#${endDate}`,
      },
    })
  );

  return (result.Items || []) as AnalyticsDynamoItem[];
}

/**
 * Get daily active users data for chart
 */
export async function getDailyActiveUsersData(
  customerId: string,
  startDate: string,
  endDate: string,
  realmId?: string
): Promise<DailyActiveUsersData[]> {
  const items = await getDailyAnalytics(customerId, startDate, endDate, realmId);
  const dateRange = generateDateRange(startDate, endDate);
  
  // Create a map for quick lookup
  const dataMap = new Map<string, AnalyticsDynamoItem>();
  for (const item of items) {
    dataMap.set(item.date, item);
  }
  
  // Fill in missing dates with zeros
  return dateRange.map(date => {
    const item = dataMap.get(date);
    if (item) {
      return toDailyActiveUsersData(item);
    }
    return {
      date,
      dau: 0,
      logins: 0,
      registrations: 0,
    };
  });
}

/**
 * Get login metrics for chart
 */
export async function getLoginMetricsData(
  customerId: string,
  startDate: string,
  endDate: string,
  realmId?: string
): Promise<LoginMetrics[]> {
  const items = await getDailyAnalytics(customerId, startDate, endDate, realmId);
  const dateRange = generateDateRange(startDate, endDate);
  
  const dataMap = new Map<string, AnalyticsDynamoItem>();
  for (const item of items) {
    dataMap.set(item.date, item);
  }
  
  return dateRange.map(date => {
    const item = dataMap.get(date);
    if (item) {
      return toLoginMetrics(item);
    }
    return {
      date,
      success_count: 0,
      failure_count: 0,
      success_rate: 0,
      mfa_challenges: 0,
    };
  });
}

/**
 * Get MFA adoption metrics
 */
export async function getMFAAdoptionMetrics(
  customerId: string,
  realmId?: string
): Promise<MFAAdoptionMetrics> {
  // Query users table to get MFA stats
  const pk = realmId ? `REALM#${realmId}` : `CUSTOMER#${customerId}`;
  
  // Get monthly aggregate which should have MFA stats
  const now = new Date();
  const monthKey = `MONTH#${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  
  const result = await docClient.send(
    new GetCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: monthKey,
      },
    })
  );

  const item = result.Item as AnalyticsDynamoItem | undefined;
  
  if (!item) {
    return {
      total_users: 0,
      mfa_enabled_users: 0,
      adoption_rate: 0,
      by_method: {
        totp: 0,
        webauthn: 0,
        sms: 0,
      },
    };
  }

  const totalUsers = item.mfa_enabled_users || 0;
  const mfaEnabled = (item.mfa_totp_users || 0) + (item.mfa_webauthn_users || 0) + (item.mfa_sms_users || 0);
  
  return {
    total_users: totalUsers,
    mfa_enabled_users: mfaEnabled,
    adoption_rate: totalUsers > 0 ? Math.round((mfaEnabled / totalUsers) * 10000) / 100 : 0,
    by_method: {
      totp: item.mfa_totp_users || 0,
      webauthn: item.mfa_webauthn_users || 0,
      sms: item.mfa_sms_users || 0,
    },
  };
}

/**
 * Record login event for analytics
 */
export async function recordLoginEvent(
  customerId: string,
  realmId: string,
  userId: string,
  success: boolean,
  mfaChallenged: boolean = false
): Promise<void> {
  const now = new Date();
  const date = now.toISOString().split('T')[0];
  const dayKey = `DAY#${date}`;
  const timestamp = now.toISOString();

  // Update customer-level analytics
  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: dayKey,
      },
      UpdateExpression: `
        SET #date = :date,
            customer_id = :customerId,
            period_type = :periodType,
            dau = if_not_exists(dau, :zero),
            login_success = if_not_exists(login_success, :zero) + :successInc,
            login_failure = if_not_exists(login_failure, :zero) + :failureInc,
            mfa_challenges = if_not_exists(mfa_challenges, :zero) + :mfaInc,
            registrations = if_not_exists(registrations, :zero),
            updated_at = :now,
            created_at = if_not_exists(created_at, :now),
            #ttl = :ttl
        ADD unique_user_ids :userIdSet
      `,
      ExpressionAttributeNames: {
        '#date': 'date',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':date': date,
        ':customerId': customerId,
        ':periodType': 'day',
        ':zero': 0,
        ':successInc': success ? 1 : 0,
        ':failureInc': success ? 0 : 1,
        ':mfaInc': mfaChallenged ? 1 : 0,
        ':now': timestamp,
        ':userIdSet': success ? new Set([userId]) : new Set<string>(),
        ':ttl': Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60),
      },
    })
  );

  // Update realm-level analytics
  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `REALM#${realmId}`,
        SK: dayKey,
      },
      UpdateExpression: `
        SET #date = :date,
            customer_id = :customerId,
            realm_id = :realmId,
            period_type = :periodType,
            dau = if_not_exists(dau, :zero),
            login_success = if_not_exists(login_success, :zero) + :successInc,
            login_failure = if_not_exists(login_failure, :zero) + :failureInc,
            mfa_challenges = if_not_exists(mfa_challenges, :zero) + :mfaInc,
            registrations = if_not_exists(registrations, :zero),
            updated_at = :now,
            created_at = if_not_exists(created_at, :now),
            #ttl = :ttl
        ADD unique_user_ids :userIdSet
      `,
      ExpressionAttributeNames: {
        '#date': 'date',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':date': date,
        ':customerId': customerId,
        ':realmId': realmId,
        ':periodType': 'day',
        ':zero': 0,
        ':successInc': success ? 1 : 0,
        ':failureInc': success ? 0 : 1,
        ':mfaInc': mfaChallenged ? 1 : 0,
        ':now': timestamp,
        ':userIdSet': success ? new Set([userId]) : new Set<string>(),
        ':ttl': Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60),
      },
    })
  );

  // Update DAU count if successful login
  if (success) {
    await updateDAUCount(customerId, realmId, date);
  }
}

/**
 * Record registration event for analytics
 */
export async function recordRegistrationEvent(
  customerId: string,
  realmId: string
): Promise<void> {
  const now = new Date();
  const date = now.toISOString().split('T')[0];
  const dayKey = `DAY#${date}`;
  const timestamp = now.toISOString();

  // Update customer-level analytics
  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: dayKey,
      },
      UpdateExpression: `
        SET #date = :date,
            customer_id = :customerId,
            period_type = :periodType,
            dau = if_not_exists(dau, :zero),
            login_success = if_not_exists(login_success, :zero),
            login_failure = if_not_exists(login_failure, :zero),
            mfa_challenges = if_not_exists(mfa_challenges, :zero),
            registrations = if_not_exists(registrations, :zero) + :one,
            updated_at = :now,
            created_at = if_not_exists(created_at, :now),
            #ttl = :ttl
      `,
      ExpressionAttributeNames: {
        '#date': 'date',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':date': date,
        ':customerId': customerId,
        ':periodType': 'day',
        ':zero': 0,
        ':one': 1,
        ':now': timestamp,
        ':ttl': Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60),
      },
    })
  );

  // Update realm-level analytics
  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `REALM#${realmId}`,
        SK: dayKey,
      },
      UpdateExpression: `
        SET #date = :date,
            customer_id = :customerId,
            realm_id = :realmId,
            period_type = :periodType,
            dau = if_not_exists(dau, :zero),
            login_success = if_not_exists(login_success, :zero),
            login_failure = if_not_exists(login_failure, :zero),
            mfa_challenges = if_not_exists(mfa_challenges, :zero),
            registrations = if_not_exists(registrations, :zero) + :one,
            updated_at = :now,
            created_at = if_not_exists(created_at, :now),
            #ttl = :ttl
      `,
      ExpressionAttributeNames: {
        '#date': 'date',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':date': date,
        ':customerId': customerId,
        ':realmId': realmId,
        ':periodType': 'day',
        ':zero': 0,
        ':one': 1,
        ':now': timestamp,
        ':ttl': Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60),
      },
    })
  );
}

/**
 * Update DAU count based on unique users
 */
async function updateDAUCount(
  customerId: string,
  realmId: string,
  date: string
): Promise<void> {
  const dayKey = `DAY#${date}`;

  // Get current unique users for customer
  const customerResult = await docClient.send(
    new GetCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: dayKey,
      },
    })
  );

  if (customerResult.Item) {
    const uniqueUsers = customerResult.Item.unique_user_ids || [];
    const dau = Array.isArray(uniqueUsers) ? uniqueUsers.length : 
                uniqueUsers instanceof Set ? uniqueUsers.size : 0;
    
    await docClient.send(
      new UpdateCommand({
        TableName: USAGE_TABLE,
        Key: {
          PK: `CUSTOMER#${customerId}`,
          SK: dayKey,
        },
        UpdateExpression: 'SET dau = :dau',
        ExpressionAttributeValues: {
          ':dau': dau,
        },
      })
    );
  }

  // Get current unique users for realm
  const realmResult = await docClient.send(
    new GetCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `REALM#${realmId}`,
        SK: dayKey,
      },
    })
  );

  if (realmResult.Item) {
    const uniqueUsers = realmResult.Item.unique_user_ids || [];
    const dau = Array.isArray(uniqueUsers) ? uniqueUsers.length : 
                uniqueUsers instanceof Set ? uniqueUsers.size : 0;
    
    await docClient.send(
      new UpdateCommand({
        TableName: USAGE_TABLE,
        Key: {
          PK: `REALM#${realmId}`,
          SK: dayKey,
        },
        UpdateExpression: 'SET dau = :dau',
        ExpressionAttributeValues: {
          ':dau': dau,
        },
      })
    );
  }
}

/**
 * Get analytics summary for a period
 */
export async function getAnalyticsSummary(
  customerId: string,
  startDate: string,
  endDate: string,
  realmId?: string
): Promise<{
  total_dau_avg: number;
  total_logins: number;
  total_login_success: number;
  total_login_failure: number;
  total_registrations: number;
  total_mfa_challenges: number;
  success_rate: number;
}> {
  const items = await getDailyAnalytics(customerId, startDate, endDate, realmId);
  
  let totalDau = 0;
  let totalLogins = 0;
  let totalSuccess = 0;
  let totalFailure = 0;
  let totalRegistrations = 0;
  let totalMfaChallenges = 0;
  
  for (const item of items) {
    totalDau += item.dau || 0;
    totalSuccess += item.login_success || 0;
    totalFailure += item.login_failure || 0;
    totalRegistrations += item.registrations || 0;
    totalMfaChallenges += item.mfa_challenges || 0;
  }
  
  totalLogins = totalSuccess + totalFailure;
  const dayCount = items.length || 1;
  
  return {
    total_dau_avg: Math.round(totalDau / dayCount),
    total_logins: totalLogins,
    total_login_success: totalSuccess,
    total_login_failure: totalFailure,
    total_registrations: totalRegistrations,
    total_mfa_challenges: totalMfaChallenges,
    success_rate: totalLogins > 0 ? Math.round((totalSuccess / totalLogins) * 10000) / 100 : 0,
  };
}
