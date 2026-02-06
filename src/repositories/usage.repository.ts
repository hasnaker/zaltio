/**
 * Usage Repository for Zalt.io Platform
 * Handles DynamoDB operations for usage tracking
 * 
 * Validates: Requirements 7.1, 7.2, 7.3
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import {
  UsageRecord,
  UsageDynamoItem,
  fromDynamoItem,
  toDynamoItem,
  getCurrentMonthPeriod,
  getCurrentDayPeriod,
} from '../models/usage.model';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);

const USAGE_TABLE = process.env.USAGE_TABLE || 'zalt-usage';

/**
 * Get usage record for a specific period
 */
export async function getUsageRecord(
  customerId: string,
  period: string
): Promise<UsageRecord | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: period,
      },
    })
  );

  if (!result.Item) {
    return null;
  }

  return fromDynamoItem(result.Item as UsageDynamoItem);
}

/**
 * Get current month's usage record
 */
export async function getCurrentMonthUsage(
  customerId: string
): Promise<UsageRecord | null> {
  return getUsageRecord(customerId, getCurrentMonthPeriod());
}

/**
 * Get current day's usage record
 */
export async function getCurrentDayUsage(
  customerId: string
): Promise<UsageRecord | null> {
  return getUsageRecord(customerId, getCurrentDayPeriod());
}

/**
 * Create or update usage record
 */
export async function saveUsageRecord(
  record: UsageRecord,
  uniqueUserIds?: string[]
): Promise<void> {
  const item = toDynamoItem(record, uniqueUserIds);

  await docClient.send(
    new PutCommand({
      TableName: USAGE_TABLE,
      Item: item,
    })
  );
}

/**
 * Increment API call count atomically
 */
export async function incrementApiCalls(
  customerId: string,
  count: number = 1
): Promise<void> {
  const monthPeriod = getCurrentMonthPeriod();
  const dayPeriod = getCurrentDayPeriod();
  const now = new Date().toISOString();

  // Update monthly record
  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: monthPeriod,
      },
      UpdateExpression: `
        SET api_calls = if_not_exists(api_calls, :zero) + :count,
            updated_at = :now,
            customer_id = if_not_exists(customer_id, :customerId),
            period_type = if_not_exists(period_type, :periodType),
            mau = if_not_exists(mau, :zero),
            realms_count = if_not_exists(realms_count, :zero),
            logins_count = if_not_exists(logins_count, :zero),
            registrations_count = if_not_exists(registrations_count, :zero),
            mfa_verifications = if_not_exists(mfa_verifications, :zero),
            unique_users_count = if_not_exists(unique_users_count, :zero),
            created_at = if_not_exists(created_at, :now)
      `,
      ExpressionAttributeValues: {
        ':count': count,
        ':zero': 0,
        ':now': now,
        ':customerId': customerId,
        ':periodType': 'month',
      },
    })
  );

  // Update daily record
  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: dayPeriod,
      },
      UpdateExpression: `
        SET api_calls = if_not_exists(api_calls, :zero) + :count,
            updated_at = :now,
            customer_id = if_not_exists(customer_id, :customerId),
            period_type = if_not_exists(period_type, :periodType),
            mau = if_not_exists(mau, :zero),
            realms_count = if_not_exists(realms_count, :zero),
            logins_count = if_not_exists(logins_count, :zero),
            registrations_count = if_not_exists(registrations_count, :zero),
            mfa_verifications = if_not_exists(mfa_verifications, :zero),
            unique_users_count = if_not_exists(unique_users_count, :zero),
            created_at = if_not_exists(created_at, :now),
            #ttl = :ttl
      `,
      ExpressionAttributeNames: {
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':count': count,
        ':zero': 0,
        ':now': now,
        ':customerId': customerId,
        ':periodType': 'day',
        ':ttl': Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60),
      },
    })
  );
}

/**
 * Record a user login (for MAU tracking)
 */
export async function recordUserLogin(
  customerId: string,
  userId: string
): Promise<void> {
  const monthPeriod = getCurrentMonthPeriod();
  const dayPeriod = getCurrentDayPeriod();
  const now = new Date().toISOString();

  // Update daily record with unique user
  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: dayPeriod,
      },
      UpdateExpression: `
        SET logins_count = if_not_exists(logins_count, :zero) + :one,
            updated_at = :now,
            customer_id = if_not_exists(customer_id, :customerId),
            period_type = if_not_exists(period_type, :periodType),
            api_calls = if_not_exists(api_calls, :zero),
            mau = if_not_exists(mau, :zero),
            realms_count = if_not_exists(realms_count, :zero),
            registrations_count = if_not_exists(registrations_count, :zero),
            mfa_verifications = if_not_exists(mfa_verifications, :zero),
            unique_users_count = if_not_exists(unique_users_count, :zero),
            created_at = if_not_exists(created_at, :now),
            #ttl = :ttl
        ADD unique_user_ids :userIdSet
      `,
      ExpressionAttributeNames: {
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':one': 1,
        ':zero': 0,
        ':now': now,
        ':customerId': customerId,
        ':periodType': 'day',
        ':userIdSet': new Set([userId]),
        ':ttl': Math.floor(Date.now() / 1000) + (90 * 24 * 60 * 60),
      },
    })
  );

  // Update monthly login count
  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: monthPeriod,
      },
      UpdateExpression: `
        SET logins_count = if_not_exists(logins_count, :zero) + :one,
            updated_at = :now,
            customer_id = if_not_exists(customer_id, :customerId),
            period_type = if_not_exists(period_type, :periodType),
            api_calls = if_not_exists(api_calls, :zero),
            mau = if_not_exists(mau, :zero),
            realms_count = if_not_exists(realms_count, :zero),
            registrations_count = if_not_exists(registrations_count, :zero),
            mfa_verifications = if_not_exists(mfa_verifications, :zero),
            unique_users_count = if_not_exists(unique_users_count, :zero),
            created_at = if_not_exists(created_at, :now)
      `,
      ExpressionAttributeValues: {
        ':one': 1,
        ':zero': 0,
        ':now': now,
        ':customerId': customerId,
        ':periodType': 'month',
      },
    })
  );
}

/**
 * Record a new user registration
 */
export async function recordUserRegistration(
  customerId: string
): Promise<void> {
  const monthPeriod = getCurrentMonthPeriod();
  const now = new Date().toISOString();

  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: monthPeriod,
      },
      UpdateExpression: `
        SET registrations_count = if_not_exists(registrations_count, :zero) + :one,
            updated_at = :now,
            customer_id = if_not_exists(customer_id, :customerId),
            period_type = if_not_exists(period_type, :periodType),
            api_calls = if_not_exists(api_calls, :zero),
            mau = if_not_exists(mau, :zero),
            realms_count = if_not_exists(realms_count, :zero),
            logins_count = if_not_exists(logins_count, :zero),
            mfa_verifications = if_not_exists(mfa_verifications, :zero),
            unique_users_count = if_not_exists(unique_users_count, :zero),
            created_at = if_not_exists(created_at, :now)
      `,
      ExpressionAttributeValues: {
        ':one': 1,
        ':zero': 0,
        ':now': now,
        ':customerId': customerId,
        ':periodType': 'month',
      },
    })
  );
}

/**
 * Update realm count for a customer
 */
export async function updateRealmCount(
  customerId: string,
  realmCount: number
): Promise<void> {
  const monthPeriod = getCurrentMonthPeriod();
  const now = new Date().toISOString();

  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: monthPeriod,
      },
      UpdateExpression: `
        SET realms_count = :realmCount,
            updated_at = :now,
            customer_id = if_not_exists(customer_id, :customerId),
            period_type = if_not_exists(period_type, :periodType),
            api_calls = if_not_exists(api_calls, :zero),
            mau = if_not_exists(mau, :zero),
            logins_count = if_not_exists(logins_count, :zero),
            registrations_count = if_not_exists(registrations_count, :zero),
            mfa_verifications = if_not_exists(mfa_verifications, :zero),
            unique_users_count = if_not_exists(unique_users_count, :zero),
            created_at = if_not_exists(created_at, :now)
      `,
      ExpressionAttributeValues: {
        ':realmCount': realmCount,
        ':zero': 0,
        ':now': now,
        ':customerId': customerId,
        ':periodType': 'month',
      },
    })
  );
}

/**
 * Get daily usage records for a month (for MAU aggregation)
 */
export async function getDailyUsageForMonth(
  customerId: string,
  yearMonth: string // YYYY-MM format
): Promise<UsageRecord[]> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: USAGE_TABLE,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk': `CUSTOMER#${customerId}`,
        ':skPrefix': `DAY#${yearMonth}`,
      },
    })
  );

  return (result.Items || []).map(item => fromDynamoItem(item as UsageDynamoItem));
}

/**
 * Get usage history for a customer (last N months)
 */
export async function getUsageHistory(
  customerId: string,
  months: number = 6
): Promise<UsageRecord[]> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: USAGE_TABLE,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :skPrefix)',
      ExpressionAttributeValues: {
        ':pk': `CUSTOMER#${customerId}`,
        ':skPrefix': 'MONTH#',
      },
      ScanIndexForward: false, // Most recent first
      Limit: months,
    })
  );

  return (result.Items || []).map(item => fromDynamoItem(item as UsageDynamoItem));
}

/**
 * Calculate MAU from daily records
 * Aggregates unique users across all days in the month
 */
export async function calculateMonthlyMAU(
  customerId: string,
  yearMonth: string
): Promise<number> {
  const dailyRecords = await getDailyUsageForMonth(customerId, yearMonth);
  
  // Collect all unique user IDs from daily records
  const uniqueUsers = new Set<string>();
  
  for (const record of dailyRecords) {
    // Get the full daily record with unique_user_ids
    const fullRecord = await docClient.send(
      new GetCommand({
        TableName: USAGE_TABLE,
        Key: {
          PK: `CUSTOMER#${customerId}`,
          SK: record.period,
        },
      })
    );
    
    const userIds = (fullRecord.Item as UsageDynamoItem)?.unique_user_ids || [];
    for (const userId of userIds) {
      uniqueUsers.add(userId);
    }
  }
  
  return uniqueUsers.size;
}

/**
 * Update monthly MAU count
 */
export async function updateMonthlyMAU(
  customerId: string,
  mau: number
): Promise<void> {
  const monthPeriod = getCurrentMonthPeriod();
  const now = new Date().toISOString();

  await docClient.send(
    new UpdateCommand({
      TableName: USAGE_TABLE,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: monthPeriod,
      },
      UpdateExpression: `
        SET mau = :mau,
            unique_users_count = :mau,
            updated_at = :now
      `,
      ExpressionAttributeValues: {
        ':mau': mau,
        ':now': now,
      },
    })
  );
}
