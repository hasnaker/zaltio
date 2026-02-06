/**
 * Rate Limiting Service for Zalt.io Auth Platform
 * Task 6.1: Rate Limiting Service
 * 
 * SECURITY FEATURES:
 * - Sliding window algorithm for accurate rate limiting
 * - Endpoint-specific limits (Login, Register, Password Reset, MFA, API)
 * - DynamoDB TTL for automatic cleanup
 * - Realm-isolated rate limits
 * - IP-based and user-based limiting
 * - Retry-After header support
 * 
 * RATE LIMITS (per steering rules):
 * - Login: 5 attempts / 15 min / IP
 * - Register: 3 attempts / hour / IP
 * - Password Reset: 3 attempts / hour / email
 * - MFA Verify: 5 attempts / min / user
 * - API General: 100 requests / min / user
 */

import { GetCommand, PutCommand, UpdateCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from './dynamodb.service';

/**
 * Rate limit endpoint types with their configurations
 */
export enum RateLimitEndpoint {
  LOGIN = 'login',
  REGISTER = 'register',
  PASSWORD_RESET = 'password_reset',
  MFA_VERIFY = 'mfa_verify',
  EMAIL_VERIFY = 'email_verify',
  API_GENERAL = 'api_general',
  SOCIAL_AUTH = 'social_auth',
  WEBAUTHN = 'webauthn',
  DEVICE_TRUST = 'device_trust',
  ACCOUNT_LINK = 'account_link'
}

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  maxRequests: number;
  windowSeconds: number;
  blockDurationSeconds?: number; // Optional extended block after limit exceeded
}

/**
 * Rate limit result
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
  blocked?: boolean;
  blockExpiresAt?: number;
}

/**
 * Rate limit record stored in DynamoDB
 */
interface RateLimitRecord {
  pk: string;
  sk: string;
  count: number;
  window_start: number;
  requests: number[]; // Timestamps of requests for sliding window
  blocked_until?: number;
  ttl: number;
}

/**
 * Default rate limit configurations per endpoint
 * Based on Zalt.io security requirements
 */
export const RATE_LIMIT_CONFIGS: Record<RateLimitEndpoint, RateLimitConfig> = {
  [RateLimitEndpoint.LOGIN]: {
    maxRequests: 5,
    windowSeconds: 900, // 15 minutes
    blockDurationSeconds: 900 // 15 min block after exceeded
  },
  [RateLimitEndpoint.REGISTER]: {
    maxRequests: 3,
    windowSeconds: 3600, // 1 hour
    blockDurationSeconds: 3600
  },
  [RateLimitEndpoint.PASSWORD_RESET]: {
    maxRequests: 3,
    windowSeconds: 3600, // 1 hour
    blockDurationSeconds: 3600
  },
  [RateLimitEndpoint.MFA_VERIFY]: {
    maxRequests: 5,
    windowSeconds: 60, // 1 minute
    blockDurationSeconds: 300 // 5 min block
  },
  [RateLimitEndpoint.EMAIL_VERIFY]: {
    maxRequests: 5,
    windowSeconds: 3600, // 1 hour
    blockDurationSeconds: 3600
  },
  [RateLimitEndpoint.API_GENERAL]: {
    maxRequests: 100,
    windowSeconds: 60, // 1 minute
    blockDurationSeconds: 60
  },
  [RateLimitEndpoint.SOCIAL_AUTH]: {
    maxRequests: 10,
    windowSeconds: 300, // 5 minutes
    blockDurationSeconds: 300
  },
  [RateLimitEndpoint.WEBAUTHN]: {
    maxRequests: 10,
    windowSeconds: 300, // 5 minutes
    blockDurationSeconds: 300
  },
  [RateLimitEndpoint.DEVICE_TRUST]: {
    maxRequests: 10,
    windowSeconds: 300, // 5 minutes
    blockDurationSeconds: 300
  },
  [RateLimitEndpoint.ACCOUNT_LINK]: {
    maxRequests: 5,
    windowSeconds: 300, // 5 minutes
    blockDurationSeconds: 600
  }
};

/**
 * Generate rate limit key for DynamoDB
 */
function generateRateLimitKey(
  realmId: string,
  endpoint: RateLimitEndpoint,
  identifier: string
): { pk: string; sk: string } {
  return {
    pk: `RATELIMIT#${realmId}`,
    sk: `${endpoint}#${identifier}`
  };
}

/**
 * Check rate limit using sliding window algorithm
 * 
 * @param realmId - Realm identifier for isolation
 * @param endpoint - Endpoint type (login, register, etc.)
 * @param identifier - Unique identifier (IP address, email, user ID)
 * @param customConfig - Optional custom configuration override
 * @returns Rate limit result with allowed status and metadata
 */
export async function checkRateLimit(
  realmId: string,
  identifier: string,
  customConfig?: RateLimitConfig
): Promise<RateLimitResult> {
  // Parse endpoint from identifier if present (e.g., "login:192.168.1.1")
  let endpoint = RateLimitEndpoint.API_GENERAL;
  let actualIdentifier = identifier;
  
  const colonIndex = identifier.indexOf(':');
  if (colonIndex > 0) {
    const possibleEndpoint = identifier.substring(0, colonIndex) as RateLimitEndpoint;
    if (Object.values(RateLimitEndpoint).includes(possibleEndpoint)) {
      endpoint = possibleEndpoint;
      actualIdentifier = identifier.substring(colonIndex + 1);
    }
  }

  const config = customConfig || RATE_LIMIT_CONFIGS[endpoint];
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - config.windowSeconds;
  const windowEnd = now + config.windowSeconds;
  
  const { pk, sk } = generateRateLimitKey(realmId, endpoint, actualIdentifier);

  try {
    // Get existing rate limit record
    const getCommand = new GetCommand({
      TableName: TableNames.SESSIONS,
      Key: { pk, sk }
    });

    const result = await dynamoDb.send(getCommand);
    const record = result.Item as RateLimitRecord | undefined;

    // Check if currently blocked
    if (record?.blocked_until && record.blocked_until > now) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: record.blocked_until,
        retryAfter: record.blocked_until - now,
        blocked: true,
        blockExpiresAt: record.blocked_until
      };
    }

    // Sliding window: filter requests within the window
    const recentRequests = record?.requests?.filter(ts => ts > windowStart) || [];
    const currentCount = recentRequests.length;

    if (currentCount >= config.maxRequests) {
      // Rate limit exceeded - apply block if configured
      const blockUntil = config.blockDurationSeconds 
        ? now + config.blockDurationSeconds 
        : windowEnd;

      // Update record with block
      const updateCommand = new UpdateCommand({
        TableName: TableNames.SESSIONS,
        Key: { pk, sk },
        UpdateExpression: 'SET blocked_until = :blocked, #ttl = :ttl',
        ExpressionAttributeNames: { '#ttl': 'ttl' },
        ExpressionAttributeValues: {
          ':blocked': blockUntil,
          ':ttl': blockUntil + 3600 // TTL 1 hour after block expires
        }
      });

      await dynamoDb.send(updateCommand);

      return {
        allowed: false,
        remaining: 0,
        resetAt: blockUntil,
        retryAfter: blockUntil - now,
        blocked: true,
        blockExpiresAt: blockUntil
      };
    }

    // Add current request to sliding window
    const updatedRequests = [...recentRequests, now];
    const newCount = updatedRequests.length;

    if (record) {
      // Update existing record
      const updateCommand = new UpdateCommand({
        TableName: TableNames.SESSIONS,
        Key: { pk, sk },
        UpdateExpression: 'SET requests = :requests, #count = :count, #ttl = :ttl, blocked_until = :blocked',
        ExpressionAttributeNames: { '#count': 'count', '#ttl': 'ttl' },
        ExpressionAttributeValues: {
          ':requests': updatedRequests,
          ':count': newCount,
          ':ttl': windowEnd + 3600,
          ':blocked': null
        }
      });

      await dynamoDb.send(updateCommand);
    } else {
      // Create new record
      const newRecord: RateLimitRecord = {
        pk,
        sk,
        count: 1,
        window_start: now,
        requests: [now],
        ttl: windowEnd + 3600
      };

      const putCommand = new PutCommand({
        TableName: TableNames.SESSIONS,
        Item: newRecord
      });

      await dynamoDb.send(putCommand);
    }

    // Calculate when the oldest request in window will expire
    const oldestRequest = updatedRequests[0];
    const resetAt = oldestRequest + config.windowSeconds;

    return {
      allowed: true,
      remaining: Math.max(0, config.maxRequests - newCount),
      resetAt
    };
  } catch (error) {
    // On error, allow the request but log the issue
    console.error('Rate limit check error:', error);
    return {
      allowed: true,
      remaining: config.maxRequests,
      resetAt: windowEnd
    };
  }
}

/**
 * Check rate limit for a specific endpoint type
 * Convenience method with explicit endpoint parameter
 */
export async function checkEndpointRateLimit(
  realmId: string,
  endpoint: RateLimitEndpoint,
  identifier: string,
  customConfig?: RateLimitConfig
): Promise<RateLimitResult> {
  const config = customConfig || RATE_LIMIT_CONFIGS[endpoint];
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - config.windowSeconds;
  const windowEnd = now + config.windowSeconds;
  
  const { pk, sk } = generateRateLimitKey(realmId, endpoint, identifier);

  try {
    const getCommand = new GetCommand({
      TableName: TableNames.SESSIONS,
      Key: { pk, sk }
    });

    const result = await dynamoDb.send(getCommand);
    const record = result.Item as RateLimitRecord | undefined;

    // Check if currently blocked
    if (record?.blocked_until && record.blocked_until > now) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: record.blocked_until,
        retryAfter: record.blocked_until - now,
        blocked: true,
        blockExpiresAt: record.blocked_until
      };
    }

    // Sliding window calculation
    const recentRequests = record?.requests?.filter(ts => ts > windowStart) || [];
    const currentCount = recentRequests.length;

    if (currentCount >= config.maxRequests) {
      const blockUntil = config.blockDurationSeconds 
        ? now + config.blockDurationSeconds 
        : windowEnd;

      const updateCommand = new UpdateCommand({
        TableName: TableNames.SESSIONS,
        Key: { pk, sk },
        UpdateExpression: 'SET blocked_until = :blocked, #ttl = :ttl',
        ExpressionAttributeNames: { '#ttl': 'ttl' },
        ExpressionAttributeValues: {
          ':blocked': blockUntil,
          ':ttl': blockUntil + 3600
        }
      });

      await dynamoDb.send(updateCommand);

      return {
        allowed: false,
        remaining: 0,
        resetAt: blockUntil,
        retryAfter: blockUntil - now,
        blocked: true,
        blockExpiresAt: blockUntil
      };
    }

    // Add current request
    const updatedRequests = [...recentRequests, now];
    const newCount = updatedRequests.length;

    if (record) {
      const updateCommand = new UpdateCommand({
        TableName: TableNames.SESSIONS,
        Key: { pk, sk },
        UpdateExpression: 'SET requests = :requests, #count = :count, #ttl = :ttl, blocked_until = :blocked',
        ExpressionAttributeNames: { '#count': 'count', '#ttl': 'ttl' },
        ExpressionAttributeValues: {
          ':requests': updatedRequests,
          ':count': newCount,
          ':ttl': windowEnd + 3600,
          ':blocked': null
        }
      });

      await dynamoDb.send(updateCommand);
    } else {
      const newRecord: RateLimitRecord = {
        pk,
        sk,
        count: 1,
        window_start: now,
        requests: [now],
        ttl: windowEnd + 3600
      };

      const putCommand = new PutCommand({
        TableName: TableNames.SESSIONS,
        Item: newRecord
      });

      await dynamoDb.send(putCommand);
    }

    const oldestRequest = updatedRequests[0];
    const resetAt = oldestRequest + config.windowSeconds;

    return {
      allowed: true,
      remaining: Math.max(0, config.maxRequests - newCount),
      resetAt
    };
  } catch (error) {
    console.error('Rate limit check error:', error);
    return {
      allowed: true,
      remaining: config.maxRequests,
      resetAt: windowEnd
    };
  }
}

/**
 * Reset rate limit for an identifier
 * Used after successful authentication or admin override
 */
export async function resetRateLimit(
  realmId: string,
  endpoint: RateLimitEndpoint,
  identifier: string
): Promise<void> {
  const { pk, sk } = generateRateLimitKey(realmId, endpoint, identifier);

  try {
    const updateCommand = new UpdateCommand({
      TableName: TableNames.SESSIONS,
      Key: { pk, sk },
      UpdateExpression: 'SET requests = :empty, #count = :zero, blocked_until = :null',
      ExpressionAttributeNames: { '#count': 'count' },
      ExpressionAttributeValues: {
        ':empty': [],
        ':zero': 0,
        ':null': null
      }
    });

    await dynamoDb.send(updateCommand);
  } catch (error) {
    console.error('Reset rate limit error:', error);
  }
}

/**
 * Get current rate limit status without incrementing
 */
export async function getRateLimitStatus(
  realmId: string,
  endpoint: RateLimitEndpoint,
  identifier: string
): Promise<RateLimitResult> {
  const config = RATE_LIMIT_CONFIGS[endpoint];
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - config.windowSeconds;
  const windowEnd = now + config.windowSeconds;
  
  const { pk, sk } = generateRateLimitKey(realmId, endpoint, identifier);

  try {
    const getCommand = new GetCommand({
      TableName: TableNames.SESSIONS,
      Key: { pk, sk }
    });

    const result = await dynamoDb.send(getCommand);
    const record = result.Item as RateLimitRecord | undefined;

    if (!record) {
      return {
        allowed: true,
        remaining: config.maxRequests,
        resetAt: windowEnd
      };
    }

    // Check if blocked
    if (record.blocked_until && record.blocked_until > now) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: record.blocked_until,
        retryAfter: record.blocked_until - now,
        blocked: true,
        blockExpiresAt: record.blocked_until
      };
    }

    // Calculate current count in sliding window
    const recentRequests = record.requests?.filter(ts => ts > windowStart) || [];
    const currentCount = recentRequests.length;
    const remaining = Math.max(0, config.maxRequests - currentCount);

    const oldestRequest = recentRequests[0] || now;
    const resetAt = oldestRequest + config.windowSeconds;

    return {
      allowed: remaining > 0,
      remaining,
      resetAt,
      retryAfter: remaining === 0 ? resetAt - now : undefined
    };
  } catch (error) {
    console.error('Get rate limit status error:', error);
    return {
      allowed: true,
      remaining: config.maxRequests,
      resetAt: windowEnd
    };
  }
}

/**
 * Get rate limit configuration for a realm
 * Allows realm-specific overrides
 */
export function getRealmRateLimitConfig(
  realmSettings?: { rate_limit?: RateLimitConfig }
): RateLimitConfig {
  return realmSettings?.rate_limit || RATE_LIMIT_CONFIGS[RateLimitEndpoint.API_GENERAL];
}

/**
 * Get endpoint-specific rate limit configuration
 */
export function getEndpointRateLimitConfig(endpoint: RateLimitEndpoint): RateLimitConfig {
  return RATE_LIMIT_CONFIGS[endpoint];
}

/**
 * Create rate limit response headers
 */
export function createRateLimitHeaders(result: RateLimitResult): Record<string, string> {
  const headers: Record<string, string> = {
    'X-RateLimit-Remaining': result.remaining.toString(),
    'X-RateLimit-Reset': result.resetAt.toString()
  };

  if (result.retryAfter !== undefined) {
    headers['Retry-After'] = result.retryAfter.toString();
  }

  if (result.blocked) {
    headers['X-RateLimit-Blocked'] = 'true';
  }

  return headers;
}

/**
 * Check if an IP is in a whitelist (for internal services)
 */
export function isWhitelistedIP(ip: string, whitelist: string[]): boolean {
  return whitelist.includes(ip) || whitelist.some(pattern => {
    if (pattern.endsWith('*')) {
      return ip.startsWith(pattern.slice(0, -1));
    }
    return false;
  });
}

/**
 * Batch check rate limits for multiple identifiers
 * Useful for distributed attack detection
 */
export async function batchCheckRateLimits(
  realmId: string,
  endpoint: RateLimitEndpoint,
  identifiers: string[]
): Promise<Map<string, RateLimitResult>> {
  const results = new Map<string, RateLimitResult>();
  
  // Process in parallel with concurrency limit
  const batchSize = 10;
  for (let i = 0; i < identifiers.length; i += batchSize) {
    const batch = identifiers.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(id => checkEndpointRateLimit(realmId, endpoint, id))
    );
    
    batch.forEach((id, index) => {
      results.set(id, batchResults[index]);
    });
  }
  
  return results;
}
