/**
 * E2E Test Helpers for Zalt.io Authentication Platform
 * 
 * Utility functions for common E2E test scenarios
 * 
 * @module e2e/helpers
 */

import { E2EApiClient, TestUser, generateTestUser, E2EAssertions, wait } from './setup';
import * as crypto from 'crypto';

/**
 * TOTP code generator for MFA testing
 * Uses the same algorithm as Google Authenticator
 */
export function generateTOTPCode(secret: string, timeOffset: number = 0): string {
  const time = Math.floor((Date.now() / 1000 + timeOffset) / 30);
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigInt64BE(BigInt(time));

  // Decode base32 secret
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of secret.toUpperCase().replace(/=/g, '')) {
    const val = base32Chars.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const secretBuffer = Buffer.from(
    bits.match(/.{8}/g)?.map(b => parseInt(b, 2)) || []
  );

  // HMAC-SHA1
  const hmac = crypto.createHmac('sha1', secretBuffer);
  hmac.update(timeBuffer);
  const hash = hmac.digest();

  // Dynamic truncation
  const offset = hash[hash.length - 1] & 0x0f;
  const code = (
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff)
  ) % 1000000;

  return code.toString().padStart(6, '0');
}

/**
 * Device fingerprint generator for testing
 */
export function generateDeviceFingerprint(options?: {
  userAgent?: string;
  screenResolution?: string;
  timezone?: string;
  language?: string;
}): object {
  return {
    userAgent: options?.userAgent || 'Mozilla/5.0 (E2E Test) Chrome/120.0.0.0',
    screenResolution: options?.screenResolution || '1920x1080',
    timezone: options?.timezone || 'Europe/Istanbul',
    language: options?.language || 'tr-TR',
    platform: 'E2E-Test',
    colorDepth: 24,
    hardwareConcurrency: 8,
    deviceMemory: 8
  };
}

/**
 * Full registration and login flow helper
 */
export async function registerAndLogin(
  client: E2EApiClient,
  userOverrides?: Partial<TestUser>
): Promise<{
  user: TestUser;
  accessToken: string;
  refreshToken: string;
}> {
  const user = generateTestUser(userOverrides);

  // Register
  const registerResult = await client.register(user);
  if (registerResult.status !== 201 && registerResult.status !== 200) {
    throw new Error(`Registration failed: ${JSON.stringify(registerResult.data)}`);
  }
  user.id = registerResult.data.user_id;

  // Login
  const loginResult = await client.login(
    user.email,
    user.password,
    user.realm_id,
    generateDeviceFingerprint()
  );
  if (loginResult.status !== 200) {
    throw new Error(`Login failed: ${JSON.stringify(loginResult.data)}`);
  }

  return {
    user,
    accessToken: loginResult.data.access_token,
    refreshToken: loginResult.data.refresh_token
  };
}

/**
 * Full MFA setup flow helper
 */
export async function setupMFA(
  client: E2EApiClient,
  accessToken: string
): Promise<{
  secret: string;
  backupCodes: string[];
}> {
  // Get MFA setup
  const setupResult = await client.setupMFA(accessToken);
  if (setupResult.status !== 200) {
    throw new Error(`MFA setup failed: ${JSON.stringify(setupResult.data)}`);
  }

  const { secret, backup_codes } = setupResult.data;

  // Generate and verify TOTP code
  const code = generateTOTPCode(secret);
  const verifyResult = await client.verifyMFASetup(code, accessToken);
  if (verifyResult.status !== 200) {
    throw new Error(`MFA verification failed: ${JSON.stringify(verifyResult.data)}`);
  }

  return {
    secret,
    backupCodes: backup_codes
  };
}

/**
 * Login with MFA flow helper
 */
export async function loginWithMFA(
  client: E2EApiClient,
  email: string,
  password: string,
  realmId: string,
  mfaSecret: string
): Promise<{
  accessToken: string;
  refreshToken: string;
}> {
  // Initial login
  const loginResult = await client.login(email, password, realmId);
  if (loginResult.status !== 200) {
    throw new Error(`Login failed: ${JSON.stringify(loginResult.data)}`);
  }

  if (!loginResult.data.mfa_required) {
    // MFA not required, return tokens directly
    return {
      accessToken: loginResult.data.access_token,
      refreshToken: loginResult.data.refresh_token
    };
  }

  // MFA required - verify
  const code = generateTOTPCode(mfaSecret);
  const mfaResult = await client.verifyMFALogin(
    loginResult.data.mfa_session_id!,
    code
  );
  if (mfaResult.status !== 200) {
    throw new Error(`MFA login failed: ${JSON.stringify(mfaResult.data)}`);
  }

  return {
    accessToken: mfaResult.data.access_token,
    refreshToken: mfaResult.data.refresh_token
  };
}

/**
 * Rate limit testing helper
 */
export async function testRateLimit(
  fn: () => Promise<{ status: number }>,
  options: {
    expectedLimit: number;
    expectedStatus: number;
  }
): Promise<{
  successCount: number;
  rateLimitedAt: number;
}> {
  let successCount = 0;
  let rateLimitedAt = -1;

  for (let i = 0; i < options.expectedLimit + 5; i++) {
    const result = await fn();
    if (result.status === 429) {
      rateLimitedAt = i;
      break;
    }
    if (result.status === options.expectedStatus) {
      successCount++;
    }
  }

  return { successCount, rateLimitedAt };
}

/**
 * Token refresh grace period testing helper
 */
export async function testGracePeriod(
  client: E2EApiClient,
  refreshToken: string,
  gracePeriodMs: number = 30000
): Promise<{
  firstRefresh: { accessToken: string; refreshToken: string };
  secondRefresh: { accessToken: string; refreshToken: string };
  sameTokens: boolean;
}> {
  // First refresh
  const first = await client.refresh(refreshToken);
  if (first.status !== 200) {
    throw new Error(`First refresh failed: ${JSON.stringify(first.data)}`);
  }

  // Immediate second refresh with OLD token (within grace period)
  const second = await client.refresh(refreshToken);
  if (second.status !== 200) {
    throw new Error(`Second refresh failed: ${JSON.stringify(second.data)}`);
  }

  return {
    firstRefresh: {
      accessToken: first.data.access_token,
      refreshToken: first.data.refresh_token
    },
    secondRefresh: {
      accessToken: second.data.access_token,
      refreshToken: second.data.refresh_token
    },
    // Within grace period, should return same tokens
    sameTokens: 
      first.data.access_token === second.data.access_token &&
      first.data.refresh_token === second.data.refresh_token
  };
}

/**
 * Security header validation helper
 */
export function validateSecurityHeaders(headers: Headers): {
  valid: boolean;
  missing: string[];
} {
  const requiredHeaders = [
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'x-xss-protection'
  ];

  const missing: string[] = [];
  for (const header of requiredHeaders) {
    if (!headers.get(header)) {
      missing.push(header);
    }
  }

  return {
    valid: missing.length === 0,
    missing
  };
}

/**
 * Response time measurement helper
 */
export async function measureResponseTime<T>(
  fn: () => Promise<T>
): Promise<{ result: T; durationMs: number }> {
  const start = Date.now();
  const result = await fn();
  const durationMs = Date.now() - start;
  return { result, durationMs };
}

/**
 * Concurrent request testing helper
 */
export async function testConcurrentRequests<T>(
  fn: () => Promise<T>,
  concurrency: number
): Promise<{
  results: T[];
  totalDurationMs: number;
  avgDurationMs: number;
}> {
  const start = Date.now();
  const promises = Array(concurrency).fill(null).map(() => fn());
  const results = await Promise.all(promises);
  const totalDurationMs = Date.now() - start;

  return {
    results,
    totalDurationMs,
    avgDurationMs: totalDurationMs / concurrency
  };
}
