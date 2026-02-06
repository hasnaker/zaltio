/**
 * E2E Test Setup for Zalt.io Authentication Platform
 * 
 * This module provides test utilities for end-to-end testing
 * against the actual API endpoints (staging/local).
 * 
 * @module e2e/setup
 */

import * as crypto from 'crypto';

// Test environment configuration
export const E2E_CONFIG = {
  // API endpoint - use local SAM or staging
  apiEndpoint: process.env.E2E_API_ENDPOINT || 'http://localhost:3000',
  
  // Test realm for isolation
  testRealmId: process.env.E2E_TEST_REALM || 'e2e-test-realm',
  
  // Timeouts
  requestTimeout: 30000,
  setupTimeout: 60000,
  
  // Test user prefix (for cleanup)
  testUserPrefix: 'e2e-test-',
  
  // Rate limit bypass (for testing only)
  bypassRateLimit: process.env.E2E_BYPASS_RATE_LIMIT === 'true'
};

/**
 * Test user data generator
 */
export interface TestUser {
  id?: string;
  email: string;
  password: string;
  profile: {
    first_name: string;
    last_name: string;
  };
  realm_id: string;
}

export function generateTestUser(overrides?: Partial<TestUser>): TestUser {
  const uniqueId = crypto.randomUUID().slice(0, 8);
  return {
    email: `${E2E_CONFIG.testUserPrefix}${uniqueId}@test.zalt.io`,
    password: `TestPass!${uniqueId}@2026`,
    profile: {
      first_name: 'Test',
      last_name: `User${uniqueId}`
    },
    realm_id: E2E_CONFIG.testRealmId,
    ...overrides
  };
}

/**
 * API client for E2E tests
 */
export class E2EApiClient {
  private baseUrl: string;
  private defaultHeaders: Record<string, string>;

  constructor(baseUrl: string = E2E_CONFIG.apiEndpoint) {
    this.baseUrl = baseUrl;
    this.defaultHeaders = {
      'Content-Type': 'application/json',
      'X-Test-Mode': 'e2e'
    };
  }

  async request<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      headers?: Record<string, string>;
      token?: string;
    } = {}
  ): Promise<{ status: number; data: T; headers: Headers }> {
    const headers: Record<string, string> = {
      ...this.defaultHeaders,
      ...options.headers
    };

    if (options.token) {
      headers['Authorization'] = `Bearer ${options.token}`;
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    });

    let data: T;
    try {
      data = await response.json() as T;
    } catch {
      data = {} as T;
    }

    return {
      status: response.status,
      data,
      headers: response.headers
    };
  }

  // Auth endpoints
  async register(user: TestUser) {
    return this.request<{ user_id: string; message: string }>('POST', '/v1/auth/register', {
      body: {
        realm_id: user.realm_id,
        email: user.email,
        password: user.password,
        profile: user.profile
      }
    });
  }

  async login(email: string, password: string, realmId: string, deviceFingerprint?: object) {
    return this.request<{
      access_token: string;
      refresh_token: string;
      expires_in: number;
      mfa_required?: boolean;
      mfa_session_id?: string;
    }>('POST', '/v1/auth/login', {
      body: {
        realm_id: realmId,
        email,
        password,
        device_fingerprint: deviceFingerprint || { userAgent: 'E2E-Test-Agent' }
      }
    });
  }

  async refresh(refreshToken: string) {
    return this.request<{
      access_token: string;
      refresh_token: string;
      expires_in: number;
    }>('POST', '/v1/auth/refresh', {
      body: { refresh_token: refreshToken }
    });
  }

  async logout(accessToken: string, allDevices: boolean = false) {
    return this.request<{ message: string }>('POST', '/v1/auth/logout', {
      token: accessToken,
      body: { all_devices: allDevices }
    });
  }

  async getMe(accessToken: string) {
    return this.request<{
      id: string;
      email: string;
      realm_id: string;
      profile: object;
      email_verified: boolean;
      mfa_enabled: boolean;
    }>('GET', '/v1/auth/me', {
      token: accessToken
    });
  }

  // Email verification
  async sendVerificationEmail(accessToken: string) {
    return this.request<{ message: string }>('POST', '/v1/auth/verify-email/send', {
      token: accessToken
    });
  }

  async verifyEmail(code: string, accessToken: string) {
    return this.request<{ message: string }>('POST', '/v1/auth/verify-email/confirm', {
      token: accessToken,
      body: { code }
    });
  }

  // Password reset
  async requestPasswordReset(email: string, realmId: string) {
    return this.request<{ message: string }>('POST', '/v1/auth/password-reset/request', {
      body: { email, realm_id: realmId }
    });
  }

  async confirmPasswordReset(token: string, newPassword: string) {
    return this.request<{ message: string }>('POST', '/v1/auth/password-reset/confirm', {
      body: { token, new_password: newPassword }
    });
  }

  // MFA
  async setupMFA(accessToken: string) {
    return this.request<{
      secret: string;
      qr_code_url: string;
      backup_codes: string[];
    }>('POST', '/v1/auth/mfa/totp/setup', {
      token: accessToken
    });
  }

  async verifyMFASetup(code: string, accessToken: string) {
    return this.request<{ message: string }>('POST', '/v1/auth/mfa/totp/verify', {
      token: accessToken,
      body: { code }
    });
  }

  async verifyMFALogin(sessionId: string, code: string) {
    return this.request<{
      access_token: string;
      refresh_token: string;
      expires_in: number;
    }>('POST', '/v1/auth/mfa/verify', {
      body: { mfa_session_id: sessionId, code }
    });
  }
}

/**
 * Test cleanup utilities
 */
export class E2ECleanup {
  private createdUsers: string[] = [];
  private createdSessions: string[] = [];
  private client: E2EApiClient;

  constructor(client: E2EApiClient) {
    this.client = client;
  }

  trackUser(userId: string) {
    this.createdUsers.push(userId);
  }

  trackSession(sessionId: string) {
    this.createdSessions.push(sessionId);
  }

  async cleanup() {
    // In a real implementation, this would call admin APIs to delete test data
    console.log(`[E2E Cleanup] Would delete ${this.createdUsers.length} users and ${this.createdSessions.length} sessions`);
    this.createdUsers = [];
    this.createdSessions = [];
  }
}

/**
 * Test assertions helpers
 */
export const E2EAssertions = {
  isValidJWT(token: string): boolean {
    const parts = token.split('.');
    return parts.length === 3 && parts.every(p => /^[A-Za-z0-9_-]+$/.test(p));
  },

  isValidUUID(id: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
  },

  responseTimeWithin(startTime: number, maxMs: number): boolean {
    return Date.now() - startTime < maxMs;
  }
};

/**
 * Wait utility for async operations
 */
export function wait(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry utility for flaky operations
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: { maxAttempts?: number; delayMs?: number } = {}
): Promise<T> {
  const { maxAttempts = 3, delayMs = 1000 } = options;
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (attempt < maxAttempts) {
        await wait(delayMs * attempt);
      }
    }
  }

  throw lastError;
}
