/**
 * Zalt API Client for Dashboard
 * Connects dashboard to real Zalt.io backend API
 * 
 * Uses Platform APIs for customer (B2B) operations
 * Uses Admin APIs for realm/user management within customer's realms
 */

const ZALT_API_URL = process.env.NEXT_PUBLIC_ZALT_API_URL || 'https://api.zalt.io';

interface ApiResponse<T> {
  data?: T;
  error?: string;
  status: number;
}

/**
 * Make authenticated request to Zalt API
 */
export async function zaltApiRequest<T>(
  endpoint: string,
  options: {
    method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    body?: Record<string, unknown>;
    accessToken?: string;
    realmId?: string;
  } = {}
): Promise<ApiResponse<T>> {
  const { method = 'GET', body, accessToken, realmId } = options;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  if (realmId) {
    headers['X-Realm-ID'] = realmId;
  }

  try {
    const response = await fetch(`${ZALT_API_URL}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = await response.json().catch(() => null);

    return {
      data,
      status: response.status,
      error: !response.ok ? (data?.error?.message || data?.message || 'Request failed') : undefined,
    };
  } catch (error) {
    console.error('Zalt API request failed:', error);
    return {
      status: 500,
      error: 'Network error - could not connect to Zalt API',
    };
  }
}

// ============ PLATFORM (CUSTOMER) OPERATIONS ============

export interface PlatformCustomer {
  id: string;
  email: string;
  email_verified: boolean;
  profile: {
    company_name: string;
    contact_name?: string;
    phone?: string;
    website?: string;
  };
  billing: {
    plan: 'free' | 'pro' | 'enterprise';
    plan_started_at?: string;
    plan_expires_at?: string;
  };
  usage_limits: {
    max_mau: number;
    max_realms: number;
    max_api_calls_per_month: number;
  };
  status: 'active' | 'suspended' | 'pending_verification';
  default_realm_id?: string;
  created_at: string;
}

export interface PlatformApiKey {
  id: string;
  type: 'publishable' | 'secret';
  environment: 'live' | 'test';
  key_prefix: string;
  key_hint: string;
  name?: string;
  description?: string;
  status: 'active' | 'revoked';
  last_used_at?: string;
  usage_count: number;
  created_at: string;
  expires_at?: string;
}

/**
 * Get current customer profile
 */
export async function getPlatformMe(accessToken: string): Promise<ApiResponse<{
  customer: PlatformCustomer;
  api_keys: PlatformApiKey[];
  realms: { id: string; is_default: boolean }[];
}>> {
  return zaltApiRequest('/platform/me', { accessToken });
}

/**
 * List customer's API keys
 */
export async function listPlatformApiKeys(accessToken: string): Promise<ApiResponse<{
  api_keys: PlatformApiKey[];
}>> {
  return zaltApiRequest('/platform/api-keys', { accessToken });
}

/**
 * Create new API key
 */
export async function createPlatformApiKey(
  data: { type: 'publishable' | 'secret'; environment: 'live' | 'test'; name?: string; description?: string },
  accessToken: string
): Promise<ApiResponse<{
  api_key: PlatformApiKey;
  full_key: string; // Only returned on creation
}>> {
  return zaltApiRequest('/platform/api-keys', {
    method: 'POST',
    body: data,
    accessToken,
  });
}

/**
 * Revoke API key
 */
export async function revokePlatformApiKey(
  keyId: string,
  accessToken: string
): Promise<ApiResponse<{ success: boolean }>> {
  return zaltApiRequest(`/platform/api-keys/${keyId}`, {
    method: 'DELETE',
    accessToken,
  });
}

/**
 * List customer's realms
 */
export async function listPlatformRealms(accessToken: string): Promise<ApiResponse<{
  realms: ZaltRealm[];
}>> {
  return zaltApiRequest('/platform/realms', { accessToken });
}

/**
 * Create new realm
 */
export async function createPlatformRealm(
  data: { name: string; domain?: string; settings?: Record<string, unknown> },
  accessToken: string
): Promise<ApiResponse<{ realm: ZaltRealm }>> {
  return zaltApiRequest('/platform/realms', {
    method: 'POST',
    body: data,
    accessToken,
  });
}

/**
 * Get customer's usage stats
 */
export async function getPlatformUsage(accessToken: string): Promise<ApiResponse<{
  usage: {
    mau: number;
    api_calls: number;
    realms: number;
  };
  limits: {
    max_mau: number;
    max_api_calls: number;
    max_realms: number;
  };
  period: {
    start: string;
    end: string;
  };
}>> {
  return zaltApiRequest('/platform/usage', { accessToken });
}

/**
 * Get billing info
 */
export async function getPlatformBilling(accessToken: string): Promise<ApiResponse<{
  plan: 'free' | 'pro' | 'enterprise';
  status: 'active' | 'past_due' | 'canceled';
  current_period_end?: string;
  stripe_customer_id?: string;
}>> {
  return zaltApiRequest('/platform/billing', { accessToken });
}

/**
 * Create Stripe checkout session
 */
export async function createPlatformCheckout(
  data: { plan: 'pro' | 'enterprise'; success_url: string; cancel_url: string },
  accessToken: string
): Promise<ApiResponse<{ checkout_url: string }>> {
  return zaltApiRequest('/platform/billing/checkout', {
    method: 'POST',
    body: data,
    accessToken,
  });
}

/**
 * Get Stripe customer portal URL
 */
export async function getPlatformBillingPortal(
  data: { return_url: string },
  accessToken: string
): Promise<ApiResponse<{ portal_url: string }>> {
  return zaltApiRequest('/platform/billing/portal', {
    method: 'POST',
    body: data,
    accessToken,
  });
}

// ============ REALM OPERATIONS ============

export interface ZaltRealm {
  id: string;
  realmId: string;
  name: string;
  domain?: string;
  status: 'active' | 'suspended';
  settings: {
    mfa_required?: boolean;
    session_timeout?: number;
    password_policy?: {
      min_length: number;
      require_uppercase: boolean;
      require_lowercase: boolean;
      require_numbers: boolean;
    };
    branding?: {
      display_name?: string;
      email_from_address?: string;
      app_url?: string;
    };
  };
  createdAt: string;
  updatedAt: string;
}

export async function listRealms(accessToken?: string): Promise<ApiResponse<{ realms: ZaltRealm[] }>> {
  return zaltApiRequest('/v1/admin/realms', { accessToken });
}

export async function getRealm(realmId: string, accessToken?: string): Promise<ApiResponse<{ realm: ZaltRealm }>> {
  return zaltApiRequest(`/v1/admin/realms/${realmId}`, { accessToken });
}

export async function createRealm(
  data: { name: string; domain?: string; settings?: Record<string, unknown> },
  accessToken?: string
): Promise<ApiResponse<{ realm: ZaltRealm }>> {
  return zaltApiRequest('/v1/admin/realms', {
    method: 'POST',
    body: data,
    accessToken,
  });
}

export async function updateRealm(
  realmId: string,
  data: Partial<ZaltRealm>,
  accessToken?: string
): Promise<ApiResponse<{ realm: ZaltRealm }>> {
  return zaltApiRequest(`/v1/admin/realms/${realmId}`, {
    method: 'PATCH',
    body: data,
    accessToken,
  });
}

// ============ USER OPERATIONS ============

export interface ZaltUser {
  id: string;
  email: string;
  email_verified: boolean;
  status: 'active' | 'suspended' | 'pending_verification' | 'locked';
  profile?: {
    first_name?: string;
    last_name?: string;
    metadata?: Record<string, unknown>;
  };
  mfa_enabled: boolean;
  created_at: string;
  last_login_at?: string;
}

export async function listUsers(
  realmId: string,
  options?: { limit?: number; cursor?: string },
  accessToken?: string
): Promise<ApiResponse<{ users: ZaltUser[]; nextCursor?: string }>> {
  const params = new URLSearchParams();
  if (options?.limit) params.set('limit', options.limit.toString());
  if (options?.cursor) params.set('cursor', options.cursor);
  
  return zaltApiRequest(`/v1/admin/users?realm_id=${realmId}&${params}`, { accessToken });
}

export async function getUser(
  realmId: string,
  userId: string,
  accessToken?: string
): Promise<ApiResponse<{ user: ZaltUser }>> {
  return zaltApiRequest(`/v1/admin/users/${userId}?realm_id=${realmId}`, { accessToken });
}

export async function suspendUser(
  realmId: string,
  userId: string,
  accessToken?: string
): Promise<ApiResponse<{ success: boolean }>> {
  return zaltApiRequest(`/v1/admin/users/${userId}/suspend`, {
    method: 'POST',
    body: { realm_id: realmId },
    accessToken,
  });
}

export async function activateUser(
  realmId: string,
  userId: string,
  accessToken?: string
): Promise<ApiResponse<{ success: boolean }>> {
  return zaltApiRequest(`/v1/admin/users/${userId}/activate`, {
    method: 'POST',
    body: { realm_id: realmId },
    accessToken,
  });
}

// ============ SESSION OPERATIONS ============

export interface ZaltSession {
  id: string;
  user_id: string;
  realm_id: string;
  ip_address: string;
  user_agent: string;
  device_name?: string;
  created_at: string;
  last_activity_at: string;
  expires_at: string;
}

export async function listSessions(
  realmId: string,
  userId?: string,
  accessToken?: string
): Promise<ApiResponse<{ sessions: ZaltSession[] }>> {
  const params = new URLSearchParams({ realm_id: realmId });
  if (userId) params.set('user_id', userId);
  
  return zaltApiRequest(`/v1/admin/sessions?${params}`, { accessToken });
}

export async function revokeSession(
  sessionId: string,
  accessToken?: string
): Promise<ApiResponse<{ success: boolean }>> {
  return zaltApiRequest(`/v1/admin/sessions/${sessionId}`, {
    method: 'DELETE',
    accessToken,
  });
}

// ============ STATS OPERATIONS ============

export interface ZaltStats {
  totalRealms: number;
  totalUsers: number;
  activeSessions: number;
  loginsTodayCount: number;
  mfaEnabledUsers: number;
  recentSignups: number;
}

export async function getDashboardStats(
  realmId?: string,
  accessToken?: string
): Promise<ApiResponse<ZaltStats>> {
  const endpoint = realmId ? `/v1/admin/stats?realm_id=${realmId}` : '/v1/admin/stats';
  return zaltApiRequest(endpoint, { accessToken });
}

export { ZALT_API_URL };
