/**
 * Configuration and API utilities for Zalt MCP Server
 * @zalt/mcp-server
 */

// Configuration from environment
export const ZALT_API_URL = process.env.ZALT_API_URL || 'https://api.zalt.io';
export const ZALT_ADMIN_KEY = process.env.ZALT_ADMIN_KEY || '';

// API Response type
interface ApiResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
  status?: number;
}

/**
 * Make an authenticated API request to Zalt API
 */
export async function makeApiRequest<T = unknown>(
  endpoint: string,
  options: {
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
    body?: Record<string, unknown>;
  }
): Promise<ApiResponse<T>> {
  const url = `${ZALT_API_URL}${endpoint}`;
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (ZALT_ADMIN_KEY) {
    headers['X-Zalt-Admin-Key'] = ZALT_ADMIN_KEY;
  }

  try {
    const response = await fetch(url, {
      method: options.method,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      return {
        ok: false,
        error: (data as { error?: { message?: string }; message?: string }).error?.message 
          || (data as { message?: string }).message 
          || `HTTP ${response.status}`,
        status: response.status,
      };
    }

    return {
      ok: true,
      data: data as T,
      status: response.status,
    };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : 'Network error',
    };
  }
}
