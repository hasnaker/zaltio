/**
 * Zalt Token Manager
 * @zalt/core
 * 
 * Handles token storage, retrieval, refresh, and expiry checking
 * with automatic refresh deduplication
 */

import type { TokenStorage, TokenResult, JWTClaims } from './types';
import { TokenRefreshError } from './errors';
import { MemoryStorage, STORAGE_KEYS } from './storage';

/**
 * Token manager configuration
 */
export interface TokenManagerConfig {
  storage: TokenStorage;
  /** Callback to refresh tokens */
  onRefresh?: () => Promise<TokenResult>;
  /** Buffer time before expiry to trigger refresh (ms) */
  refreshBuffer?: number;
  /** Enable debug logging */
  debug?: boolean;
}

/**
 * Manages token lifecycle - storage, retrieval, refresh, expiry
 */
export class TokenManager {
  private storage: TokenStorage;
  private onRefresh?: () => Promise<TokenResult>;
  private refreshBuffer: number;
  private debug: boolean;
  
  // Refresh deduplication
  private refreshPromise: Promise<TokenResult> | null = null;
  private refreshLock = false;

  constructor(config: TokenManagerConfig) {
    this.storage = config.storage || new MemoryStorage();
    this.onRefresh = config.onRefresh;
    this.refreshBuffer = config.refreshBuffer ?? 60000; // 1 minute default
    this.debug = config.debug ?? false;
  }

  /**
   * Store tokens
   */
  async storeTokens(tokens: TokenResult): Promise<void> {
    const expiresAt = Date.now() + tokens.expiresIn * 1000;
    
    await Promise.all([
      this.storage.set(STORAGE_KEYS.ACCESS_TOKEN, tokens.accessToken),
      this.storage.set(STORAGE_KEYS.REFRESH_TOKEN, tokens.refreshToken),
      this.storage.set(STORAGE_KEYS.EXPIRES_AT, expiresAt.toString()),
    ]);

    this.log('Tokens stored, expires at:', new Date(expiresAt).toISOString());
  }

  /**
   * Get access token, refreshing if needed
   */
  async getAccessToken(): Promise<string | null> {
    const token = await this.storage.get(STORAGE_KEYS.ACCESS_TOKEN);
    
    if (!token) {
      this.log('No access token found');
      return null;
    }

    // Check if token needs refresh
    if (await this.shouldRefresh()) {
      this.log('Token needs refresh');
      try {
        const newTokens = await this.refresh();
        return newTokens.accessToken;
      } catch (error) {
        this.log('Refresh failed:', error);
        // Return existing token if refresh fails but token not expired
        if (!(await this.isExpired())) {
          return token;
        }
        return null;
      }
    }

    return token;
  }

  /**
   * Get refresh token
   */
  async getRefreshToken(): Promise<string | null> {
    return this.storage.get(STORAGE_KEYS.REFRESH_TOKEN);
  }

  /**
   * Check if token is expired
   */
  async isExpired(): Promise<boolean> {
    const expiresAtStr = await this.storage.get(STORAGE_KEYS.EXPIRES_AT);
    if (!expiresAtStr) return true;
    
    const expiresAt = parseInt(expiresAtStr, 10);
    return Date.now() >= expiresAt;
  }

  /**
   * Check if token should be refreshed (within buffer time)
   */
  async shouldRefresh(): Promise<boolean> {
    const expiresAtStr = await this.storage.get(STORAGE_KEYS.EXPIRES_AT);
    if (!expiresAtStr) return false;
    
    const expiresAt = parseInt(expiresAtStr, 10);
    return Date.now() >= expiresAt - this.refreshBuffer;
  }

  /**
   * Refresh tokens with deduplication
   * Multiple concurrent calls will share the same refresh request
   */
  async refresh(): Promise<TokenResult> {
    // If refresh is already in progress, wait for it
    if (this.refreshPromise) {
      this.log('Refresh already in progress, waiting...');
      return this.refreshPromise;
    }

    // Acquire lock
    if (this.refreshLock) {
      throw new TokenRefreshError('Refresh already in progress');
    }
    this.refreshLock = true;

    try {
      if (!this.onRefresh) {
        throw new TokenRefreshError('No refresh callback configured');
      }

      this.log('Starting token refresh');
      
      // Create and store the promise for deduplication
      this.refreshPromise = this.onRefresh();
      
      const tokens = await this.refreshPromise;
      await this.storeTokens(tokens);
      
      this.log('Token refresh successful');
      return tokens;
    } finally {
      // Release lock and clear promise
      this.refreshLock = false;
      this.refreshPromise = null;
    }
  }

  /**
   * Clear all tokens
   */
  async clearTokens(): Promise<void> {
    await Promise.all([
      this.storage.remove(STORAGE_KEYS.ACCESS_TOKEN),
      this.storage.remove(STORAGE_KEYS.REFRESH_TOKEN),
      this.storage.remove(STORAGE_KEYS.EXPIRES_AT),
    ]);
    this.log('Tokens cleared');
  }

  /**
   * Check if user has tokens stored
   */
  async hasTokens(): Promise<boolean> {
    const token = await this.storage.get(STORAGE_KEYS.ACCESS_TOKEN);
    return token !== null;
  }

  /**
   * Decode JWT without verification (for client-side claims reading)
   * WARNING: Do not use for security decisions - always verify on server
   */
  decodeToken(token: string): JWTClaims | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      
      const payload = parts[1];
      const decoded = this.base64UrlDecode(payload);
      return JSON.parse(decoded) as JWTClaims;
    } catch {
      return null;
    }
  }

  /**
   * Get token expiry time
   */
  async getExpiresAt(): Promise<number | null> {
    const expiresAtStr = await this.storage.get(STORAGE_KEYS.EXPIRES_AT);
    if (!expiresAtStr) return null;
    return parseInt(expiresAtStr, 10);
  }

  /**
   * Get time until token expires (ms)
   */
  async getTimeUntilExpiry(): Promise<number | null> {
    const expiresAt = await this.getExpiresAt();
    if (!expiresAt) return null;
    return Math.max(0, expiresAt - Date.now());
  }

  /**
   * Set refresh callback
   */
  setRefreshCallback(callback: () => Promise<TokenResult>): void {
    this.onRefresh = callback;
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private base64UrlDecode(str: string): string {
    // Replace URL-safe characters
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding if needed
    const padding = base64.length % 4;
    if (padding) {
      base64 += '='.repeat(4 - padding);
    }
    
    // Decode
    if (typeof atob !== 'undefined') {
      return atob(base64);
    }
    
    // Node.js fallback
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  private log(...args: unknown[]): void {
    if (this.debug) {
      console.log('[Zalt TokenManager]', ...args);
    }
  }
}

/**
 * Create a token manager with default configuration
 */
export function createTokenManager(config: Partial<TokenManagerConfig> = {}): TokenManager {
  return new TokenManager({
    storage: config.storage || new MemoryStorage(),
    onRefresh: config.onRefresh,
    refreshBuffer: config.refreshBuffer,
    debug: config.debug,
  });
}
