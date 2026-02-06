/**
 * Zalt.io Auth SDK Token Storage Implementations
 * @zalt/auth-sdk - Official TypeScript SDK for Zalt.io Authentication Platform
 * 
 * Validates: Requirements 4.3 (automatic token refresh)
 */

import { TokenStorage } from './types';

// Declare window for browser environments
declare const window: {
  localStorage: {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
  };
  sessionStorage: {
    getItem(key: string): string | null;
    setItem(key: string, value: string): void;
    removeItem(key: string): void;
  };
} | undefined;

/**
 * In-memory token storage (default)
 * Suitable for server-side applications and testing
 */
export class MemoryStorage implements TokenStorage {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private expiresAt: number = 0;

  getAccessToken(): string | null {
    return this.accessToken;
  }

  getRefreshToken(): string | null {
    return this.refreshToken;
  }

  setTokens(accessToken: string, refreshToken: string, expiresIn: number): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.expiresAt = Date.now() + expiresIn * 1000;
  }

  clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.expiresAt = 0;
  }

  /**
   * Get token expiration timestamp
   */
  getExpiresAt(): number {
    return this.expiresAt;
  }

  /**
   * Check if access token is expired
   */
  isExpired(): boolean {
    return Date.now() >= this.expiresAt;
  }

  /**
   * Check if token will expire within threshold
   */
  willExpireSoon(thresholdSeconds: number): boolean {
    return Date.now() >= this.expiresAt - thresholdSeconds * 1000;
  }
}

/**
 * Browser localStorage token storage
 * Suitable for browser-based applications with persistent sessions
 */
export class BrowserStorage implements TokenStorage {
  private readonly prefix: string;

  constructor(prefix: string = 'zalt_auth_') {
    this.prefix = prefix;
  }

  getAccessToken(): string | null {
    if (typeof window === 'undefined' || !window.localStorage) {
      return null;
    }
    return window.localStorage.getItem(`${this.prefix}access_token`);
  }

  getRefreshToken(): string | null {
    if (typeof window === 'undefined' || !window.localStorage) {
      return null;
    }
    return window.localStorage.getItem(`${this.prefix}refresh_token`);
  }

  setTokens(accessToken: string, refreshToken: string, expiresIn: number): void {
    if (typeof window === 'undefined' || !window.localStorage) {
      return;
    }
    const expiresAt = Date.now() + expiresIn * 1000;
    window.localStorage.setItem(`${this.prefix}access_token`, accessToken);
    window.localStorage.setItem(`${this.prefix}refresh_token`, refreshToken);
    window.localStorage.setItem(`${this.prefix}expires_at`, expiresAt.toString());
  }

  clearTokens(): void {
    if (typeof window === 'undefined' || !window.localStorage) {
      return;
    }
    window.localStorage.removeItem(`${this.prefix}access_token`);
    window.localStorage.removeItem(`${this.prefix}refresh_token`);
    window.localStorage.removeItem(`${this.prefix}expires_at`);
  }

  /**
   * Get token expiration timestamp
   */
  getExpiresAt(): number {
    if (typeof window === 'undefined' || !window.localStorage) {
      return 0;
    }
    const expiresAt = window.localStorage.getItem(`${this.prefix}expires_at`);
    return expiresAt ? parseInt(expiresAt, 10) : 0;
  }

  /**
   * Check if access token is expired
   */
  isExpired(): boolean {
    return Date.now() >= this.getExpiresAt();
  }

  /**
   * Check if token will expire within threshold
   */
  willExpireSoon(thresholdSeconds: number): boolean {
    return Date.now() >= this.getExpiresAt() - thresholdSeconds * 1000;
  }
}

/**
 * Browser sessionStorage token storage
 * Suitable for browser-based applications with session-only persistence
 * Tokens are cleared when browser tab is closed
 */
export class SessionStorage implements TokenStorage {
  private readonly prefix: string;

  constructor(prefix: string = 'zalt_auth_') {
    this.prefix = prefix;
  }

  getAccessToken(): string | null {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return null;
    }
    return window.sessionStorage.getItem(`${this.prefix}access_token`);
  }

  getRefreshToken(): string | null {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return null;
    }
    return window.sessionStorage.getItem(`${this.prefix}refresh_token`);
  }

  setTokens(accessToken: string, refreshToken: string, expiresIn: number): void {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return;
    }
    const expiresAt = Date.now() + expiresIn * 1000;
    window.sessionStorage.setItem(`${this.prefix}access_token`, accessToken);
    window.sessionStorage.setItem(`${this.prefix}refresh_token`, refreshToken);
    window.sessionStorage.setItem(`${this.prefix}expires_at`, expiresAt.toString());
  }

  clearTokens(): void {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return;
    }
    window.sessionStorage.removeItem(`${this.prefix}access_token`);
    window.sessionStorage.removeItem(`${this.prefix}refresh_token`);
    window.sessionStorage.removeItem(`${this.prefix}expires_at`);
  }

  /**
   * Get token expiration timestamp
   */
  getExpiresAt(): number {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      return 0;
    }
    const expiresAt = window.sessionStorage.getItem(`${this.prefix}expires_at`);
    return expiresAt ? parseInt(expiresAt, 10) : 0;
  }

  /**
   * Check if access token is expired
   */
  isExpired(): boolean {
    return Date.now() >= this.getExpiresAt();
  }

  /**
   * Check if token will expire within threshold
   */
  willExpireSoon(thresholdSeconds: number): boolean {
    return Date.now() >= this.getExpiresAt() - thresholdSeconds * 1000;
  }
}

/**
 * Custom storage adapter
 * Allows wrapping any storage mechanism that implements get/set/remove
 */
export class CustomStorage implements TokenStorage {
  private readonly prefix: string;
  private readonly storage: {
    get(key: string): string | null | Promise<string | null>;
    set(key: string, value: string): void | Promise<void>;
    remove(key: string): void | Promise<void>;
  };

  constructor(
    storage: {
      get(key: string): string | null | Promise<string | null>;
      set(key: string, value: string): void | Promise<void>;
      remove(key: string): void | Promise<void>;
    },
    prefix: string = 'zalt_auth_'
  ) {
    this.storage = storage;
    this.prefix = prefix;
  }

  async getAccessToken(): Promise<string | null> {
    return this.storage.get(`${this.prefix}access_token`);
  }

  async getRefreshToken(): Promise<string | null> {
    return this.storage.get(`${this.prefix}refresh_token`);
  }

  async setTokens(accessToken: string, refreshToken: string, expiresIn: number): Promise<void> {
    const expiresAt = Date.now() + expiresIn * 1000;
    await this.storage.set(`${this.prefix}access_token`, accessToken);
    await this.storage.set(`${this.prefix}refresh_token`, refreshToken);
    await this.storage.set(`${this.prefix}expires_at`, expiresAt.toString());
  }

  async clearTokens(): Promise<void> {
    await this.storage.remove(`${this.prefix}access_token`);
    await this.storage.remove(`${this.prefix}refresh_token`);
    await this.storage.remove(`${this.prefix}expires_at`);
  }
}
