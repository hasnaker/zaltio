/**
 * Zalt Storage Adapters
 * @zalt/core
 * 
 * Token storage implementations for different environments
 */

import type { TokenStorage } from './types';

// ============================================================================
// Memory Storage (Default - for SSR/testing)
// ============================================================================

/**
 * In-memory storage - tokens lost on page refresh
 * Use for SSR or testing environments
 */
export class MemoryStorage implements TokenStorage {
  private store: Map<string, string> = new Map();

  get(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  set(key: string, value: string): void {
    this.store.set(key, value);
  }

  remove(key: string): void {
    this.store.delete(key);
  }

  /** Clear all stored values */
  clear(): void {
    this.store.clear();
  }
}

// ============================================================================
// Browser Storage (localStorage)
// ============================================================================

/**
 * Browser localStorage storage - persists across sessions
 * Use for client-side web applications
 */
export class BrowserStorage implements TokenStorage {
  private prefix: string;

  constructor(prefix: string = 'zalt_') {
    this.prefix = prefix;
  }

  get(key: string): string | null {
    if (typeof window === 'undefined') return null;
    try {
      return localStorage.getItem(this.prefix + key);
    } catch {
      // localStorage might be disabled
      return null;
    }
  }

  set(key: string, value: string): void {
    if (typeof window === 'undefined') return;
    try {
      localStorage.setItem(this.prefix + key, value);
    } catch {
      // localStorage might be full or disabled
      console.warn('[Zalt] Failed to save to localStorage');
    }
  }

  remove(key: string): void {
    if (typeof window === 'undefined') return;
    try {
      localStorage.removeItem(this.prefix + key);
    } catch {
      // Ignore errors
    }
  }

  /** Clear all Zalt-related stored values */
  clear(): void {
    if (typeof window === 'undefined') return;
    try {
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key?.startsWith(this.prefix)) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key));
    } catch {
      // Ignore errors
    }
  }
}

// ============================================================================
// Session Storage
// ============================================================================

/**
 * Browser sessionStorage - cleared when tab closes
 * Use for more secure client-side storage
 */
export class SessionStorage implements TokenStorage {
  private prefix: string;

  constructor(prefix: string = 'zalt_') {
    this.prefix = prefix;
  }

  get(key: string): string | null {
    if (typeof window === 'undefined') return null;
    try {
      return sessionStorage.getItem(this.prefix + key);
    } catch {
      return null;
    }
  }

  set(key: string, value: string): void {
    if (typeof window === 'undefined') return;
    try {
      sessionStorage.setItem(this.prefix + key, value);
    } catch {
      console.warn('[Zalt] Failed to save to sessionStorage');
    }
  }

  remove(key: string): void {
    if (typeof window === 'undefined') return;
    try {
      sessionStorage.removeItem(this.prefix + key);
    } catch {
      // Ignore errors
    }
  }

  /** Clear all Zalt-related stored values */
  clear(): void {
    if (typeof window === 'undefined') return;
    try {
      const keysToRemove: string[] = [];
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key?.startsWith(this.prefix)) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => sessionStorage.removeItem(key));
    } catch {
      // Ignore errors
    }
  }
}

// ============================================================================
// Cookie Storage (for Next.js/SSR)
// ============================================================================

/**
 * Cookie-based storage - works with SSR
 * Use for Next.js or other SSR frameworks
 */
export class CookieStorage implements TokenStorage {
  private prefix: string;
  private secure: boolean;
  private sameSite: 'strict' | 'lax' | 'none';
  private path: string;
  private maxAge: number;

  constructor(options: {
    prefix?: string;
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    path?: string;
    maxAge?: number;
  } = {}) {
    this.prefix = options.prefix ?? 'zalt_';
    this.secure = options.secure ?? (typeof window !== 'undefined' && window.location.protocol === 'https:');
    this.sameSite = options.sameSite ?? 'lax';
    this.path = options.path ?? '/';
    this.maxAge = options.maxAge ?? 7 * 24 * 60 * 60; // 7 days
  }

  get(key: string): string | null {
    if (typeof document === 'undefined') return null;
    
    const name = this.prefix + key + '=';
    const decodedCookie = decodeURIComponent(document.cookie);
    const cookies = decodedCookie.split(';');
    
    for (const cookie of cookies) {
      const trimmed = cookie.trim();
      if (trimmed.startsWith(name)) {
        return trimmed.substring(name.length);
      }
    }
    return null;
  }

  set(key: string, value: string): void {
    if (typeof document === 'undefined') return;
    
    const cookieParts = [
      `${this.prefix}${key}=${encodeURIComponent(value)}`,
      `path=${this.path}`,
      `max-age=${this.maxAge}`,
      `samesite=${this.sameSite}`,
    ];
    
    if (this.secure) {
      cookieParts.push('secure');
    }
    
    document.cookie = cookieParts.join('; ');
  }

  remove(key: string): void {
    if (typeof document === 'undefined') return;
    
    // Set cookie with expired date to remove it
    document.cookie = `${this.prefix}${key}=; path=${this.path}; max-age=0`;
  }

  /** Clear all Zalt-related cookies */
  clear(): void {
    if (typeof document === 'undefined') return;
    
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name] = cookie.trim().split('=');
      if (name.startsWith(this.prefix)) {
        document.cookie = `${name}=; path=${this.path}; max-age=0`;
      }
    }
  }
}

// ============================================================================
// Custom Storage Wrapper
// ============================================================================

/**
 * Wrapper for custom storage implementations
 * Allows using any async storage (e.g., React Native AsyncStorage)
 */
export class CustomStorage implements TokenStorage {
  private getItem: (key: string) => string | null | Promise<string | null>;
  private setItem: (key: string, value: string) => void | Promise<void>;
  private removeItem: (key: string) => void | Promise<void>;

  constructor(options: {
    getItem: (key: string) => string | null | Promise<string | null>;
    setItem: (key: string, value: string) => void | Promise<void>;
    removeItem: (key: string) => void | Promise<void>;
  }) {
    this.getItem = options.getItem;
    this.setItem = options.setItem;
    this.removeItem = options.removeItem;
  }

  get(key: string): string | null | Promise<string | null> {
    return this.getItem(key);
  }

  set(key: string, value: string): void | Promise<void> {
    return this.setItem(key, value);
  }

  remove(key: string): void | Promise<void> {
    return this.removeItem(key);
  }
}

// ============================================================================
// Storage Keys
// ============================================================================

/** Standard storage keys used by Zalt SDK */
export const STORAGE_KEYS = {
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
  USER: 'user',
  EXPIRES_AT: 'expires_at',
  DEVICE_ID: 'device_id',
} as const;

// ============================================================================
// Auto-detect best storage
// ============================================================================

/**
 * Automatically select the best storage for the current environment
 */
export function createAutoStorage(): TokenStorage {
  // Server-side: use memory
  if (typeof window === 'undefined') {
    return new MemoryStorage();
  }
  
  // Browser: prefer localStorage, fallback to memory
  try {
    localStorage.setItem('zalt_test', 'test');
    localStorage.removeItem('zalt_test');
    return new BrowserStorage();
  } catch {
    return new MemoryStorage();
  }
}
