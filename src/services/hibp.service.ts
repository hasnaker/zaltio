/**
 * HaveIBeenPwned (HIBP) Service for Zalt.io Auth Platform
 * Task 17.1: Implement HaveIBeenPwned integration
 * 
 * SECURITY FEATURES:
 * - k-Anonymity API integration (only first 5 chars of SHA-1 hash sent)
 * - SHA-1 prefix lookup
 * - In-memory cache for performance
 * - Fail-open design (don't block auth if API is down)
 * 
 * PRIVACY:
 * - NEVER sends full password or full hash to HIBP API
 * - Uses k-Anonymity: only first 5 characters of SHA-1 hash are sent
 * - The API returns all hash suffixes that match the prefix
 * - Comparison is done locally
 * 
 * _Requirements: 8.1, 8.2_
 */

import crypto from 'crypto';

/**
 * Result of checking a password against HIBP
 */
export interface HIBPCheckResult {
  /** Whether the password was found in breach databases */
  isCompromised: boolean;
  /** Number of times the password appeared in breaches (0 if not found) */
  count: number;
  /** Whether the result came from cache */
  fromCache: boolean;
  /** Error message if check failed */
  error?: string;
}

/**
 * Cache entry for HIBP results
 */
interface CacheEntry {
  /** Map of hash suffix to breach count */
  suffixes: Map<string, number>;
  /** Timestamp when entry was cached */
  cachedAt: number;
  /** TTL in milliseconds */
  ttl: number;
}

/**
 * HIBP Service configuration
 */
export interface HIBPServiceConfig {
  /** Base URL for HIBP API (default: https://api.pwnedpasswords.com) */
  apiBaseUrl?: string;
  /** Cache TTL in milliseconds (default: 5 minutes) */
  cacheTtlMs?: number;
  /** Maximum cache size (default: 10000 entries) */
  maxCacheSize?: number;
  /** Request timeout in milliseconds (default: 5000) */
  timeoutMs?: number;
  /** User-Agent header for API requests */
  userAgent?: string;
  /** Whether to add padding to prevent response size analysis */
  addPadding?: boolean;
  /** Whether to fail open (return not compromised) on API errors */
  failOpen?: boolean;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: Required<HIBPServiceConfig> = {
  apiBaseUrl: 'https://api.pwnedpasswords.com',
  cacheTtlMs: 5 * 60 * 1000, // 5 minutes
  maxCacheSize: 10000,
  timeoutMs: 5000,
  userAgent: 'Zalt.io-Auth-Service/1.0',
  addPadding: true,
  failOpen: true,
};

/**
 * HaveIBeenPwned Service
 * 
 * Provides password breach checking using the HIBP k-Anonymity API.
 * Results are cached to improve performance and reduce API calls.
 */
export class HIBPService {
  private config: Required<HIBPServiceConfig>;
  private cache: Map<string, CacheEntry>;
  private cacheHits: number = 0;
  private cacheMisses: number = 0;
  private apiCalls: number = 0;
  private apiErrors: number = 0;

  constructor(config: HIBPServiceConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.cache = new Map();
  }

  /**
   * Check if a password has been compromised in known data breaches
   * 
   * Uses the HIBP k-Anonymity API:
   * 1. Hash the password with SHA-1
   * 2. Send only the first 5 characters of the hash to HIBP
   * 3. HIBP returns all hash suffixes that match the prefix
   * 4. Check locally if the full hash suffix is in the response
   * 
   * @param password - The password to check
   * @returns Promise<HIBPCheckResult> - Result indicating if password is compromised
   * 
   * @example
   * ```typescript
   * const hibp = new HIBPService();
   * const result = await hibp.checkPassword('password123');
   * if (result.isCompromised) {
   *   console.log(`Password found ${result.count} times in breaches`);
   * }
   * ```
   */
  async checkPassword(password: string): Promise<HIBPCheckResult> {
    if (!password || typeof password !== 'string') {
      return {
        isCompromised: false,
        count: 0,
        fromCache: false,
        error: 'Invalid password provided',
      };
    }

    // Generate SHA-1 hash of password
    const hash = this.hashPassword(password);
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);

    // Check cache first
    const cachedResult = this.checkCache(prefix, suffix);
    if (cachedResult !== null) {
      this.cacheHits++;
      return {
        isCompromised: cachedResult > 0,
        count: cachedResult,
        fromCache: true,
      };
    }

    this.cacheMisses++;

    // Fetch from HIBP API
    try {
      const suffixes = await this.fetchFromAPI(prefix);
      
      // Cache the result
      this.setCache(prefix, suffixes);

      // Check if our suffix is in the results
      const count = suffixes.get(suffix) || 0;

      return {
        isCompromised: count > 0,
        count,
        fromCache: false,
      };
    } catch (error) {
      this.apiErrors++;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      if (this.config.failOpen) {
        // Fail open - don't block authentication if API is down
        console.warn(`HIBP check failed (fail-open): ${errorMessage}`);
        return {
          isCompromised: false,
          count: 0,
          fromCache: false,
          error: errorMessage,
        };
      }

      // Fail closed - treat as compromised if API is down
      throw new Error(`HIBP check failed: ${errorMessage}`);
    }
  }

  /**
   * Generate SHA-1 hash of password (uppercase hex)
   * 
   * @param password - Password to hash
   * @returns Uppercase hex string of SHA-1 hash
   */
  hashPassword(password: string): string {
    return crypto
      .createHash('sha1')
      .update(password)
      .digest('hex')
      .toUpperCase();
  }

  /**
   * Check cache for a hash prefix/suffix combination
   * 
   * @param prefix - First 5 characters of SHA-1 hash
   * @param suffix - Remaining characters of SHA-1 hash
   * @returns Breach count if cached, null if not in cache or expired
   */
  private checkCache(prefix: string, suffix: string): number | null {
    const entry = this.cache.get(prefix);
    
    if (!entry) {
      return null;
    }

    // Check if cache entry has expired
    if (Date.now() - entry.cachedAt > entry.ttl) {
      this.cache.delete(prefix);
      return null;
    }

    // Return the count for this suffix (0 if not found in suffixes)
    return entry.suffixes.has(suffix) ? entry.suffixes.get(suffix)! : 0;
  }

  /**
   * Store HIBP response in cache
   * 
   * @param prefix - First 5 characters of SHA-1 hash
   * @param suffixes - Map of hash suffixes to breach counts
   */
  private setCache(prefix: string, suffixes: Map<string, number>): void {
    // Evict oldest entries if cache is full
    if (this.cache.size >= this.config.maxCacheSize) {
      this.evictOldestEntries();
    }

    this.cache.set(prefix, {
      suffixes,
      cachedAt: Date.now(),
      ttl: this.config.cacheTtlMs,
    });
  }

  /**
   * Evict oldest cache entries to make room for new ones
   */
  private evictOldestEntries(): void {
    // Remove 10% of oldest entries
    const entriesToRemove = Math.ceil(this.config.maxCacheSize * 0.1);
    const entries = Array.from(this.cache.entries())
      .sort((a, b) => a[1].cachedAt - b[1].cachedAt);

    for (let i = 0; i < entriesToRemove && i < entries.length; i++) {
      this.cache.delete(entries[i][0]);
    }
  }

  /**
   * Fetch hash suffixes from HIBP API
   * 
   * @param prefix - First 5 characters of SHA-1 hash
   * @returns Map of hash suffixes to breach counts
   */
  private async fetchFromAPI(prefix: string): Promise<Map<string, number>> {
    this.apiCalls++;

    const url = `${this.config.apiBaseUrl}/range/${prefix}`;
    const headers: Record<string, string> = {
      'User-Agent': this.config.userAgent,
    };

    if (this.config.addPadding) {
      headers['Add-Padding'] = 'true';
    }

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(url, {
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HIBP API returned status ${response.status}`);
      }

      const text = await response.text();
      return this.parseAPIResponse(text);
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(`HIBP API request timed out after ${this.config.timeoutMs}ms`);
      }
      
      throw error;
    }
  }

  /**
   * Parse HIBP API response into a map of suffixes to counts
   * 
   * Response format:
   * ```
   * SUFFIX1:COUNT1
   * SUFFIX2:COUNT2
   * ...
   * ```
   * 
   * @param responseText - Raw response text from HIBP API
   * @returns Map of hash suffixes to breach counts
   */
  private parseAPIResponse(responseText: string): Map<string, number> {
    const suffixes = new Map<string, number>();
    const lines = responseText.split('\n');

    for (const line of lines) {
      const trimmedLine = line.trim();
      if (!trimmedLine) continue;

      const colonIndex = trimmedLine.indexOf(':');
      if (colonIndex === -1) continue;

      const suffix = trimmedLine.substring(0, colonIndex).trim();
      const countStr = trimmedLine.substring(colonIndex + 1).trim();
      const count = parseInt(countStr, 10);

      if (suffix && !isNaN(count) && count > 0) {
        suffixes.set(suffix, count);
      }
    }

    return suffixes;
  }

  /**
   * Clear the cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): {
    size: number;
    hits: number;
    misses: number;
    hitRate: number;
    apiCalls: number;
    apiErrors: number;
  } {
    const total = this.cacheHits + this.cacheMisses;
    return {
      size: this.cache.size,
      hits: this.cacheHits,
      misses: this.cacheMisses,
      hitRate: total > 0 ? this.cacheHits / total : 0,
      apiCalls: this.apiCalls,
      apiErrors: this.apiErrors,
    };
  }

  /**
   * Reset statistics counters
   */
  resetStats(): void {
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.apiCalls = 0;
    this.apiErrors = 0;
  }

  /**
   * Check if a pre-computed SHA-1 hash has been compromised
   * Used by background breach check job where we store SHA-1 hashes
   * 
   * @param sha1Hash - The SHA-1 hash to check (uppercase hex, 40 characters)
   * @returns Promise<HIBPCheckResult> - Result indicating if hash is compromised
   * 
   * @example
   * ```typescript
   * const hibp = new HIBPService();
   * // SHA-1 hash of "password" (uppercase)
   * const result = await hibp.checkPasswordHash('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
   * if (result.isCompromised) {
   *   console.log(`Hash found ${result.count} times in breaches`);
   * }
   * ```
   */
  async checkPasswordHash(sha1Hash: string): Promise<HIBPCheckResult> {
    if (!sha1Hash || typeof sha1Hash !== 'string' || sha1Hash.length !== 40) {
      return {
        isCompromised: false,
        count: 0,
        fromCache: false,
        error: 'Invalid SHA-1 hash provided (must be 40 character hex string)',
      };
    }

    // Normalize to uppercase
    const hash = sha1Hash.toUpperCase();
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);

    // Check cache first
    const cachedResult = this.checkCache(prefix, suffix);
    if (cachedResult !== null) {
      this.cacheHits++;
      return {
        isCompromised: cachedResult > 0,
        count: cachedResult,
        fromCache: true,
      };
    }

    this.cacheMisses++;

    // Fetch from HIBP API
    try {
      const suffixes = await this.fetchFromAPI(prefix);
      
      // Cache the result
      this.setCache(prefix, suffixes);

      // Check if our suffix is in the results
      const count = suffixes.get(suffix) || 0;

      return {
        isCompromised: count > 0,
        count,
        fromCache: false,
      };
    } catch (error) {
      this.apiErrors++;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      if (this.config.failOpen) {
        // Fail open - don't block if API is down
        console.warn(`HIBP hash check failed (fail-open): ${errorMessage}`);
        return {
          isCompromised: false,
          count: 0,
          fromCache: false,
          error: errorMessage,
        };
      }

      // Fail closed - treat as error
      throw new Error(`HIBP hash check failed: ${errorMessage}`);
    }
  }
}

// Singleton instance for convenience
let defaultInstance: HIBPService | null = null;

/**
 * Get the default HIBP service instance
 */
export function getHIBPService(): HIBPService {
  if (!defaultInstance) {
    defaultInstance = new HIBPService();
  }
  return defaultInstance;
}

/**
 * Create a new HIBP service instance with custom configuration
 */
export function createHIBPService(config?: HIBPServiceConfig): HIBPService {
  return new HIBPService(config);
}

/**
 * Check if a password has been compromised (convenience function)
 * Uses the default singleton instance
 * 
 * @param password - Password to check
 * @returns Promise<HIBPCheckResult>
 */
export async function checkPassword(password: string): Promise<HIBPCheckResult> {
  return getHIBPService().checkPassword(password);
}

/**
 * Check if a password is compromised and return just the boolean result
 * 
 * @param password - Password to check
 * @returns Promise<boolean> - true if compromised, false otherwise
 */
export async function isPasswordCompromised(password: string): Promise<boolean> {
  const result = await checkPassword(password);
  return result.isCompromised;
}
