/**
 * Cryptographic Utilities for Zalt.io Auth Platform
 * Task 6.7: Timing Attack Prevention
 * 
 * SECURITY CRITICAL:
 * - All comparison functions use constant-time algorithms
 * - Prevents timing-based side-channel attacks
 * - Used for password verification, token comparison, HMAC verification
 * 
 * @security-module
 * @owasp A02:2021 - Cryptographic Failures
 */

import * as crypto from 'crypto';

/**
 * Constant-time string comparison
 * Prevents timing attacks by always comparing all characters
 * 
 * @param a - First string to compare
 * @param b - Second string to compare
 * @returns true if strings are equal, false otherwise
 * 
 * @security Uses crypto.timingSafeEqual internally
 * @timing Execution time is independent of where strings differ
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  // Handle empty strings
  if (a.length === 0 && b.length === 0) {
    return true;
  }

  if (a.length === 0 || b.length === 0) {
    // Still perform comparison to maintain constant time
    const dummy = crypto.timingSafeEqual(
      Buffer.from('dummy'),
      Buffer.from('dummy')
    );
    return false;
  }

  // Pad to same length to prevent length-based timing attacks
  const maxLen = Math.max(a.length, b.length);
  const paddedA = a.padEnd(maxLen, '\0');
  const paddedB = b.padEnd(maxLen, '\0');

  try {
    const result = crypto.timingSafeEqual(
      Buffer.from(paddedA, 'utf8'),
      Buffer.from(paddedB, 'utf8')
    );
    
    // Only return true if lengths were originally equal AND content matches
    return result && a.length === b.length;
  } catch {
    return false;
  }
}

/**
 * Constant-time buffer comparison
 * Direct wrapper around crypto.timingSafeEqual with safety checks
 * 
 * @param a - First buffer to compare
 * @param b - Second buffer to compare
 * @returns true if buffers are equal, false otherwise
 * 
 * @security Uses crypto.timingSafeEqual internally
 * @timing Execution time is independent of buffer content
 */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    return false;
  }

  if (a.length === 0 && b.length === 0) {
    return true;
  }

  if (a.length !== b.length) {
    // Perform dummy comparison to maintain constant time
    const maxLen = Math.max(a.length, b.length);
    const paddedA = Buffer.alloc(maxLen);
    const paddedB = Buffer.alloc(maxLen);
    a.copy(paddedA);
    b.copy(paddedB);
    
    crypto.timingSafeEqual(paddedA, paddedB);
    return false;
  }

  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Constant-time hex string comparison
 * Optimized for comparing hex-encoded values (tokens, hashes)
 * 
 * @param a - First hex string
 * @param b - Second hex string
 * @returns true if hex strings are equal, false otherwise
 */
export function constantTimeHexCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  // Validate hex format
  const hexRegex = /^[0-9a-fA-F]*$/;
  if (!hexRegex.test(a) || !hexRegex.test(b)) {
    // Still perform comparison to maintain constant time
    constantTimeCompare(a, b);
    return false;
  }

  try {
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    return constantTimeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Constant-time HMAC verification
 * Verifies HMAC signature in constant time
 * 
 * @param message - Original message
 * @param signature - Provided HMAC signature (hex)
 * @param secret - HMAC secret key
 * @param algorithm - Hash algorithm (default: sha256)
 * @returns true if signature is valid, false otherwise
 */
export function verifyHmacConstantTime(
  message: string | Buffer,
  signature: string,
  secret: string | Buffer,
  algorithm: string = 'sha256'
): boolean {
  if (!message || !signature || !secret) {
    return false;
  }

  try {
    const expectedSignature = crypto
      .createHmac(algorithm, secret)
      .update(message)
      .digest('hex');

    return constantTimeHexCompare(signature, expectedSignature);
  } catch {
    return false;
  }
}

/**
 * Constant-time token hash verification
 * Verifies a token against its stored hash
 * 
 * @param token - Plain token to verify
 * @param storedHash - Stored hash (hex)
 * @param algorithm - Hash algorithm (default: sha256)
 * @returns true if token matches hash, false otherwise
 */
export function verifyTokenHashConstantTime(
  token: string,
  storedHash: string,
  algorithm: string = 'sha256'
): boolean {
  if (!token || !storedHash) {
    return false;
  }

  try {
    const tokenHash = crypto
      .createHash(algorithm)
      .update(token)
      .digest('hex');

    return constantTimeHexCompare(tokenHash, storedHash);
  } catch {
    return false;
  }
}

/**
 * Generate cryptographically secure random bytes
 * 
 * @param length - Number of bytes to generate
 * @returns Buffer of random bytes
 */
export function secureRandomBytes(length: number): Buffer {
  if (length <= 0 || length > 65536) {
    throw new Error('Invalid length for random bytes');
  }
  return crypto.randomBytes(length);
}

/**
 * Generate cryptographically secure random hex string
 * 
 * @param length - Number of bytes (output will be 2x length in hex chars)
 * @returns Hex string of random bytes
 */
export function secureRandomHex(length: number): string {
  return secureRandomBytes(length).toString('hex');
}

/**
 * Generate cryptographically secure random integer
 * 
 * @param min - Minimum value (inclusive)
 * @param max - Maximum value (exclusive)
 * @returns Random integer in range [min, max)
 */
export function secureRandomInt(min: number, max: number): number {
  if (min >= max) {
    throw new Error('min must be less than max');
  }
  return crypto.randomInt(min, max);
}

/**
 * Hash data with SHA-256
 * 
 * @param data - Data to hash
 * @returns Hex-encoded hash
 */
export function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Hash data with SHA-512
 * 
 * @param data - Data to hash
 * @returns Hex-encoded hash
 */
export function sha512(data: string | Buffer): string {
  return crypto.createHash('sha512').update(data).digest('hex');
}

/**
 * Create HMAC signature
 * 
 * @param data - Data to sign
 * @param secret - HMAC secret
 * @param algorithm - Hash algorithm (default: sha256)
 * @returns Hex-encoded HMAC
 */
export function createHmac(
  data: string | Buffer,
  secret: string | Buffer,
  algorithm: string = 'sha256'
): string {
  return crypto.createHmac(algorithm, secret).update(data).digest('hex');
}

/**
 * Timing-safe user lookup helper
 * Always performs hash computation to prevent user enumeration
 * 
 * @param userExists - Whether user was found
 * @param storedHash - Stored password hash (or fake hash if user doesn't exist)
 * @param providedHash - Hash of provided password
 * @returns true only if user exists AND hashes match
 */
export function timingSafeUserVerify(
  userExists: boolean,
  storedHash: string,
  providedHash: string
): boolean {
  // Always perform comparison regardless of user existence
  const hashMatch = constantTimeHexCompare(storedHash, providedHash);
  
  // Only return true if BOTH conditions are met
  return userExists && hashMatch;
}

/**
 * Add random jitter to prevent timing analysis
 * 
 * @param baseDelayMs - Base delay in milliseconds
 * @param jitterMs - Maximum jitter to add (default: 50ms)
 * @returns Promise that resolves after delay
 */
export async function addTimingJitter(
  baseDelayMs: number = 0,
  jitterMs: number = 50
): Promise<void> {
  const jitter = secureRandomInt(0, jitterMs + 1);
  const totalDelay = baseDelayMs + jitter;
  
  if (totalDelay > 0) {
    await new Promise(resolve => setTimeout(resolve, totalDelay));
  }
}

/**
 * Constant-time API key comparison
 * Specifically designed for API key validation
 * 
 * @param providedKey - API key provided in request
 * @param storedKey - Stored API key
 * @returns true if keys match, false otherwise
 */
export function verifyApiKey(providedKey: string, storedKey: string): boolean {
  if (!providedKey || !storedKey) {
    // Perform dummy comparison
    constantTimeCompare('dummy', 'dummy');
    return false;
  }

  return constantTimeCompare(providedKey, storedKey);
}

/**
 * Constant-time session token comparison
 * 
 * @param providedToken - Token from request
 * @param storedToken - Token from database
 * @returns true if tokens match, false otherwise
 */
export function verifySessionToken(providedToken: string, storedToken: string): boolean {
  return constantTimeCompare(providedToken, storedToken);
}

/**
 * Constant-time refresh token comparison
 * 
 * @param providedToken - Refresh token from request
 * @param storedTokenHash - Hashed refresh token from database
 * @returns true if token matches hash, false otherwise
 */
export function verifyRefreshToken(providedToken: string, storedTokenHash: string): boolean {
  return verifyTokenHashConstantTime(providedToken, storedTokenHash);
}
