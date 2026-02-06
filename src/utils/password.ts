/**
 * Password hashing utilities
 * Validates: Requirements 9.2 (industry-standard hashing algorithms)
 * 
 * SECURITY UPGRADE (January 2026):
 * - Using hash-wasm for Argon2id (pure WASM, Lambda-compatible)
 * - Added HaveIBeenPwned integration for leaked password detection
 * - bcrypt kept for backward compatibility during migration
 */

import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { argon2id, argon2Verify } from 'hash-wasm';
import { PASSWORD_CONFIG } from '../config/security.config';

const SALT_ROUNDS = PASSWORD_CONFIG.bcrypt.saltRounds;

// Argon2 configuration per Siberci research recommendations
// Updated 15 Jan 2026: Lambda-optimized params (CLIENT-QUESTIONS-ANSWERS.md Q2)
// - 32MB allows ~90 concurrent hashes vs 45 with 64MB
// - timeCost 5 compensates for lower memory
// - parallelism 2 matches typical Lambda vCPU count
const ARGON2_CONFIG = {
  memoryCost: 32768,    // 32 MB (Lambda-optimized, was 64MB)
  timeCost: 5,          // 5 iterations (compensates for lower memory, was 3)
  parallelism: 2,       // 2 threads (Lambda typically has 2 vCPUs, was 4)
  hashLength: 32        // 256 bits
};

/**
 * Password validation result
 */
export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Password hash result with algorithm info
 */
export interface PasswordHashResult {
  hash: string;
  algorithm: 'argon2id' | 'bcrypt';
}

/**
 * Hash a password using Argon2id (recommended)
 * Uses hash-wasm for Lambda compatibility (pure WASM)
 */
export async function hashPassword(password: string): Promise<string> {
  try {
    // Generate random salt
    const salt = crypto.randomBytes(16);
    
    // Hash with Argon2id using hash-wasm
    const hash = await argon2id({
      password,
      salt,
      parallelism: ARGON2_CONFIG.parallelism,
      iterations: ARGON2_CONFIG.timeCost,
      memorySize: ARGON2_CONFIG.memoryCost,
      hashLength: ARGON2_CONFIG.hashLength,
      outputType: 'encoded'
    });
    
    return hash;
  } catch (error) {
    // Fallback to bcrypt if argon2 fails
    console.warn('Argon2 not available, falling back to bcrypt:', error);
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    return bcrypt.hash(password, salt);
  }
}

/**
 * Verify a password against a hash
 * Automatically detects hash algorithm (Argon2 or bcrypt)
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  // Detect algorithm from hash format
  if (hash.startsWith('$argon2')) {
    try {
      return await argon2Verify({ password, hash });
    } catch (error) {
      console.error('Argon2 verification failed:', error);
      return false;
    }
  }
  
  // bcrypt hash (starts with $2a$, $2b$, or $2y$)
  return bcrypt.compare(password, hash);
}

/**
 * Check if password needs rehashing (migration from bcrypt to Argon2)
 */
export function needsRehash(hash: string): boolean {
  // If it's bcrypt, it needs rehashing to Argon2
  return !hash.startsWith('$argon2');
}

/**
 * Check if password appears in known data breaches using HaveIBeenPwned API
 * Uses k-Anonymity model - only first 5 chars of SHA-1 hash are sent
 * 
 * @returns Number of times password was found in breaches (0 = not found)
 */
export async function checkPasswordPwned(password: string): Promise<number> {
  try {
    // SHA-1 hash of password
    const hash = crypto.createHash('sha1')
      .update(password)
      .digest('hex')
      .toUpperCase();
    
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);
    
    // k-Anonymity: Only send first 5 characters
    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        headers: {
          'Add-Padding': 'true',  // Prevent response size analysis
          'User-Agent': 'Zalt.io-Auth-Service'
        }
      }
    );
    
    if (!response.ok) {
      console.warn('HaveIBeenPwned API error:', response.status);
      return 0; // Fail open - don't block registration if API is down
    }
    
    const text = await response.text();
    const hashes = text.split('\n');
    
    for (const line of hashes) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix.trim() === suffix) {
        return parseInt(count.trim(), 10);
      }
    }
    
    return 0; // Not found in breaches
  } catch (error) {
    console.error('HaveIBeenPwned check failed:', error);
    return 0; // Fail open
  }
}


/**
 * Validate password against security policy
 * Validates: Requirements 9.2 (password security)
 */
export function validatePasswordPolicy(password: string): PasswordValidationResult {
  const errors: string[] = [];
  const policy = PASSWORD_CONFIG.policy;

  if (!password || typeof password !== 'string') {
    return { valid: false, errors: ['Password is required'] };
  }

  if (password.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters long`);
  }

  if (password.length > policy.maxLength) {
    errors.push(`Password must not exceed ${policy.maxLength} characters`);
  }

  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (policy.requireNumbers && !/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (policy.requireSpecialChars) {
    const specialCharsRegex = new RegExp(`[${escapeRegex(policy.specialChars)}]`);
    if (!specialCharsRegex.test(password)) {
      errors.push('Password must contain at least one special character');
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Escape special regex characters
 */
function escapeRegex(str: string): string {
  // Escape special regex characters including hyphen
  // Hyphen must be escaped or placed at start/end of character class
  return str.replace(/[-.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Check if password is commonly used (basic check)
 */
export function isCommonPassword(password: string): boolean {
  const commonPasswords = [
    'password', 'password123', '123456', '12345678', 'qwerty',
    'abc123', 'monkey', 'letmein', 'dragon', 'master',
    'admin', 'welcome', 'login', 'passw0rd', 'Password1',
    'iloveyou', 'sunshine', 'princess', 'football', 'baseball',
    'trustno1', 'shadow', 'superman', 'michael', 'jennifer'
  ];
  
  return commonPasswords.some(
    common => password.toLowerCase() === common.toLowerCase()
  );
}

/**
 * Calculate password strength score (0-100)
 */
export function calculatePasswordStrength(password: string): number {
  if (!password) return 0;
  
  let score = 0;
  
  // Length score (up to 30 points)
  score += Math.min(password.length * 2, 30);
  
  // Character variety (up to 40 points)
  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  if (/[0-9]/.test(password)) score += 10;
  if (/[^a-zA-Z0-9]/.test(password)) score += 10;
  
  // Bonus for mixed case and numbers (up to 20 points)
  if (/(?=.*[a-z])(?=.*[A-Z])/.test(password)) score += 10;
  if (/(?=.*[0-9])(?=.*[^a-zA-Z0-9])/.test(password)) score += 10;
  
  // Penalty for common patterns
  if (/^[a-zA-Z]+$/.test(password)) score -= 10;
  if (/^[0-9]+$/.test(password)) score -= 20;
  if (isCommonPassword(password)) score -= 30;
  
  return Math.max(0, Math.min(100, score));
}

/**
 * Get password strength label
 */
export function getPasswordStrengthLabel(score: number): string {
  if (score < 20) return 'Very Weak';
  if (score < 40) return 'Weak';
  if (score < 60) return 'Fair';
  if (score < 80) return 'Strong';
  return 'Very Strong';
}
