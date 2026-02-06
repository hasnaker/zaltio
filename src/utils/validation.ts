/**
 * Validation utilities for HSD Auth Platform
 * Validates: Requirements 1.1, 9.2
 */

import { PasswordPolicy, DEFAULT_PASSWORD_POLICY } from '../models/realm.model';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validates email format
 */
export function validateEmail(email: string): ValidationResult {
  const errors: string[] = [];
  
  if (!email || typeof email !== 'string') {
    errors.push('Email is required');
    return { valid: false, errors };
  }

  const trimmedEmail = email.trim().toLowerCase();
  
  if (trimmedEmail.length === 0) {
    errors.push('Email cannot be empty');
    return { valid: false, errors };
  }

  // RFC 5322 compliant email regex (simplified)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmedEmail)) {
    errors.push('Invalid email format');
    return { valid: false, errors };
  }

  if (trimmedEmail.length > 254) {
    errors.push('Email exceeds maximum length of 254 characters');
    return { valid: false, errors };
  }

  return { valid: true, errors: [] };
}

/**
 * Validates password against policy
 */
export function validatePassword(
  password: string,
  policy: PasswordPolicy = DEFAULT_PASSWORD_POLICY
): ValidationResult {
  const errors: string[] = [];

  if (!password || typeof password !== 'string') {
    errors.push('Password is required');
    return { valid: false, errors };
  }

  if (password.length < policy.min_length) {
    errors.push(`Password must be at least ${policy.min_length} characters`);
  }

  if (policy.require_uppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (policy.require_lowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (policy.require_numbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (policy.require_special_chars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validates realm ID format
 */
export function validateRealmId(realmId: string): ValidationResult {
  const errors: string[] = [];

  if (!realmId || typeof realmId !== 'string') {
    errors.push('Realm ID is required');
    return { valid: false, errors };
  }

  const trimmedRealmId = realmId.trim();

  if (trimmedRealmId.length === 0) {
    errors.push('Realm ID cannot be empty');
    return { valid: false, errors };
  }

  // Realm ID should be alphanumeric with hyphens, 3-64 chars
  const realmIdRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,62}[a-zA-Z0-9]$/;
  if (!realmIdRegex.test(trimmedRealmId) && trimmedRealmId.length >= 3) {
    errors.push('Realm ID must be alphanumeric with hyphens, 3-64 characters');
  } else if (trimmedRealmId.length < 3) {
    errors.push('Realm ID must be at least 3 characters');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validates realm name
 */
export function validateRealmName(name: string): ValidationResult {
  const errors: string[] = [];

  if (!name || typeof name !== 'string') {
    errors.push('Realm name is required');
    return { valid: false, errors };
  }

  const trimmedName = name.trim();

  if (trimmedName.length === 0) {
    errors.push('Realm name cannot be empty');
    return { valid: false, errors };
  }

  if (trimmedName.length < 3) {
    errors.push('Realm name must be at least 3 characters');
    return { valid: false, errors };
  }

  if (trimmedName.length > 64) {
    errors.push('Realm name cannot exceed 64 characters');
    return { valid: false, errors };
  }

  // Name should start with alphanumeric
  if (!/^[a-zA-Z0-9]/.test(trimmedName)) {
    errors.push('Realm name must start with a letter or number');
    return { valid: false, errors };
  }

  return { valid: true, errors: [] };
}

/**
 * Validates domain format
 */
export function validateDomain(domain: string): ValidationResult {
  const errors: string[] = [];

  if (!domain || typeof domain !== 'string') {
    errors.push('Domain is required');
    return { valid: false, errors };
  }

  const trimmedDomain = domain.trim().toLowerCase();

  if (trimmedDomain.length === 0) {
    errors.push('Domain cannot be empty');
    return { valid: false, errors };
  }

  // Basic domain validation
  const domainRegex = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;
  if (!domainRegex.test(trimmedDomain)) {
    errors.push('Invalid domain format');
    return { valid: false, errors };
  }

  if (trimmedDomain.length > 253) {
    errors.push('Domain exceeds maximum length of 253 characters');
    return { valid: false, errors };
  }

  return { valid: true, errors: [] };
}

/**
 * Validates realm settings
 */
export function validateRealmSettings(settings: unknown): ValidationResult {
  const errors: string[] = [];

  if (!settings || typeof settings !== 'object') {
    return { valid: true, errors: [] }; // Settings are optional
  }

  const s = settings as Record<string, unknown>;

  // Validate session_timeout
  if (s.session_timeout !== undefined) {
    if (typeof s.session_timeout !== 'number' || s.session_timeout < 300) {
      errors.push('Session timeout must be at least 300 seconds (5 minutes)');
    }
    if (typeof s.session_timeout === 'number' && s.session_timeout > 604800) {
      errors.push('Session timeout cannot exceed 604800 seconds (7 days)');
    }
  }

  // Validate password_policy
  if (s.password_policy !== undefined) {
    const pp = s.password_policy as Record<string, unknown>;
    if (typeof pp !== 'object') {
      errors.push('Password policy must be an object');
    } else {
      if (pp.min_length !== undefined) {
        if (typeof pp.min_length !== 'number' || pp.min_length < 6) {
          errors.push('Minimum password length must be at least 6');
        }
        if (typeof pp.min_length === 'number' && pp.min_length > 128) {
          errors.push('Minimum password length cannot exceed 128');
        }
      }
    }
  }

  // Validate allowed_origins
  if (s.allowed_origins !== undefined) {
    if (!Array.isArray(s.allowed_origins)) {
      errors.push('Allowed origins must be an array');
    } else {
      for (const origin of s.allowed_origins) {
        if (typeof origin !== 'string') {
          errors.push('Each allowed origin must be a string');
          break;
        }
        // Basic URL validation for origins
        if (origin !== '*' && !/^https?:\/\//.test(origin)) {
          errors.push('Allowed origins must be valid URLs or "*"');
          break;
        }
      }
    }
  }

  return { valid: errors.length === 0, errors };
}
