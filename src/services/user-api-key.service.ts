/**
 * User API Key Service
 * Manages user-generated API keys for programmatic access
 * 
 * Features:
 * - Create API keys with custom scopes
 * - Validate keys and return user context
 * - List keys (masked) with metadata
 * - Revoke keys immediately
 * 
 * Validates: Requirements 2.3, 2.4, 2.5, 2.6 (User API Key Service)
 * 
 * Security:
 * - Keys are SHA-256 hashed (never stored in plain text)
 * - Full key returned only once on creation
 * - Revoked keys are immediately invalidated
 * - Expired keys return 401
 */

import {
  UserAPIKey,
  CreateUserAPIKeyInput,
  UserAPIKeyWithSecret,
  UserAPIKeyResponse,
  UserAPIKeyContext,
  validateUserAPIKeyScopes,
  userAPIKeyScopesAllowed,
  isValidUserAPIKeyFormat
} from '../models/user-api-key.model';
import {
  createUserAPIKey,
  getUserAPIKeyById,
  validateUserAPIKey as validateUserAPIKeyRepo,
  listUserAPIKeysByUser,
  revokeUserAPIKey,
  updateUserAPIKey,
  revokeAllUserAPIKeys,
  hasActiveUserAPIKeys
} from '../repositories/user-api-key.repository';

/**
 * User API Key Service Error
 */
export class UserAPIKeyError extends Error {
  code: string;
  statusCode: number;
  
  constructor(code: string, message: string, statusCode: number = 400) {
    super(message);
    this.name = 'UserAPIKeyError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * User API Key Service
 */
export class UserAPIKeyService {
  
  /**
   * Create a new API key for a user
   * Returns the full key only once - it cannot be retrieved later
   */
  async createKey(
    userId: string,
    realmId: string,
    config: {
      name: string;
      description?: string;
      scopes?: string[];
      expiresAt?: string;
      tenantId?: string;
      ipRestrictions?: string[];
    }
  ): Promise<UserAPIKeyWithSecret> {
    // Validate name
    if (!config.name || config.name.trim().length === 0) {
      throw new UserAPIKeyError('INVALID_NAME', 'API key name is required');
    }
    
    if (config.name.length > 100) {
      throw new UserAPIKeyError('INVALID_NAME', 'API key name must be 100 characters or less');
    }
    
    // Validate scopes if provided
    if (config.scopes && config.scopes.length > 0) {
      const scopeValidation = validateUserAPIKeyScopes(config.scopes);
      if (!scopeValidation.valid) {
        throw new UserAPIKeyError(
          'INVALID_SCOPES',
          `Invalid scopes: ${scopeValidation.invalid.join(', ')}`
        );
      }
    }
    
    // Validate expiration if provided
    if (config.expiresAt) {
      const expiresDate = new Date(config.expiresAt);
      if (isNaN(expiresDate.getTime())) {
        throw new UserAPIKeyError('INVALID_EXPIRATION', 'Invalid expiration date format');
      }
      if (expiresDate <= new Date()) {
        throw new UserAPIKeyError('INVALID_EXPIRATION', 'Expiration date must be in the future');
      }
    }
    
    // Create the key
    const result = await createUserAPIKey({
      user_id: userId,
      realm_id: realmId,
      tenant_id: config.tenantId,
      name: config.name.trim(),
      description: config.description?.trim(),
      scopes: config.scopes,
      expires_at: config.expiresAt,
      ip_restrictions: config.ipRestrictions
    });
    
    // Audit log (fire and forget)
    this.logAuditEvent('api_key.created', {
      userId,
      realmId,
      resourceId: result.key.id,
      metadata: { name: config.name, scopes: result.key.scopes }
    }).catch(() => {});
    
    return result;
  }
  
  /**
   * Validate an API key and return user context
   * Used for authenticating API requests
   */
  async validateKey(fullKey: string): Promise<UserAPIKeyContext> {
    // Validate format first
    if (!isValidUserAPIKeyFormat(fullKey)) {
      throw new UserAPIKeyError('INVALID_KEY_FORMAT', 'Invalid API key format', 401);
    }
    
    // Validate key in repository
    const context = await validateUserAPIKeyRepo(fullKey);
    
    if (!context) {
      throw new UserAPIKeyError('API_KEY_INVALID', 'API key not found or revoked', 401);
    }
    
    // Check if key is expired (double-check, repo should handle this)
    if (context.key.expires_at && new Date(context.key.expires_at) < new Date()) {
      throw new UserAPIKeyError('API_KEY_EXPIRED', 'API key has expired', 401);
    }
    
    return context;
  }
  
  /**
   * List all API keys for a user (masked, no full keys)
   */
  async listKeys(userId: string): Promise<UserAPIKeyResponse[]> {
    return listUserAPIKeysByUser(userId);
  }
  
  /**
   * Get a specific API key by ID
   */
  async getKey(userId: string, keyId: string): Promise<UserAPIKey | null> {
    return getUserAPIKeyById(userId, keyId);
  }
  
  /**
   * Revoke an API key (immediate invalidation)
   */
  async revokeKey(
    userId: string,
    keyId: string,
    revokedBy?: string
  ): Promise<UserAPIKey> {
    const key = await getUserAPIKeyById(userId, keyId);
    
    if (!key) {
      throw new UserAPIKeyError('KEY_NOT_FOUND', 'API key not found', 404);
    }
    
    if (key.status === 'revoked') {
      throw new UserAPIKeyError('KEY_ALREADY_REVOKED', 'API key is already revoked');
    }
    
    const revokedKey = await revokeUserAPIKey(userId, keyId, revokedBy);
    
    if (!revokedKey) {
      throw new UserAPIKeyError('REVOKE_FAILED', 'Failed to revoke API key');
    }
    
    // Audit log
    this.logAuditEvent('api_key.revoked', {
      userId,
      realmId: key.realm_id,
      resourceId: keyId,
      metadata: { revokedBy: revokedBy || userId }
    }).catch(() => {});
    
    return revokedKey;
  }
  
  /**
   * Update an API key's metadata
   */
  async updateKey(
    userId: string,
    keyId: string,
    updates: {
      name?: string;
      description?: string;
      scopes?: string[];
      expiresAt?: string;
      ipRestrictions?: string[];
    }
  ): Promise<UserAPIKey> {
    const key = await getUserAPIKeyById(userId, keyId);
    
    if (!key) {
      throw new UserAPIKeyError('KEY_NOT_FOUND', 'API key not found', 404);
    }
    
    if (key.status !== 'active') {
      throw new UserAPIKeyError('KEY_NOT_ACTIVE', 'Cannot update inactive API key');
    }
    
    // Validate name if provided
    if (updates.name !== undefined) {
      if (!updates.name || updates.name.trim().length === 0) {
        throw new UserAPIKeyError('INVALID_NAME', 'API key name cannot be empty');
      }
      if (updates.name.length > 100) {
        throw new UserAPIKeyError('INVALID_NAME', 'API key name must be 100 characters or less');
      }
    }
    
    // Validate scopes if provided
    if (updates.scopes && updates.scopes.length > 0) {
      const scopeValidation = validateUserAPIKeyScopes(updates.scopes);
      if (!scopeValidation.valid) {
        throw new UserAPIKeyError(
          'INVALID_SCOPES',
          `Invalid scopes: ${scopeValidation.invalid.join(', ')}`
        );
      }
    }
    
    const updatedKey = await updateUserAPIKey(userId, keyId, {
      name: updates.name?.trim(),
      description: updates.description?.trim(),
      scopes: updates.scopes,
      expires_at: updates.expiresAt,
      ip_restrictions: updates.ipRestrictions
    });
    
    if (!updatedKey) {
      throw new UserAPIKeyError('UPDATE_FAILED', 'Failed to update API key');
    }
    
    // Audit log
    this.logAuditEvent('api_key.updated', {
      userId,
      realmId: key.realm_id,
      resourceId: keyId,
      metadata: { updates: Object.keys(updates) }
    }).catch(() => {});
    
    return updatedKey;
  }
  
  /**
   * Revoke all API keys for a user
   */
  async revokeAllKeys(userId: string, revokedBy?: string): Promise<number> {
    const count = await revokeAllUserAPIKeys(userId, revokedBy);
    
    // Audit log
    this.logAuditEvent('api_key.revoked_all', {
      userId,
      metadata: { count, revokedBy: revokedBy || userId }
    }).catch(() => {});
    
    return count;
  }
  
  /**
   * Check if user has any active API keys
   */
  async hasActiveKeys(userId: string): Promise<boolean> {
    return hasActiveUserAPIKeys(userId);
  }
  
  /**
   * Check if a key's scopes allow a specific action
   */
  checkKeyScope(key: UserAPIKey, requiredScope: string): boolean {
    return userAPIKeyScopesAllowed([requiredScope], key.scopes);
  }
  
  /**
   * Log audit event
   */
  private async logAuditEvent(
    event: string,
    data: {
      userId?: string;
      realmId?: string;
      resourceId?: string;
      metadata?: Record<string, unknown>;
    }
  ): Promise<void> {
    // In production, this would call the audit service
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[AUDIT] ${event}`, JSON.stringify(data));
    }
  }
}

// Export singleton instance
export const userAPIKeyService = new UserAPIKeyService();
