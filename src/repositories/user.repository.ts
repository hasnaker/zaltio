/**
 * User Repository - DynamoDB operations for users
 * Validates: Requirements 1.1, 1.2 (realm isolation)
 */

import {
  PutCommand,
  GetCommand,
  QueryCommand,
  DeleteCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from '../services/dynamodb.service';
import { User, CreateUserInput, UserResponse, UserStatus } from '../models/user.model';
import { hashPassword } from '../utils/password';
import * as crypto from 'crypto';

// Use crypto.randomUUID() instead of uuid package for ESM compatibility
const uuidv4 = () => crypto.randomUUID();

/**
 * Creates a composite key for realm isolation
 * Format: realm_id#user_id
 */
function createUserPK(realmId: string, userId: string): string {
  return `${realmId}#${userId}`;
}

/**
 * Check if a user exists by email within a specific realm
 */
export async function findUserByEmail(
  realmId: string,
  email: string
): Promise<User | null> {
  const command = new QueryCommand({
    TableName: TableNames.USERS,
    IndexName: 'email-index',
    KeyConditionExpression: 'email = :email',
    FilterExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':email': email.toLowerCase().trim(),
      ':realmId': realmId
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  return result.Items[0] as User;
}

/**
 * Get user by ID within a specific realm
 */
export async function findUserById(
  realmId: string,
  id: string
): Promise<User | null> {
  const command = new GetCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, id),
      sk: `USER#${id}`
    }
  });

  const result = await dynamoDb.send(command);
  
  return result.Item as User | null;
}

/**
 * Create a new user with realm isolation
 */
export async function createUser(input: CreateUserInput): Promise<UserResponse> {
  const id = uuidv4();
  const now = new Date().toISOString();
  const passwordHash = await hashPassword(input.password);

  // Use pk/sk as primary keys (matches DynamoDB table schema)
  const user = {
    pk: createUserPK(input.realm_id, id),  // Primary key: realm_id#user_id
    sk: `USER#${id}`,                       // Sort key
    userId: id,
    id: id,
    realm_id: input.realm_id,
    realmId: input.realm_id,  // Alternative field name
    email: input.email.toLowerCase().trim(),
    email_verified: false,
    password_hash: passwordHash,
    profile: {
      first_name: input.profile?.first_name,
      last_name: input.profile?.last_name,
      avatar_url: input.profile?.avatar_url,
      metadata: input.profile?.metadata || {}
    },
    created_at: now,
    updated_at: now,
    last_login: now,
    status: 'pending_verification' as const
  };

  const command = new PutCommand({
    TableName: TableNames.USERS,
    Item: user,
    ConditionExpression: 'attribute_not_exists(pk)'
  });

  await dynamoDb.send(command);

  // Return user without password_hash
  const { password_hash, ...userResponse } = user;
  return userResponse as UserResponse;
}

/**
 * Update user's last login timestamp
 */
export async function updateLastLogin(
  realmId: string,
  userId: string
): Promise<void> {
  const command = new UpdateCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, userId),
      sk: `USER#${userId}`
    },
    UpdateExpression: 'SET last_login = :now, updated_at = :now',
    ExpressionAttributeValues: {
      ':now': new Date().toISOString()
    }
  });

  await dynamoDb.send(command);
}

/**
 * Delete user from a realm
 */
export async function deleteUser(
  realmId: string,
  userId: string
): Promise<void> {
  const command = new DeleteCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, userId),
      sk: `USER#${userId}`
    }
  });

  await dynamoDb.send(command);
}

/**
 * Delete all users in a realm (for realm cleanup)
 * Validates: Requirements 1.5 (cascading deletion)
 */
export async function deleteAllRealmUsers(realmId: string): Promise<number> {
  // Query all users in this realm using GSI
  const queryCommand = new QueryCommand({
    TableName: TableNames.USERS,
    IndexName: 'realm-index',
    KeyConditionExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':realmId': realmId
    }
  });

  const result = await dynamoDb.send(queryCommand);
  
  if (!result.Items || result.Items.length === 0) {
    return 0;
  }

  // Delete each user
  let deletedCount = 0;
  for (const item of result.Items) {
    const user = item as User & { pk: string; sk: string };
    const deleteCommand = new DeleteCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: user.pk,
        sk: user.sk
      }
    });
    
    try {
      await dynamoDb.send(deleteCommand);
      deletedCount++;
    } catch {
      // Continue with other deletions
      console.error(`Failed to delete user ${user.id} in realm ${realmId}`);
    }
  }

  return deletedCount;
}

/**
 * Count users in a realm
 */
export async function countRealmUsers(realmId: string): Promise<number> {
  const command = new QueryCommand({
    TableName: TableNames.USERS,
    IndexName: 'realm-index',
    KeyConditionExpression: 'realm_id = :realmId',
    ExpressionAttributeValues: {
      ':realmId': realmId
    },
    Select: 'COUNT'
  });

  const result = await dynamoDb.send(command);
  return result.Count || 0;
}

import { UpdateCommand } from '@aws-sdk/lib-dynamodb';

/**
 * Update user's email_verified status
 */
export async function updateUserEmailVerified(
  realmId: string,
  userId: string,
  verified: boolean
): Promise<void> {
  const command = new UpdateCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, userId),
      sk: `USER#${userId}`
    },
    UpdateExpression: 'SET email_verified = :verified, #status = :status, updated_at = :now',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':verified': verified,
      ':status': verified ? 'active' : 'pending_verification',
      ':now': new Date().toISOString()
    }
  });

  await dynamoDb.send(command);
}

/**
 * Update user's password
 */
export async function updateUserPassword(
  realmId: string,
  userId: string,
  passwordHash: string
): Promise<void> {
  const command = new UpdateCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, userId),
      sk: `USER#${userId}`
    },
    UpdateExpression: 'SET password_hash = :hash, updated_at = :now, password_changed_at = :now',
    ExpressionAttributeValues: {
      ':hash': passwordHash,
      ':now': new Date().toISOString()
    }
  });

  await dynamoDb.send(command);
}

/**
 * Update user's MFA settings
 */
export async function updateUserMFA(
  realmId: string,
  userId: string,
  mfaEnabled: boolean,
  mfaSecret?: string,
  backupCodes?: string[]
): Promise<void> {
  const updateExpression = mfaEnabled
    ? 'SET mfa_enabled = :enabled, mfa_secret = :secret, backup_codes = :codes, updated_at = :now'
    : 'SET mfa_enabled = :enabled, updated_at = :now REMOVE mfa_secret, backup_codes';

  const expressionValues: Record<string, unknown> = {
    ':enabled': mfaEnabled,
    ':now': new Date().toISOString()
  };

  if (mfaEnabled && mfaSecret) {
    expressionValues[':secret'] = mfaSecret;
    expressionValues[':codes'] = backupCodes || [];
  }

  const command = new UpdateCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, userId),
      sk: `USER#${userId}`
    },
    UpdateExpression: updateExpression,
    ExpressionAttributeValues: expressionValues
  });

  await dynamoDb.send(command);
}

/**
 * Update user's status (for document verification flow)
 */
export async function updateUserStatus(
  realmId: string,
  userId: string,
  status: 'pending_verification' | 'pending_document_review' | 'active' | 'suspended' | 'rejected'
): Promise<void> {
  const command = new UpdateCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, userId),
      sk: `USER#${userId}`
    },
    UpdateExpression: 'SET #status = :status, updated_at = :now',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':status': status,
      ':now': new Date().toISOString()
    }
  });

  await dynamoDb.send(command);
}


/**
 * Update user's failed login attempts and lockout status
 * Used for brute force protection
 */
export async function updateUserLoginAttempts(
  userId: string,
  failedAttempts: number,
  lockedUntil?: string
): Promise<void> {
  // Note: We need to find the user first to get the realm_id
  // In production, this should be optimized with a GSI on user_id
  const updateExpression = lockedUntil
    ? 'SET failed_login_attempts = :attempts, locked_until = :locked, updated_at = :now'
    : 'SET failed_login_attempts = :attempts, updated_at = :now REMOVE locked_until';

  const expressionValues: Record<string, unknown> = {
    ':attempts': failedAttempts,
    ':now': new Date().toISOString()
  };

  if (lockedUntil) {
    expressionValues[':locked'] = lockedUntil;
  }

  // Query to find user by ID (using GSI)
  const queryCommand = new QueryCommand({
    TableName: TableNames.USERS,
    IndexName: 'user-id-index',
    KeyConditionExpression: 'id = :userId',
    ExpressionAttributeValues: {
      ':userId': userId
    },
    Limit: 1
  });

  try {
    const result = await dynamoDb.send(queryCommand);
    if (result.Items && result.Items.length > 0) {
      const user = result.Items[0] as { pk: string; sk: string };
      
      const command = new UpdateCommand({
        TableName: TableNames.USERS,
        Key: {
          pk: user.pk,
          sk: user.sk
        },
        UpdateExpression: updateExpression,
        ExpressionAttributeValues: expressionValues
      });

      await dynamoDb.send(command);
    }
  } catch (error) {
    console.error('Failed to update login attempts:', error);
    // Don't throw - this is a non-critical operation
  }
}

/**
 * Update user's WebAuthn credentials
 * Used for passkey/biometric authentication
 */
export async function updateUserWebAuthn(
  realmId: string,
  userId: string,
  credentials: Array<{
    id: string;
    credentialId: Buffer;
    publicKey: Buffer;
    counter: number;
    transports?: string[];
    createdAt: string;
    lastUsedAt?: string;
    deviceName?: string;
    aaguid?: string;
  }>
): Promise<void> {
  // Serialize Buffer fields for DynamoDB storage
  const serializedCredentials = credentials.map(cred => ({
    ...cred,
    credentialId: cred.credentialId.toString('base64'),
    publicKey: cred.publicKey.toString('base64')
  }));

  const command = new UpdateCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, userId),
      sk: `USER#${userId}`
    },
    UpdateExpression: 'SET webauthn_credentials = :credentials, updated_at = :now',
    ExpressionAttributeValues: {
      ':credentials': serializedCredentials,
      ':now': new Date().toISOString()
    }
  });

  await dynamoDb.send(command);
}


/**
 * Update user's profile metadata
 * Used for account linking and other metadata updates
 */
export async function updateUserMetadata(
  realmId: string,
  userId: string,
  metadata: Record<string, unknown>
): Promise<void> {
  const command = new UpdateCommand({
    TableName: TableNames.USERS,
    Key: {
      pk: createUserPK(realmId, userId),
      sk: `USER#${userId}`
    },
    UpdateExpression: 'SET profile.metadata = :metadata, updated_at = :now',
    ExpressionAttributeValues: {
      ':metadata': metadata,
      ':now': new Date().toISOString()
    }
  });

  await dynamoDb.send(command);
}


// ============================================================================
// ADMIN USER MANAGEMENT (Task 9.3)
// ============================================================================

/**
 * List users in a realm with pagination
 * Used by admin dashboard for user management
 */
export async function listRealmUsers(
  realmId: string,
  options: {
    limit?: number;
    lastEvaluatedKey?: Record<string, unknown>;
    status?: UserStatus;
    search?: string;
  } = {}
): Promise<{
  users: UserResponse[];
  lastEvaluatedKey?: Record<string, unknown>;
  total: number;
}> {
  const { limit = 50, lastEvaluatedKey, status, search } = options;

  // Build filter expression
  let filterExpression = 'realm_id = :realmId';
  const expressionAttributeValues: Record<string, unknown> = {
    ':realmId': realmId
  };

  if (status) {
    filterExpression += ' AND #status = :status';
    expressionAttributeValues[':status'] = status;
  }

  if (search) {
    filterExpression += ' AND (contains(email, :search) OR contains(profile.first_name, :search) OR contains(profile.last_name, :search))';
    expressionAttributeValues[':search'] = search.toLowerCase();
  }

  const command = new QueryCommand({
    TableName: TableNames.USERS,
    IndexName: 'realm-index',
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: status || search ? filterExpression.replace('realm_id = :realmId AND ', '') : undefined,
    ExpressionAttributeValues: expressionAttributeValues,
    ExpressionAttributeNames: status ? { '#status': 'status' } : undefined,
    Limit: limit,
    ExclusiveStartKey: lastEvaluatedKey as Record<string, unknown> | undefined
  });

  const result = await dynamoDb.send(command);

  // Map to UserResponse (exclude sensitive fields)
  const users: UserResponse[] = (result.Items || []).map((item) => {
    const user = item as User;
    return {
      id: user.id,
      realm_id: user.realm_id,
      email: user.email,
      email_verified: user.email_verified,
      profile: user.profile,
      created_at: user.created_at,
      updated_at: user.updated_at,
      last_login: user.last_login,
      status: user.status,
      mfa_enabled: user.mfa_enabled
    };
  });

  return {
    users,
    lastEvaluatedKey: result.LastEvaluatedKey,
    total: result.Count || 0
  };
}

/**
 * Get user details for admin view (includes more fields than regular user response)
 */
export async function getAdminUserDetails(
  realmId: string,
  userId: string
): Promise<{
  user: UserResponse;
  security: {
    mfa_enabled: boolean;
    webauthn_enabled: boolean;
    webauthn_credential_count: number;
    failed_login_attempts: number;
    locked_until?: string;
    password_changed_at?: string;
  };
} | null> {
  const user = await findUserById(realmId, userId);
  
  if (!user) {
    return null;
  }

  return {
    user: {
      id: user.id,
      realm_id: user.realm_id,
      email: user.email,
      email_verified: user.email_verified,
      profile: user.profile,
      created_at: user.created_at,
      updated_at: user.updated_at,
      last_login: user.last_login,
      status: user.status,
      mfa_enabled: user.mfa_enabled
    },
    security: {
      mfa_enabled: user.mfa_enabled || false,
      webauthn_enabled: (user.webauthn_credentials?.length || 0) > 0,
      webauthn_credential_count: user.webauthn_credentials?.length || 0,
      failed_login_attempts: user.failed_login_attempts || 0,
      locked_until: user.locked_until,
      password_changed_at: user.password_changed_at
    }
  };
}

/**
 * Suspend a user account
 * Used by admin for policy violations or security concerns
 */
export async function suspendUser(
  realmId: string,
  userId: string,
  reason?: string
): Promise<boolean> {
  try {
    const command = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: createUserPK(realmId, userId),
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET #status = :status, suspended_at = :now, suspension_reason = :reason, updated_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':status': 'suspended',
        ':now': new Date().toISOString(),
        ':reason': reason || 'Admin action'
      },
      ConditionExpression: 'attribute_exists(pk)'
    });

    await dynamoDb.send(command);
    return true;
  } catch {
    return false;
  }
}

/**
 * Activate/unsuspend a user account
 */
export async function activateUser(
  realmId: string,
  userId: string
): Promise<boolean> {
  try {
    const command = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: createUserPK(realmId, userId),
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET #status = :status, updated_at = :now REMOVE suspended_at, suspension_reason',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':status': 'active',
        ':now': new Date().toISOString()
      },
      ConditionExpression: 'attribute_exists(pk)'
    });

    await dynamoDb.send(command);
    return true;
  } catch {
    return false;
  }
}

/**
 * Unlock a locked user account (clear failed login attempts)
 */
export async function unlockUser(
  realmId: string,
  userId: string
): Promise<boolean> {
  try {
    const command = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: createUserPK(realmId, userId),
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET failed_login_attempts = :zero, updated_at = :now REMOVE locked_until',
      ExpressionAttributeValues: {
        ':zero': 0,
        ':now': new Date().toISOString()
      },
      ConditionExpression: 'attribute_exists(pk)'
    });

    await dynamoDb.send(command);
    return true;
  } catch {
    return false;
  }
}

/**
 * Admin reset user's MFA (for recovery scenarios)
 * SECURITY: Requires admin MFA verification before calling
 */
export async function adminResetUserMFA(
  realmId: string,
  userId: string
): Promise<boolean> {
  try {
    const command = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: createUserPK(realmId, userId),
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET mfa_enabled = :false, updated_at = :now REMOVE mfa_secret, backup_codes',
      ExpressionAttributeValues: {
        ':false': false,
        ':now': new Date().toISOString()
      },
      ConditionExpression: 'attribute_exists(pk)'
    });

    await dynamoDb.send(command);
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate password reset token for admin-initiated reset
 */
export async function setPasswordResetToken(
  realmId: string,
  userId: string,
  tokenHash: string,
  expiresAt: string
): Promise<boolean> {
  try {
    const command = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: createUserPK(realmId, userId),
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET password_reset_token_hash = :hash, password_reset_expires_at = :expires, updated_at = :now',
      ExpressionAttributeValues: {
        ':hash': tokenHash,
        ':expires': expiresAt,
        ':now': new Date().toISOString()
      },
      ConditionExpression: 'attribute_exists(pk)'
    });

    await dynamoDb.send(command);
    return true;
  } catch {
    return false;
  }
}

/**
 * Update user's password breach status
 * Used by background breach check job (Task 17.4)
 * 
 * @param realmId - Realm ID
 * @param userId - User ID
 * @param status - Breach status to update
 * @returns Promise<boolean> - True if update succeeded
 * 
 * _Requirements: 8.7, 8.8_
 */
export async function updateUserBreachStatus(
  realmId: string,
  userId: string,
  status: {
    password_breach_checked_at?: string;
    password_compromised?: boolean;
    password_breach_count?: number;
  }
): Promise<boolean> {
  try {
    const updateExpressions: string[] = ['updated_at = :now'];
    const expressionAttributeValues: Record<string, unknown> = {
      ':now': new Date().toISOString()
    };

    if (status.password_breach_checked_at !== undefined) {
      updateExpressions.push('password_breach_checked_at = :checkedAt');
      expressionAttributeValues[':checkedAt'] = status.password_breach_checked_at;
    }

    if (status.password_compromised !== undefined) {
      updateExpressions.push('password_compromised = :compromised');
      expressionAttributeValues[':compromised'] = status.password_compromised;
    }

    if (status.password_breach_count !== undefined) {
      updateExpressions.push('password_breach_count = :breachCount');
      expressionAttributeValues[':breachCount'] = status.password_breach_count;
    }

    const command = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: createUserPK(realmId, userId),
        sk: `USER#${userId}`
      },
      UpdateExpression: `SET ${updateExpressions.join(', ')}`,
      ExpressionAttributeValues: expressionAttributeValues,
      ConditionExpression: 'attribute_exists(pk)'
    });

    await dynamoDb.send(command);
    return true;
  } catch (error) {
    console.error('Failed to update user breach status:', error);
    return false;
  }
}

/**
 * Store SHA-1 hash of password for breach checking
 * Called during registration and password change
 * 
 * SECURITY NOTE: This SHA-1 hash is ONLY used for HIBP breach checking.
 * The actual password is stored with Argon2id.
 * 
 * @param realmId - Realm ID
 * @param userId - User ID
 * @param sha1Hash - SHA-1 hash of the password (uppercase hex)
 * @returns Promise<boolean> - True if update succeeded
 */
export async function storePasswordSha1Hash(
  realmId: string,
  userId: string,
  sha1Hash: string
): Promise<boolean> {
  try {
    const command = new UpdateCommand({
      TableName: TableNames.USERS,
      Key: {
        pk: createUserPK(realmId, userId),
        sk: `USER#${userId}`
      },
      UpdateExpression: 'SET password_sha1_hash = :hash, updated_at = :now',
      ExpressionAttributeValues: {
        ':hash': sha1Hash.toUpperCase(),
        ':now': new Date().toISOString()
      },
      ConditionExpression: 'attribute_exists(pk)'
    });

    await dynamoDb.send(command);
    return true;
  } catch (error) {
    console.error('Failed to store password SHA-1 hash:', error);
    return false;
  }
}
