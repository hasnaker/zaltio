/**
 * Account Linking Service
 * Validates: Requirements 4.4 (Account Linking)
 * 
 * Allows users to link multiple social providers to their account
 * Security: Password verification required for linking
 * 
 * @security Account takeover protection via email verification
 */

import { User } from '../models/user.model';
import { findUserByEmail, findUserById } from '../repositories/user.repository';
import { verifyPassword } from '../utils/password';

/**
 * Linked Provider Information
 */
export interface LinkedProvider {
  provider: 'google' | 'apple';
  providerId: string;
  email: string;
  linkedAt: string;
  lastUsedAt?: string;
}

/**
 * Account Linking Result
 */
export interface LinkingResult {
  success: boolean;
  action: 'linked' | 'already_linked' | 'email_mismatch' | 'password_required' | 'error';
  message: string;
  requiresPassword?: boolean;
  existingUserId?: string;
}

/**
 * Check if an email is already associated with an account
 */
export async function checkEmailExists(
  realmId: string,
  email: string
): Promise<{ exists: boolean; userId?: string; hasPassword?: boolean }> {
  const user = await findUserByEmail(realmId, email);
  
  if (!user) {
    return { exists: false };
  }

  return {
    exists: true,
    userId: user.id,
    hasPassword: !!user.password_hash && user.password_hash.length > 0
  };
}

/**
 * Check if a provider is already linked to a user
 */
export function isProviderLinked(
  user: User,
  provider: 'google' | 'apple'
): boolean {
  const metadata = user.profile?.metadata as Record<string, unknown> | undefined;
  if (!metadata) return false;

  const linkedProviders = metadata.linked_providers as LinkedProvider[] | undefined;
  if (!linkedProviders) {
    // Check legacy single provider
    return metadata.oauth_provider === provider;
  }

  return linkedProviders.some(p => p.provider === provider);
}

/**
 * Get all linked providers for a user
 */
export function getLinkedProviders(user: User): LinkedProvider[] {
  const metadata = user.profile?.metadata as Record<string, unknown> | undefined;
  if (!metadata) return [];

  const linkedProviders = metadata.linked_providers as LinkedProvider[] | undefined;
  if (linkedProviders) {
    return linkedProviders;
  }

  // Check legacy single provider
  if (metadata.oauth_provider && metadata.oauth_id) {
    return [{
      provider: metadata.oauth_provider as 'google' | 'apple',
      providerId: metadata.oauth_id as string,
      email: user.email,
      linkedAt: user.created_at
    }];
  }

  return [];
}

/**
 * Determine linking action based on OAuth callback
 * Called when a user authenticates via OAuth
 */
export async function determineLinkingAction(
  realmId: string,
  oauthEmail: string,
  oauthProvider: 'google' | 'apple',
  oauthProviderId: string,
  currentUserId?: string
): Promise<LinkingResult> {
  // Case 1: User is already logged in and wants to link a new provider
  if (currentUserId) {
    const currentUser = await findUserById(realmId, currentUserId);
    if (!currentUser) {
      return {
        success: false,
        action: 'error',
        message: 'Current user not found'
      };
    }

    // Check if provider is already linked
    if (isProviderLinked(currentUser, oauthProvider)) {
      return {
        success: false,
        action: 'already_linked',
        message: `${oauthProvider} is already linked to your account`
      };
    }

    // Provider not linked, can proceed
    return {
      success: true,
      action: 'linked',
      message: `${oauthProvider} can be linked to your account`
    };
  }

  // Case 2: User is not logged in, check if email exists
  const emailCheck = await checkEmailExists(realmId, oauthEmail);
  
  if (!emailCheck.exists) {
    // New user, will create account
    return {
      success: true,
      action: 'linked',
      message: 'New account will be created'
    };
  }

  // Email exists, check if it's the same provider
  const existingUser = await findUserByEmail(realmId, oauthEmail);
  if (!existingUser) {
    return {
      success: false,
      action: 'error',
      message: 'User lookup failed'
    };
  }

  // Check if this exact provider is already linked
  if (isProviderLinked(existingUser, oauthProvider)) {
    // Same provider, same email - just login
    return {
      success: true,
      action: 'linked',
      message: 'Login with existing account'
    };
  }

  // Different provider, same email - requires password to link
  if (emailCheck.hasPassword) {
    return {
      success: false,
      action: 'password_required',
      message: 'Password verification required to link this provider',
      requiresPassword: true,
      existingUserId: existingUser.id
    };
  }

  // No password (OAuth-only account), can auto-link
  return {
    success: true,
    action: 'linked',
    message: 'Provider will be linked to existing account',
    existingUserId: existingUser.id
  };
}

/**
 * Verify password for account linking
 */
export async function verifyLinkingPassword(
  realmId: string,
  userId: string,
  password: string
): Promise<{ valid: boolean; error?: string }> {
  const user = await findUserById(realmId, userId);
  
  if (!user) {
    return { valid: false, error: 'User not found' };
  }

  if (!user.password_hash) {
    return { valid: false, error: 'Account has no password' };
  }

  const isValid = await verifyPassword(password, user.password_hash);
  
  if (!isValid) {
    return { valid: false, error: 'Invalid password' };
  }

  return { valid: true };
}

/**
 * Create linked provider data
 */
export function createLinkedProviderData(
  provider: 'google' | 'apple',
  providerId: string,
  email: string
): LinkedProvider {
  return {
    provider,
    providerId,
    email,
    linkedAt: new Date().toISOString()
  };
}

/**
 * Add provider to user's linked providers list
 * Returns updated metadata
 */
export function addLinkedProvider(
  currentMetadata: Record<string, unknown> | undefined,
  newProvider: LinkedProvider
): Record<string, unknown> {
  const metadata = currentMetadata || {};
  const linkedProviders = (metadata.linked_providers as LinkedProvider[]) || [];

  // Migrate legacy single provider if exists
  if (metadata.oauth_provider && metadata.oauth_id && linkedProviders.length === 0) {
    linkedProviders.push({
      provider: metadata.oauth_provider as 'google' | 'apple',
      providerId: metadata.oauth_id as string,
      email: metadata.oauth_email as string || '',
      linkedAt: new Date().toISOString()
    });
  }

  // Add new provider
  linkedProviders.push(newProvider);

  return {
    ...metadata,
    linked_providers: linkedProviders,
    // Keep legacy fields for backward compatibility
    oauth_provider: undefined,
    oauth_id: undefined
  };
}

/**
 * Remove provider from user's linked providers list
 * Returns updated metadata
 */
export function removeLinkedProvider(
  currentMetadata: Record<string, unknown> | undefined,
  provider: 'google' | 'apple'
): { metadata: Record<string, unknown>; removed: boolean } {
  const metadata = currentMetadata || {};
  const linkedProviders = (metadata.linked_providers as LinkedProvider[]) || [];

  const initialLength = linkedProviders.length;
  const filteredProviders = linkedProviders.filter(p => p.provider !== provider);

  return {
    metadata: {
      ...metadata,
      linked_providers: filteredProviders
    },
    removed: filteredProviders.length < initialLength
  };
}

/**
 * Check if user can unlink a provider
 * User must have either a password or another linked provider
 */
export function canUnlinkProvider(
  user: User,
  providerToUnlink: 'google' | 'apple'
): { canUnlink: boolean; reason?: string } {
  const hasPassword = !!user.password_hash && user.password_hash.length > 0;
  const linkedProviders = getLinkedProviders(user);
  const otherProviders = linkedProviders.filter(p => p.provider !== providerToUnlink);

  if (!hasPassword && otherProviders.length === 0) {
    return {
      canUnlink: false,
      reason: 'Cannot unlink the only authentication method. Set a password first.'
    };
  }

  return { canUnlink: true };
}
