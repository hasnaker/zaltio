/**
 * Account Linking Lambda Handlers
 * Validates: Requirements 4.4 (Account Linking)
 * 
 * Endpoints:
 * - GET /v1/auth/account/providers - List linked providers
 * - POST /v1/auth/account/link/verify - Verify password for linking
 * - DELETE /v1/auth/account/providers/:provider - Unlink a provider
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { findUserById, updateUserMetadata } from '../repositories/user.repository';
import { verifyAccessToken } from '../utils/jwt';
import { logSecurityEvent } from '../services/security-logger.service';
import { checkRateLimit } from '../services/ratelimit.service';
import {
  getLinkedProviders,
  canUnlinkProvider,
  verifyLinkingPassword,
  removeLinkedProvider
} from '../services/account-linking.service';

// Rate limit configuration
const LINKING_RATE_LIMIT = {
  maxRequests: 10,
  windowSeconds: 60
};

function createResponse(
  statusCode: number,
  body: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
    body: JSON.stringify(body)
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 'unknown';
}

function getAuthToken(event: APIGatewayProxyEvent): string | null {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.slice(7);
}

/**
 * GET /v1/auth/account/providers
 * List all linked providers for the authenticated user
 */
export async function listProvidersHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

  try {
    // Verify authentication
    const token = getAuthToken(event);
    if (!token) {
      return createResponse(401, {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
          request_id: requestId
        }
      });
    }

    let tokenPayload: { sub: string; realm_id: string };
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, {
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token',
          request_id: requestId
        }
      });
    }

    const { sub: userId, realm_id: realmId } = tokenPayload;

    // Get user
    const user = await findUserById(realmId, userId);
    if (!user) {
      return createResponse(404, {
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
          request_id: requestId
        }
      });
    }

    // Get linked providers
    const providers = getLinkedProviders(user);
    const hasPassword = !!user.password_hash && user.password_hash.length > 0;

    return createResponse(200, {
      providers: providers.map(p => ({
        provider: p.provider,
        email: p.email,
        linked_at: p.linkedAt,
        last_used_at: p.lastUsedAt
      })),
      has_password: hasPassword,
      can_add_password: !hasPassword
    });

  } catch (error) {
    console.error('List providers error:', error);
    return createResponse(500, {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
        request_id: requestId
      }
    });
  }
}

/**
 * POST /v1/auth/account/link/verify
 * Verify password before linking a provider to existing account
 */
export async function verifyLinkingHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Rate limiting
    const rateLimitResult = await checkRateLimit(
      'global',
      `link-verify:${clientIP}`,
      LINKING_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      return createResponse(429, {
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many requests',
          request_id: requestId
        }
      });
    }

    // Parse body
    if (!event.body) {
      return createResponse(400, {
        error: {
          code: 'INVALID_REQUEST',
          message: 'Request body is required',
          request_id: requestId
        }
      });
    }

    const body = JSON.parse(event.body);
    const { realm_id: realmId, user_id: userId, password } = body;

    if (!realmId || !userId || !password) {
      return createResponse(400, {
        error: {
          code: 'INVALID_REQUEST',
          message: 'realm_id, user_id, and password are required',
          request_id: requestId
        }
      });
    }

    // Verify password
    const verifyResult = await verifyLinkingPassword(realmId, userId, password);

    if (!verifyResult.valid) {
      await logSecurityEvent({
        event_type: 'account_linking_password_failed',
        ip_address: clientIP,
        realm_id: realmId,
        user_id: userId,
        details: { error: verifyResult.error }
      });

      return createResponse(401, {
        error: {
          code: 'INVALID_PASSWORD',
          message: 'Invalid password',
          request_id: requestId
        }
      });
    }

    await logSecurityEvent({
      event_type: 'account_linking_password_verified',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId
    });

    // Return success with a linking confirmation token
    return createResponse(200, {
      verified: true,
      message: 'Password verified. You can now complete the linking process.',
      linking_confirmed: true
    });

  } catch (error) {
    console.error('Verify linking error:', error);
    return createResponse(500, {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
        request_id: requestId
      }
    });
  }
}

/**
 * DELETE /v1/auth/account/providers/:provider
 * Unlink a provider from the authenticated user's account
 */
export async function unlinkProviderHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Rate limiting
    const rateLimitResult = await checkRateLimit(
      'global',
      `unlink:${clientIP}`,
      LINKING_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      return createResponse(429, {
        error: {
          code: 'RATE_LIMITED',
          message: 'Too many requests',
          request_id: requestId
        }
      });
    }

    // Verify authentication
    const token = getAuthToken(event);
    if (!token) {
      return createResponse(401, {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
          request_id: requestId
        }
      });
    }

    let tokenPayload: { sub: string; realm_id: string };
    try {
      tokenPayload = await verifyAccessToken(token);
    } catch {
      return createResponse(401, {
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token',
          request_id: requestId
        }
      });
    }

    const { sub: userId, realm_id: realmId } = tokenPayload;

    // Get provider from path
    const provider = event.pathParameters?.provider as 'google' | 'apple';
    if (!provider || !['google', 'apple'].includes(provider)) {
      return createResponse(400, {
        error: {
          code: 'INVALID_PROVIDER',
          message: 'Invalid provider. Must be "google" or "apple"',
          request_id: requestId
        }
      });
    }

    // Get user
    const user = await findUserById(realmId, userId);
    if (!user) {
      return createResponse(404, {
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
          request_id: requestId
        }
      });
    }

    // Check if can unlink
    const canUnlink = canUnlinkProvider(user, provider);
    if (!canUnlink.canUnlink) {
      return createResponse(400, {
        error: {
          code: 'CANNOT_UNLINK',
          message: canUnlink.reason || 'Cannot unlink this provider',
          request_id: requestId
        }
      });
    }

    // Parse password from body (required for security)
    let password: string | undefined;
    if (event.body) {
      const body = JSON.parse(event.body);
      password = body.password;
    }

    // If user has password, require it for unlinking
    if (user.password_hash && user.password_hash.length > 0) {
      if (!password) {
        return createResponse(400, {
          error: {
            code: 'PASSWORD_REQUIRED',
            message: 'Password is required to unlink a provider',
            request_id: requestId
          }
        });
      }

      const verifyResult = await verifyLinkingPassword(realmId, userId, password);
      if (!verifyResult.valid) {
        await logSecurityEvent({
          event_type: 'provider_unlink_password_failed',
          ip_address: clientIP,
          realm_id: realmId,
          user_id: userId,
          details: { provider }
        });

        return createResponse(401, {
          error: {
            code: 'INVALID_PASSWORD',
            message: 'Invalid password',
            request_id: requestId
          }
        });
      }
    }

    // Remove provider
    const { metadata, removed } = removeLinkedProvider(
      user.profile?.metadata as Record<string, unknown>,
      provider
    );

    if (!removed) {
      return createResponse(400, {
        error: {
          code: 'PROVIDER_NOT_LINKED',
          message: `${provider} is not linked to your account`,
          request_id: requestId
        }
      });
    }

    // Update user metadata
    await updateUserMetadata(realmId, userId, metadata);

    await logSecurityEvent({
      event_type: 'provider_unlinked',
      ip_address: clientIP,
      realm_id: realmId,
      user_id: userId,
      details: { provider }
    });

    return createResponse(200, {
      message: `${provider} has been unlinked from your account`,
      provider
    });

  } catch (error) {
    console.error('Unlink provider error:', error);
    return createResponse(500, {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
        request_id: requestId
      }
    });
  }
}
