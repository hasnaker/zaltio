/**
 * WebAuthn Lambda Handlers
 * Validates: Requirements 2.2 (MFA - WebAuthn)
 * 
 * CRITICAL: WebAuthn is the primary defense against Evilginx2 phishing proxies
 * 
 * Endpoints:
 * - POST /v1/auth/webauthn/register/options - Get registration options
 * - POST /v1/auth/webauthn/register/verify - Verify and save credential
 * - POST /v1/auth/webauthn/authenticate/options - Get authentication options
 * - POST /v1/auth/webauthn/authenticate/verify - Verify authentication
 * - GET /v1/auth/webauthn/credentials - List user's credentials
 * - DELETE /v1/auth/webauthn/credentials/{id} - Delete a credential
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../utils/jwt';

/**
 * Main Lambda handler - routes requests to appropriate handlers
 */
export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const path = event.path;
  const method = event.httpMethod;

  // Route to appropriate handler
  if (method === 'POST' && path === '/v1/auth/webauthn/register/options') {
    return webauthnRegisterOptionsHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/webauthn/register/verify') {
    return webauthnRegisterVerifyHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/webauthn/authenticate/options') {
    return webauthnAuthenticateOptionsHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/webauthn/authenticate/verify') {
    return webauthnAuthenticateVerifyHandler(event);
  }
  if (method === 'GET' && path === '/v1/auth/webauthn/credentials') {
    return webauthnListCredentialsHandler(event);
  }
  if (method === 'DELETE' && path.startsWith('/v1/auth/webauthn/credentials/')) {
    return webauthnDeleteCredentialHandler(event);
  }

  // 404 for unknown paths
  return {
    statusCode: 404,
    headers: {
      'Content-Type': 'text/plain',
      'Access-Control-Allow-Origin': '*'
    },
    body: '404 page not found'
  };
};
import { findUserById, updateUserWebAuthn } from '../repositories/user.repository';
import { verifyPassword } from '../utils/password';
import { logSecurityEvent } from '../services/security-logger.service';
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  WebAuthnCredential,
  WEBAUTHN_CONFIG
} from '../services/webauthn.service';

// Configuration
const MAX_CREDENTIALS_PER_USER = 10;
const CHALLENGE_EXPIRY_SECONDS = 300; // 5 minutes

// In-memory challenge store (in production, use DynamoDB with TTL)
const challengeStore = new Map<string, {
  challenge: string;
  userId: string;
  realmId: string;
  expiresAt: number;
  type: 'registration' | 'authentication';
}>();

/**
 * Convert stored credential data to WebAuthnCredential
 * DynamoDB stores Buffer as base64 string
 */
function deserializeCredentials(credentials: any[]): WebAuthnCredential[] {
  return credentials.map(cred => ({
    ...cred,
    credentialId: typeof cred.credentialId === 'string' 
      ? Buffer.from(cred.credentialId, 'base64')
      : cred.credentialId,
    publicKey: typeof cred.publicKey === 'string'
      ? Buffer.from(cred.publicKey, 'base64')
      : cred.publicKey
  }));
}

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

function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') return null;
  return parts[1];
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 'unknown';
}

/**
 * Store challenge for later verification
 */
function storeChallenge(
  challenge: string,
  userId: string,
  realmId: string,
  type: 'registration' | 'authentication'
): void {
  const key = `${userId}:${type}`;
  challengeStore.set(key, {
    challenge,
    userId,
    realmId,
    expiresAt: Date.now() + (CHALLENGE_EXPIRY_SECONDS * 1000),
    type
  });
}

/**
 * Get and validate stored challenge
 */
function getStoredChallenge(
  userId: string,
  type: 'registration' | 'authentication'
): string | null {
  const key = `${userId}:${type}`;
  const stored = challengeStore.get(key);
  
  if (!stored) return null;
  if (Date.now() > stored.expiresAt) {
    challengeStore.delete(key);
    return null;
  }
  
  return stored.challenge;
}

/**
 * Delete stored challenge after use
 */
function deleteStoredChallenge(userId: string, type: 'registration' | 'authentication'): void {
  const key = `${userId}:${type}`;
  challengeStore.delete(key);
}

/**
 * POST /v1/auth/webauthn/register/options
 * Get registration options for creating a new credential
 */
export async function webauthnRegisterOptionsHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    const token = extractBearerToken(authHeader);
    
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const payload = await verifyAccessToken(token);
    
    // Get user
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    // Check credential limit
    const existingCredentials = deserializeCredentials(user.webauthn_credentials || []);
    if (existingCredentials.length >= MAX_CREDENTIALS_PER_USER) {
      return createResponse(400, {
        error: { 
          code: 'MAX_CREDENTIALS_REACHED', 
          message: `Maximum ${MAX_CREDENTIALS_PER_USER} credentials allowed`,
          request_id: requestId 
        }
      });
    }

    // Generate registration options
    const options = generateRegistrationOptions(
      user.id,
      user.email,
      user.profile?.first_name 
        ? `${user.profile.first_name} ${user.profile.last_name || ''}`.trim()
        : user.email,
      existingCredentials
    );

    // Store challenge for verification
    storeChallenge(options.challenge, user.id, user.realm_id, 'registration');

    await logSecurityEvent({
      event_type: 'webauthn_register_options',
      ip_address: clientIP,
      realm_id: user.realm_id,
      user_id: user.id,
      details: { existing_credentials: existingCredentials.length }
    });

    return createResponse(200, {
      options,
      expires_in: CHALLENGE_EXPIRY_SECONDS
    });

  } catch (error) {
    console.error('WebAuthn register options error:', error);
    
    if ((error as Error).name === 'TokenExpiredError') {
      return createResponse(401, {
        error: { code: 'TOKEN_EXPIRED', message: 'Access token expired', request_id: requestId }
      });
    }

    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * POST /v1/auth/webauthn/register/verify
 * Verify registration response and save credential
 */
export async function webauthnRegisterVerifyHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    const token = extractBearerToken(authHeader);
    
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const payload = await verifyAccessToken(token);

    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { response, deviceName } = JSON.parse(event.body);

    if (!response) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'response is required', request_id: requestId }
      });
    }

    // Get stored challenge
    const expectedChallenge = getStoredChallenge(payload.sub, 'registration');
    if (!expectedChallenge) {
      return createResponse(400, {
        error: { code: 'CHALLENGE_EXPIRED', message: 'Registration challenge expired', request_id: requestId }
      });
    }

    // Verify registration response
    const verifyResult = await verifyRegistrationResponse(
      response,
      expectedChallenge,
      WEBAUTHN_CONFIG.origin,
      WEBAUTHN_CONFIG.rpId
    );

    if (!verifyResult.verified || !verifyResult.credential) {
      await logSecurityEvent({
        event_type: 'webauthn_register_failure',
        ip_address: clientIP,
        realm_id: payload.realm_id,
        user_id: payload.sub,
        details: { error: verifyResult.error }
      });

      return createResponse(400, {
        error: { 
          code: 'VERIFICATION_FAILED', 
          message: verifyResult.error || 'Failed to verify registration',
          request_id: requestId 
        }
      });
    }

    // Delete used challenge
    deleteStoredChallenge(payload.sub, 'registration');

    // Get user and add credential
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    const existingCredentials = deserializeCredentials(user.webauthn_credentials || []);
    
    // Create new credential
    const newCredential: WebAuthnCredential = {
      id: verifyResult.credential.credentialId.toString('base64url'),
      credentialId: verifyResult.credential.credentialId,
      publicKey: verifyResult.credential.publicKey,
      counter: verifyResult.credential.counter,
      transports: verifyResult.credential.transports,
      createdAt: new Date().toISOString(),
      deviceName: deviceName || 'Security Key',
      aaguid: verifyResult.credential.aaguid
    };

    // Save credential
    await updateUserWebAuthn(
      payload.realm_id,
      payload.sub,
      [...existingCredentials, newCredential]
    );

    await logSecurityEvent({
      event_type: 'webauthn_register_success',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { 
        credential_id: newCredential.id.substring(0, 16) + '...',
        device_name: newCredential.deviceName
      }
    });

    return createResponse(200, {
      message: 'WebAuthn credential registered successfully',
      credential: {
        id: newCredential.id,
        deviceName: newCredential.deviceName,
        createdAt: newCredential.createdAt
      }
    });

  } catch (error) {
    console.error('WebAuthn register verify error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * POST /v1/auth/webauthn/authenticate/options
 * Get authentication options for existing credentials
 */
export async function webauthnAuthenticateOptionsHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

  try {
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { realm_id, email } = JSON.parse(event.body);

    if (!realm_id || !email) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'realm_id and email are required', request_id: requestId }
      });
    }

    // Find user (don't reveal if user exists - same response)
    const { findUserByEmail } = await import('../repositories/user.repository');
    const user = await findUserByEmail(realm_id, email);

    // Generate options even if user doesn't exist (prevent enumeration)
    const credentials = deserializeCredentials(user?.webauthn_credentials || []);
    
    if (credentials.length === 0) {
      // Return empty options - client will show appropriate message
      return createResponse(200, {
        options: null,
        message: 'No WebAuthn credentials registered'
      });
    }

    const options = generateAuthenticationOptions(credentials);

    // Store challenge
    if (user) {
      storeChallenge(options.challenge, user.id, user.realm_id, 'authentication');
    }

    return createResponse(200, {
      options,
      expires_in: CHALLENGE_EXPIRY_SECONDS
    });

  } catch (error) {
    console.error('WebAuthn authenticate options error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * POST /v1/auth/webauthn/authenticate/verify
 * Verify authentication and return tokens
 */
export async function webauthnAuthenticateVerifyHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { realm_id, email, response } = JSON.parse(event.body);

    if (!realm_id || !email || !response) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'realm_id, email, and response are required', request_id: requestId }
      });
    }

    // Find user
    const { findUserByEmail } = await import('../repositories/user.repository');
    const user = await findUserByEmail(realm_id, email);

    if (!user) {
      return createResponse(401, {
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid credentials', request_id: requestId }
      });
    }

    // Get stored challenge
    const expectedChallenge = getStoredChallenge(user.id, 'authentication');
    if (!expectedChallenge) {
      return createResponse(400, {
        error: { code: 'CHALLENGE_EXPIRED', message: 'Authentication challenge expired', request_id: requestId }
      });
    }

    // Find matching credential
    const credentials = deserializeCredentials(user.webauthn_credentials || []);
    const credentialId = response.id;
    const credential = credentials.find(c => c.id === credentialId);

    if (!credential) {
      return createResponse(401, {
        error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Credential not found', request_id: requestId }
      });
    }

    // Verify authentication
    const verifyResult = await verifyAuthenticationResponse(
      response,
      expectedChallenge,
      WEBAUTHN_CONFIG.origin,
      WEBAUTHN_CONFIG.rpId,
      credential
    );

    if (!verifyResult.verified) {
      await logSecurityEvent({
        event_type: 'webauthn_auth_failure',
        ip_address: clientIP,
        realm_id: user.realm_id,
        user_id: user.id,
        details: { error: verifyResult.error }
      });

      return createResponse(401, {
        error: { 
          code: 'VERIFICATION_FAILED', 
          message: verifyResult.error || 'Authentication failed',
          request_id: requestId 
        }
      });
    }

    // Delete used challenge
    deleteStoredChallenge(user.id, 'authentication');

    // Update credential counter
    if (verifyResult.newCounter !== undefined) {
      const updatedCredentials = credentials.map(c => 
        c.id === credentialId 
          ? { ...c, counter: verifyResult.newCounter!, lastUsedAt: new Date().toISOString() }
          : c
      );
      await updateUserWebAuthn(user.realm_id, user.id, updatedCredentials);
    }

    // Generate tokens
    const { generateTokenPair } = await import('../utils/jwt');
    const { getRealmSettings } = await import('../repositories/realm.repository');
    const realmSettings = await getRealmSettings(user.realm_id);

    const tokenPair = await generateTokenPair(
      user.id,
      user.realm_id,
      user.email,
      { accessTokenExpiry: realmSettings.session_timeout }
    );

    // Create session
    const { createSession } = await import('../repositories/session.repository');
    await createSession(
      {
        user_id: user.id,
        realm_id: user.realm_id,
        ip_address: clientIP,
        user_agent: event.headers?.['User-Agent'] || 'unknown'
      },
      tokenPair.access_token,
      tokenPair.refresh_token,
      7 * 24 * 60 * 60
    );

    await logSecurityEvent({
      event_type: 'webauthn_auth_success',
      ip_address: clientIP,
      realm_id: user.realm_id,
      user_id: user.id,
      details: { credential_id: credentialId.substring(0, 16) + '...' }
    });

    return createResponse(200, {
      message: 'Authentication successful',
      user: {
        id: user.id,
        email: user.email,
        email_verified: user.email_verified,
        profile: user.profile,
        status: user.status
      },
      tokens: tokenPair
    });

  } catch (error) {
    console.error('WebAuthn authenticate verify error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * GET /v1/auth/webauthn/credentials
 * List user's WebAuthn credentials
 */
export async function webauthnListCredentialsHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    const token = extractBearerToken(authHeader);
    
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const payload = await verifyAccessToken(token);
    
    // Get user
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    const credentials = deserializeCredentials(user.webauthn_credentials || []);

    // Return safe credential info (no public keys)
    const safeCredentials = credentials.map(c => ({
      id: c.id,
      deviceName: c.deviceName,
      createdAt: c.createdAt,
      lastUsedAt: c.lastUsedAt,
      transports: c.transports
    }));

    return createResponse(200, {
      credentials: safeCredentials,
      count: safeCredentials.length,
      max_allowed: MAX_CREDENTIALS_PER_USER
    });

  } catch (error) {
    console.error('WebAuthn list credentials error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * DELETE /v1/auth/webauthn/credentials/:id
 * Delete a WebAuthn credential (requires password)
 */
export async function webauthnDeleteCredentialHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    const token = extractBearerToken(authHeader);
    
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const payload = await verifyAccessToken(token);

    // Get credential ID from path
    const credentialId = event.pathParameters?.id;
    if (!credentialId) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Credential ID required', request_id: requestId }
      });
    }

    // Get password from body
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Password required to delete credential', request_id: requestId }
      });
    }

    const { password } = JSON.parse(event.body);
    if (!password) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Password is required', request_id: requestId }
      });
    }

    // Get user
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    // Verify password
    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid) {
      return createResponse(401, {
        error: { code: 'INVALID_PASSWORD', message: 'Invalid password', request_id: requestId }
      });
    }

    // Find and remove credential
    const credentials = deserializeCredentials(user.webauthn_credentials || []);
    const credentialIndex = credentials.findIndex(c => c.id === credentialId);

    if (credentialIndex === -1) {
      return createResponse(404, {
        error: { code: 'CREDENTIAL_NOT_FOUND', message: 'Credential not found', request_id: requestId }
      });
    }

    const deletedCredential = credentials[credentialIndex];
    const updatedCredentials = credentials.filter(c => c.id !== credentialId);

    await updateUserWebAuthn(payload.realm_id, payload.sub, updatedCredentials);

    await logSecurityEvent({
      event_type: 'webauthn_credential_deleted',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { 
        credential_id: credentialId.substring(0, 16) + '...',
        device_name: deletedCredential.deviceName
      }
    });

    return createResponse(200, {
      message: 'Credential deleted successfully'
    });

  } catch (error) {
    console.error('WebAuthn delete credential error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}
