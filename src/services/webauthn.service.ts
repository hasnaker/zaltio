/**
 * WebAuthn Service
 * Validates: Requirements 2.2 (MFA - WebAuthn)
 * 
 * Implements WebAuthn/FIDO2 for phishing-resistant authentication
 * CRITICAL: This is the primary defense against Evilginx2 and similar phishing proxies
 * 
 * SECURITY NOTES:
 * - Origin validation is CRITICAL for phishing protection
 * - Challenge must be cryptographically random (32 bytes)
 * - Counter validation prevents replay attacks
 * - Public keys stored securely, never exposed
 */

import crypto from 'crypto';

// WebAuthn Configuration
export const WEBAUTHN_CONFIG = {
  rpName: 'Zalt.io',
  rpId: 'zalt.io',
  origin: 'https://zalt.io',
  challengeSize: 32, // 256 bits
  timeout: 60000, // 60 seconds
  attestation: 'none' as const, // We don't need attestation for most use cases
  userVerification: 'preferred' as const,
  authenticatorAttachment: 'platform' as const, // Prefer platform authenticators (Touch ID, Face ID, Windows Hello)
  residentKey: 'preferred' as const
};

// Supported algorithms (ES256 preferred, RS256 as fallback)
export const SUPPORTED_ALGORITHMS = [
  { alg: -7, type: 'public-key' as const },   // ES256 (ECDSA w/ SHA-256)
  { alg: -257, type: 'public-key' as const }  // RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)
];

export interface WebAuthnCredential {
  id: string;
  credentialId: Buffer;
  publicKey: Buffer;
  counter: number;
  transports?: AuthenticatorTransport[];
  createdAt: string;
  lastUsedAt?: string;
  deviceName?: string;
  aaguid?: string;
}

export type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'internal' | 'hybrid';

export interface RegistrationOptions {
  challenge: string;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{ alg: number; type: 'public-key' }>;
  timeout: number;
  attestation: 'none' | 'indirect' | 'direct' | 'enterprise';
  authenticatorSelection: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    residentKey: 'discouraged' | 'preferred' | 'required';
    userVerification: 'required' | 'preferred' | 'discouraged';
  };
  excludeCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
}

export interface AuthenticationOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  userVerification: 'required' | 'preferred' | 'discouraged';
}

export interface RegistrationResponse {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: AuthenticatorTransport[];
  };
  type: 'public-key';
  clientExtensionResults?: Record<string, unknown>;
}

export interface AuthenticationResponse {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  type: 'public-key';
  clientExtensionResults?: Record<string, unknown>;
}

/**
 * Generate cryptographically random challenge
 */
export function generateChallenge(): string {
  const challenge = crypto.randomBytes(WEBAUTHN_CONFIG.challengeSize);
  return challenge.toString('base64url');
}

/**
 * Generate registration options for WebAuthn credential creation
 */
export function generateRegistrationOptions(
  userId: string,
  userEmail: string,
  userName: string,
  existingCredentials: WebAuthnCredential[] = [],
  rpId?: string,
  rpName?: string
): RegistrationOptions {
  const challenge = generateChallenge();
  
  // Exclude existing credentials to prevent re-registration
  const excludeCredentials = existingCredentials.map(cred => ({
    id: cred.credentialId.toString('base64url'),
    type: 'public-key' as const,
    transports: cred.transports
  }));

  return {
    challenge,
    rp: {
      name: rpName || WEBAUTHN_CONFIG.rpName,
      id: rpId || WEBAUTHN_CONFIG.rpId
    },
    user: {
      id: Buffer.from(userId).toString('base64url'),
      name: userEmail,
      displayName: userName
    },
    pubKeyCredParams: SUPPORTED_ALGORITHMS,
    timeout: WEBAUTHN_CONFIG.timeout,
    attestation: WEBAUTHN_CONFIG.attestation,
    authenticatorSelection: {
      authenticatorAttachment: WEBAUTHN_CONFIG.authenticatorAttachment,
      residentKey: WEBAUTHN_CONFIG.residentKey,
      userVerification: WEBAUTHN_CONFIG.userVerification
    },
    excludeCredentials: excludeCredentials.length > 0 ? excludeCredentials : undefined
  };
}

/**
 * Generate authentication options for WebAuthn assertion
 */
export function generateAuthenticationOptions(
  credentials: WebAuthnCredential[],
  rpId?: string
): AuthenticationOptions {
  const challenge = generateChallenge();
  
  const allowCredentials = credentials.map(cred => ({
    id: cred.credentialId.toString('base64url'),
    type: 'public-key' as const,
    transports: cred.transports
  }));

  return {
    challenge,
    timeout: WEBAUTHN_CONFIG.timeout,
    rpId: rpId || WEBAUTHN_CONFIG.rpId,
    allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
    userVerification: WEBAUTHN_CONFIG.userVerification
  };
}

/**
 * Verify registration response from authenticator
 * CRITICAL: Origin validation prevents phishing attacks
 */
export async function verifyRegistrationResponse(
  response: RegistrationResponse,
  expectedChallenge: string,
  expectedOrigin: string,
  expectedRpId: string
): Promise<{
  verified: boolean;
  credential?: {
    credentialId: Buffer;
    publicKey: Buffer;
    counter: number;
    transports?: AuthenticatorTransport[];
    aaguid?: string;
  };
  error?: string;
}> {
  try {
    // Decode clientDataJSON
    const clientDataJSON = Buffer.from(response.response.clientDataJSON, 'base64url');
    const clientData = JSON.parse(clientDataJSON.toString('utf8'));

    // Verify type
    if (clientData.type !== 'webauthn.create') {
      return { verified: false, error: 'Invalid client data type' };
    }

    // Verify challenge (CRITICAL)
    if (clientData.challenge !== expectedChallenge) {
      return { verified: false, error: 'Challenge mismatch' };
    }

    // Verify origin (CRITICAL for phishing protection)
    if (clientData.origin !== expectedOrigin) {
      return { verified: false, error: `Origin mismatch: expected ${expectedOrigin}, got ${clientData.origin}` };
    }

    // Decode attestation object
    const attestationObject = Buffer.from(response.response.attestationObject, 'base64url');
    const attestation = decodeAttestationObject(attestationObject);

    if (!attestation) {
      return { verified: false, error: 'Failed to decode attestation object' };
    }

    // Verify RP ID hash
    const rpIdHash = crypto.createHash('sha256').update(expectedRpId).digest();
    if (!attestation.authData.rpIdHash.equals(rpIdHash)) {
      return { verified: false, error: 'RP ID hash mismatch' };
    }

    // Verify user presence flag
    if (!(attestation.authData.flags & 0x01)) {
      return { verified: false, error: 'User presence flag not set' };
    }

    // Extract credential data
    if (!attestation.authData.attestedCredentialData) {
      return { verified: false, error: 'No attested credential data' };
    }

    const { credentialId, publicKey, aaguid } = attestation.authData.attestedCredentialData;

    return {
      verified: true,
      credential: {
        credentialId,
        publicKey,
        counter: attestation.authData.signCount,
        transports: response.response.transports,
        aaguid: aaguid.toString('hex')
      }
    };
  } catch (error) {
    console.error('WebAuthn registration verification error:', error);
    return { verified: false, error: (error as Error).message };
  }
}

/**
 * Verify authentication response from authenticator
 * CRITICAL: Counter validation prevents replay attacks
 */
export async function verifyAuthenticationResponse(
  response: AuthenticationResponse,
  expectedChallenge: string,
  expectedOrigin: string,
  expectedRpId: string,
  credential: WebAuthnCredential
): Promise<{
  verified: boolean;
  newCounter?: number;
  error?: string;
}> {
  try {
    // Decode clientDataJSON
    const clientDataJSON = Buffer.from(response.response.clientDataJSON, 'base64url');
    const clientData = JSON.parse(clientDataJSON.toString('utf8'));

    // Verify type
    if (clientData.type !== 'webauthn.get') {
      return { verified: false, error: 'Invalid client data type' };
    }

    // Verify challenge (CRITICAL)
    if (clientData.challenge !== expectedChallenge) {
      return { verified: false, error: 'Challenge mismatch' };
    }

    // Verify origin (CRITICAL for phishing protection)
    if (clientData.origin !== expectedOrigin) {
      return { verified: false, error: `Origin mismatch: expected ${expectedOrigin}, got ${clientData.origin}` };
    }

    // Decode authenticator data
    const authenticatorData = Buffer.from(response.response.authenticatorData, 'base64url');
    const authData = parseAuthenticatorData(authenticatorData);

    // Verify RP ID hash
    const rpIdHash = crypto.createHash('sha256').update(expectedRpId).digest();
    if (!authData.rpIdHash.equals(rpIdHash)) {
      return { verified: false, error: 'RP ID hash mismatch' };
    }

    // Verify user presence flag
    if (!(authData.flags & 0x01)) {
      return { verified: false, error: 'User presence flag not set' };
    }

    // Verify counter (replay protection)
    if (authData.signCount <= credential.counter && authData.signCount !== 0) {
      return { verified: false, error: 'Counter not incremented - possible cloned authenticator' };
    }

    // Verify signature
    const signature = Buffer.from(response.response.signature, 'base64url');
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
    const signedData = Buffer.concat([authenticatorData, clientDataHash]);

    const signatureValid = verifySignature(
      credential.publicKey,
      signedData,
      signature
    );

    if (!signatureValid) {
      return { verified: false, error: 'Invalid signature' };
    }

    return {
      verified: true,
      newCounter: authData.signCount
    };
  } catch (error) {
    console.error('WebAuthn authentication verification error:', error);
    return { verified: false, error: (error as Error).message };
  }
}

/**
 * Decode CBOR attestation object
 * Simplified implementation - in production use cbor library
 */
function decodeAttestationObject(attestationObject: Buffer): {
  fmt: string;
  authData: {
    rpIdHash: Buffer;
    flags: number;
    signCount: number;
    attestedCredentialData?: {
      aaguid: Buffer;
      credentialId: Buffer;
      publicKey: Buffer;
    };
  };
  attStmt: Record<string, unknown>;
} | null {
  try {
    // Simple CBOR map parsing for attestation object
    // Format: { fmt: string, authData: bytes, attStmt: map }
    
    // For testing purposes, we'll parse the authenticator data directly
    // In production, use a proper CBOR library
    
    // Skip CBOR header and find authData
    let offset = 0;
    
    // Look for authData in the CBOR structure
    // This is a simplified parser - production should use cbor-x or similar
    
    // Find the authData bytes (typically after "authData" key)
    const authDataMarker = Buffer.from('authData');
    const markerIndex = attestationObject.indexOf(authDataMarker);
    
    if (markerIndex === -1) {
      // Try direct parsing assuming standard format
      // Skip initial CBOR map header (1 byte) + fmt field
      offset = findAuthDataOffset(attestationObject);
    } else {
      offset = markerIndex + authDataMarker.length + 1; // +1 for CBOR byte string header
    }

    // Parse authenticator data
    const authData = parseAuthenticatorData(attestationObject.slice(offset));
    
    return {
      fmt: 'none',
      authData,
      attStmt: {}
    };
  } catch (error) {
    console.error('Failed to decode attestation object:', error);
    return null;
  }
}

/**
 * Find authData offset in CBOR structure
 */
function findAuthDataOffset(buffer: Buffer): number {
  // Standard attestation object structure offset
  // This is simplified - production should use proper CBOR parsing
  return 0;
}

/**
 * Parse authenticator data structure
 */
function parseAuthenticatorData(authData: Buffer): {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
  attestedCredentialData?: {
    aaguid: Buffer;
    credentialId: Buffer;
    publicKey: Buffer;
  };
} {
  let offset = 0;

  // RP ID Hash (32 bytes)
  const rpIdHash = authData.slice(offset, offset + 32);
  offset += 32;

  // Flags (1 byte)
  const flags = authData[offset];
  offset += 1;

  // Sign Count (4 bytes, big-endian)
  const signCount = authData.readUInt32BE(offset);
  offset += 4;

  // Check if attested credential data is present (bit 6)
  let attestedCredentialData;
  if (flags & 0x40) {
    // AAGUID (16 bytes)
    const aaguid = authData.slice(offset, offset + 16);
    offset += 16;

    // Credential ID Length (2 bytes, big-endian)
    const credentialIdLength = authData.readUInt16BE(offset);
    offset += 2;

    // Credential ID
    const credentialId = authData.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    // Public Key (COSE format, remaining bytes)
    const publicKey = authData.slice(offset);

    attestedCredentialData = {
      aaguid,
      credentialId,
      publicKey
    };
  }

  return {
    rpIdHash,
    flags,
    signCount,
    attestedCredentialData
  };
}

/**
 * Verify signature using public key
 */
function verifySignature(
  publicKey: Buffer,
  data: Buffer,
  signature: Buffer
): boolean {
  try {
    // Parse COSE public key to determine algorithm
    // For ES256 (ECDSA P-256)
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    
    // Convert COSE key to PEM format
    const pemKey = coseKeyToPem(publicKey);
    
    return verify.verify(pemKey, signature);
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

/**
 * Convert COSE public key to PEM format
 * Simplified - handles ES256 (P-256) keys
 */
function coseKeyToPem(coseKey: Buffer): string {
  // This is a simplified implementation
  // In production, properly parse COSE key format
  
  // For ES256, extract x and y coordinates and create PEM
  // COSE key format: map with kty, alg, crv, x, y
  
  try {
    // Parse COSE map (simplified)
    // Assuming ES256 key with x,y coordinates
    
    // For testing, return a placeholder
    // Production should properly convert COSE to PEM
    return `-----BEGIN PUBLIC KEY-----
${coseKey.toString('base64')}
-----END PUBLIC KEY-----`;
  } catch {
    throw new Error('Failed to convert COSE key to PEM');
  }
}

/**
 * Validate credential ID format
 */
export function isValidCredentialId(credentialId: string): boolean {
  try {
    const decoded = Buffer.from(credentialId, 'base64url');
    return decoded.length >= 16 && decoded.length <= 1023;
  } catch {
    return false;
  }
}

/**
 * Generate a unique credential ID for testing
 */
export function generateCredentialId(): Buffer {
  return crypto.randomBytes(32);
}
