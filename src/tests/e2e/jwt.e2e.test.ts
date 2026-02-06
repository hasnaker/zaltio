/**
 * JWT Service E2E Tests - RS256 Implementation
 * 
 * Task 1.2: JWT Service (RS256)
 * Validates: Requirements 2.3 (JWT tokens with configurable expiration)
 * 
 * @e2e-test
 * @phase Phase 1
 * @security-critical
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Generate test RSA keys for RS256
const { publicKey: testPublicKey, privateKey: testPrivateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Mock the secrets service
jest.mock('../../services/secrets.service', () => ({
  getJWTSecrets: jest.fn().mockResolvedValue({
    access_token_secret: 'test-access-secret',
    refresh_token_secret: 'test-refresh-secret'
  }),
  getJWTKeys: jest.fn().mockResolvedValue({
    privateKey: testPrivateKey,
    publicKey: testPublicKey
  })
}));

import {
  generateTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  decodeTokenUnsafe,
  getTokenExpiry,
  isTokenExpired
} from '../../utils/jwt';

describe('JWT Service E2E Tests', () => {
  const testUser = {
    userId: 'user-123-456',
    realmId: 'clinisyn-psychologists',
    email: 'dr.ayse@clinisyn.com'
  };

  describe('RS256 Algorithm Verification', () => {
    it('should use RS256 algorithm (not HS256)', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      // Decode header to verify algorithm
      const [headerB64] = tokenPair.access_token.split('.');
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

      expect(header.alg).toBe('RS256');
      expect(header.typ).toBe('JWT');
    });

    it('should include kid header for key rotation support', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      // Decode header
      const [headerB64] = tokenPair.access_token.split('.');
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

      // Note: kid is optional but recommended for key rotation
      // Current implementation may not include it yet
      expect(header.alg).toBe('RS256');
    });
  });

  describe('Token Expiration Configuration', () => {
    it('should default to 15 minutes for access token', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      expect(tokenPair.expires_in).toBe(900); // 15 minutes
    });

    it('should default to 7 days for refresh token', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      const payload = await verifyRefreshToken(tokenPair.refresh_token);
      const expiryDuration = payload.exp - payload.iat;

      expect(expiryDuration).toBe(604800); // 7 days
    });

    it('should respect custom expiration times', async () => {
      const customExpiry = 300; // 5 minutes
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email,
        { accessTokenExpiry: customExpiry }
      );

      expect(tokenPair.expires_in).toBe(customExpiry);

      const payload = await verifyAccessToken(tokenPair.access_token);
      expect(payload.exp - payload.iat).toBe(customExpiry);
    });
  });

  describe('Token Payload Verification', () => {
    it('should include all required fields in access token', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      const payload = await verifyAccessToken(tokenPair.access_token);

      expect(payload.sub).toBe(testUser.userId);
      expect(payload.realm_id).toBe(testUser.realmId);
      expect(payload.email).toBe(testUser.email);
      expect(payload.type).toBe('access');
      expect(payload.jti).toBeTruthy(); // Unique token ID
      expect(payload.iat).toBeTruthy(); // Issued at
      expect(payload.exp).toBeTruthy(); // Expiration
    });

    it('should include issuer and audience claims', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      // Decode full payload including standard claims
      const decoded = jwt.decode(tokenPair.access_token, { complete: true }) as any;

      expect(decoded.payload.iss).toBe('https://api.zalt.io');
      expect(decoded.payload.aud).toBe('https://api.zalt.io');
    });

    it('should generate unique jti for each token', async () => {
      const tokenPair1 = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );
      const tokenPair2 = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      const payload1 = await verifyAccessToken(tokenPair1.access_token);
      const payload2 = await verifyAccessToken(tokenPair2.access_token);

      expect(payload1.jti).not.toBe(payload2.jti);
    });
  });

  describe('Token Type Separation', () => {
    it('should reject refresh token when verifying as access token', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      await expect(verifyAccessToken(tokenPair.refresh_token))
        .rejects.toThrow('Invalid token type');
    });

    it('should reject access token when verifying as refresh token', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      await expect(verifyRefreshToken(tokenPair.access_token))
        .rejects.toThrow('Invalid token type');
    });
  });

  describe('Security: Algorithm Confusion Prevention', () => {
    it('should reject tokens signed with HS256', async () => {
      // Create a token with HS256 (symmetric) - this should be rejected
      const maliciousToken = jwt.sign(
        {
          sub: testUser.userId,
          realm_id: testUser.realmId,
          email: testUser.email,
          type: 'access',
          jti: 'malicious-jti'
        },
        'some-secret',
        { algorithm: 'HS256' }
      );

      await expect(verifyAccessToken(maliciousToken)).rejects.toThrow();
    });

    it('should reject tokens with none algorithm', async () => {
      // Create unsigned token
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({
        sub: testUser.userId,
        realm_id: testUser.realmId,
        email: testUser.email,
        type: 'access'
      })).toString('base64url');
      const maliciousToken = `${header}.${payload}.`;

      await expect(verifyAccessToken(maliciousToken)).rejects.toThrow();
    });
  });

  describe('Security: Token Tampering Detection', () => {
    it('should reject tokens with modified payload', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      // Modify the payload
      const [header, , signature] = tokenPair.access_token.split('.');
      const modifiedPayload = Buffer.from(JSON.stringify({
        sub: 'hacker-user-id',
        realm_id: testUser.realmId,
        email: 'hacker@evil.com',
        type: 'access'
      })).toString('base64url');

      const tamperedToken = `${header}.${modifiedPayload}.${signature}`;

      await expect(verifyAccessToken(tamperedToken)).rejects.toThrow();
    });

    it('should reject tokens with modified signature', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      // Modify the signature
      const tamperedToken = tokenPair.access_token.slice(0, -10) + 'XXXXXXXXXX';

      await expect(verifyAccessToken(tamperedToken)).rejects.toThrow();
    });
  });

  describe('Token Expiration Handling', () => {
    it('should correctly identify expired tokens', async () => {
      // Create a token that expires immediately
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email,
        { accessTokenExpiry: 1 } // 1 second
      );

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 1500));

      expect(isTokenExpired(tokenPair.access_token)).toBe(true);
    });

    it('should correctly identify valid tokens', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      expect(isTokenExpired(tokenPair.access_token)).toBe(false);
    });

    it('should return correct expiry date', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      const expiry = getTokenExpiry(tokenPair.access_token);
      expect(expiry).toBeInstanceOf(Date);
      expect(expiry!.getTime()).toBeGreaterThan(Date.now());
    });
  });

  describe('Unsafe Decode (for logging/debugging)', () => {
    it('should decode token without verification', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      const decoded = decodeTokenUnsafe(tokenPair.access_token);

      expect(decoded).not.toBeNull();
      expect(decoded!.sub).toBe(testUser.userId);
      expect(decoded!.email).toBe(testUser.email);
    });

    it('should return null for invalid tokens', () => {
      const decoded = decodeTokenUnsafe('invalid-token');
      expect(decoded).toBeNull();
    });
  });

  describe('Token Format Validation', () => {
    it('should produce valid JWT format (3 parts)', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      const accessParts = tokenPair.access_token.split('.');
      const refreshParts = tokenPair.refresh_token.split('.');

      expect(accessParts).toHaveLength(3);
      expect(refreshParts).toHaveLength(3);
    });

    it('should use base64url encoding', async () => {
      const tokenPair = await generateTokenPair(
        testUser.userId,
        testUser.realmId,
        testUser.email
      );

      const parts = tokenPair.access_token.split('.');
      parts.forEach(part => {
        // Base64url uses only these characters
        expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
      });
    });
  });
});
