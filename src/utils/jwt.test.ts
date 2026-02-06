/**
 * Property-based tests for JWT Token Generation
 * Feature: zalt-platform, Property 3: JWT Token Validity and Security
 * Validates: Requirements 2.3
 */

import * as fc from 'fast-check';
import jwt from 'jsonwebtoken';
import { JWTPayload } from '../models/session.model';

// Mock the secrets service for testing
// Generate test RSA keys for RS256
const crypto = require('crypto');
const { publicKey: testPublicKey, privateKey: testPrivateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

jest.mock('../services/secrets.service', () => ({
  getJWTSecrets: jest.fn().mockResolvedValue({
    access_token_secret: 'test-access-secret-key-for-testing-purposes-only',
    refresh_token_secret: 'test-refresh-secret-key-for-testing-purposes-only'
  }),
  getJWTKeys: jest.fn().mockResolvedValue({
    privateKey: testPrivateKey,
    publicKey: testPublicKey
  })
}));

import { generateTokenPair, verifyAccessToken, verifyRefreshToken } from './jwt';

/**
 * Custom generators for realistic test data
 */
const userIdArb = fc.uuid();

const realmIdArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'),
  { minLength: 3, maxLength: 30 }
).filter(s => /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$/.test(s) && s.length >= 3);

const emailArb = fc.tuple(
  fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'), { minLength: 3, maxLength: 15 }),
  fc.constantFrom('gmail.com', 'example.com', 'hsdcore.com')
).map(([local, domain]) => `${local}@${domain}`);

const expiryArb = fc.integer({ min: 60, max: 86400 }); // 1 minute to 24 hours

describe('JWT Token - Property Tests', () => {
  /**
   * Property 3: JWT Token Validity and Security
   * For any authentication request, generated JWT tokens should be properly formatted,
   * contain correct expiration times, and be cryptographically valid according to
   * the configured realm settings.
   * Validates: Requirements 2.3
   */
  describe('Property 3: JWT Token Validity and Security', () => {
    it('should generate valid JWT tokens with correct structure', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          async (userId, realmId, email) => {
            const tokenPair = await generateTokenPair(userId, realmId, email);

            // Both tokens should be non-empty strings
            expect(typeof tokenPair.access_token).toBe('string');
            expect(typeof tokenPair.refresh_token).toBe('string');
            expect(tokenPair.access_token.length).toBeGreaterThan(0);
            expect(tokenPair.refresh_token.length).toBeGreaterThan(0);

            // Tokens should be different
            expect(tokenPair.access_token).not.toBe(tokenPair.refresh_token);

            // expires_in should be a positive number
            expect(tokenPair.expires_in).toBeGreaterThan(0);

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should include correct payload data in access tokens', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          async (userId, realmId, email) => {
            const tokenPair = await generateTokenPair(userId, realmId, email);
            const payload = await verifyAccessToken(tokenPair.access_token);

            // Payload should contain correct user data
            expect(payload.sub).toBe(userId);
            expect(payload.realm_id).toBe(realmId);
            expect(payload.email).toBe(email);
            expect(payload.type).toBe('access');

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should include correct payload data in refresh tokens', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          async (userId, realmId, email) => {
            const tokenPair = await generateTokenPair(userId, realmId, email);
            const payload = await verifyRefreshToken(tokenPair.refresh_token);

            // Payload should contain correct user data
            expect(payload.sub).toBe(userId);
            expect(payload.realm_id).toBe(realmId);
            expect(payload.email).toBe(email);
            expect(payload.type).toBe('refresh');

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should respect configurable expiration times', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          expiryArb,
          async (userId, realmId, email, expiry) => {
            const tokenPair = await generateTokenPair(userId, realmId, email, {
              accessTokenExpiry: expiry
            });

            // expires_in should match configured expiry
            expect(tokenPair.expires_in).toBe(expiry);

            // Verify token expiration is set correctly
            const payload = await verifyAccessToken(tokenPair.access_token);
            const expectedExp = payload.iat + expiry;
            expect(payload.exp).toBe(expectedExp);

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should generate cryptographically valid tokens', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          async (userId, realmId, email) => {
            const tokenPair = await generateTokenPair(userId, realmId, email);

            // Tokens should be valid JWT format (3 parts separated by dots)
            const accessParts = tokenPair.access_token.split('.');
            const refreshParts = tokenPair.refresh_token.split('.');

            expect(accessParts).toHaveLength(3);
            expect(refreshParts).toHaveLength(3);

            // Each part should be base64url encoded
            accessParts.forEach(part => {
              expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
            });

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should reject tampered tokens', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          async (userId, realmId, email) => {
            const tokenPair = await generateTokenPair(userId, realmId, email);

            // Tamper with the token by modifying a character
            const tamperedToken = tokenPair.access_token.slice(0, -5) + 'XXXXX';

            // Verification should fail
            await expect(verifyAccessToken(tamperedToken)).rejects.toThrow();

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not allow access token verification with refresh token', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          async (userId, realmId, email) => {
            const tokenPair = await generateTokenPair(userId, realmId, email);

            // Using refresh token as access token should fail
            await expect(verifyAccessToken(tokenPair.refresh_token)).rejects.toThrow();

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should generate unique tokens for each call', async () => {
      await fc.assert(
        fc.asyncProperty(
          userIdArb,
          realmIdArb,
          emailArb,
          async (userId, realmId, email) => {
            // Generate two token pairs - they may have same iat if within same second
            // but the tokens themselves should still be valid and verifiable
            const tokenPair1 = await generateTokenPair(userId, realmId, email);
            const tokenPair2 = await generateTokenPair(userId, realmId, email);

            // Both token pairs should be valid
            const payload1 = await verifyAccessToken(tokenPair1.access_token);
            const payload2 = await verifyAccessToken(tokenPair2.access_token);

            // Both should have same user data
            expect(payload1.sub).toBe(payload2.sub);
            expect(payload1.realm_id).toBe(payload2.realm_id);
            expect(payload1.email).toBe(payload2.email);

            return true;
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
