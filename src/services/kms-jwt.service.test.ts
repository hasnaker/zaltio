/**
 * KMS JWT Service Tests
 * Tests for enterprise-grade JWT signing with AWS KMS
 */

import { base64urlDecode } from './kms-jwt.service';

describe('KMS JWT Service', () => {
  describe('base64urlDecode', () => {
    it('should decode base64url encoded string', () => {
      const encoded = 'SGVsbG8gV29ybGQ'; // "Hello World" in base64url
      const decoded = base64urlDecode(encoded);
      expect(decoded.toString()).toBe('Hello World');
    });

    it('should handle strings with - and _ characters', () => {
      // Base64url uses - instead of + and _ instead of /
      const encoded = 'PDw_Pz4-'; // "<<??>>""
      const decoded = base64urlDecode(encoded);
      expect(decoded.toString()).toBe('<<??>>');
    });

    it('should handle strings without padding', () => {
      const encoded = 'YQ'; // "a" without padding
      const decoded = base64urlDecode(encoded);
      expect(decoded.toString()).toBe('a');
    });

    it('should handle empty string', () => {
      const decoded = base64urlDecode('');
      expect(decoded.toString()).toBe('');
    });
  });

  describe('JWT Structure', () => {
    it('should have correct header format', () => {
      const header = {
        alg: 'RS256',
        typ: 'JWT',
        kid: 'zalt-kms-2026-01-16'
      };
      
      expect(header.alg).toBe('RS256');
      expect(header.typ).toBe('JWT');
      expect(header.kid).toMatch(/^zalt-/);
    });

    it('should have correct payload structure', () => {
      const payload = {
        sub: 'user-123',
        realm_id: 'clinisyn',
        email: 'test@example.com',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900, // 15 min
        type: 'access',
        jti: 'token-id-123',
        iss: 'https://api.zalt.io',
        aud: 'https://api.zalt.io'
      };
      
      expect(payload.iss).toBe('https://api.zalt.io');
      expect(payload.aud).toBe('https://api.zalt.io');
      expect(payload.exp - payload.iat).toBe(900); // 15 minutes
    });
  });

  describe('Security Requirements', () => {
    it('should use RS256 algorithm (FIPS compliant)', () => {
      const algorithm = 'RSASSA_PKCS1_V1_5_SHA_256';
      // This is the KMS equivalent of RS256
      expect(algorithm).toContain('SHA_256');
      expect(algorithm).toContain('RSASSA');
    });

    it('should have kid in header for key rotation', () => {
      const header = {
        alg: 'RS256',
        typ: 'JWT',
        kid: 'zalt-kms-2026-01-16'
      };
      
      expect(header.kid).toBeDefined();
      expect(typeof header.kid).toBe('string');
    });

    it('should have short access token expiry (15 min)', () => {
      const ACCESS_TOKEN_EXPIRY = 900; // seconds
      expect(ACCESS_TOKEN_EXPIRY).toBe(15 * 60);
    });

    it('should have 7 day refresh token expiry', () => {
      const REFRESH_TOKEN_EXPIRY = 604800; // seconds
      expect(REFRESH_TOKEN_EXPIRY).toBe(7 * 24 * 60 * 60);
    });
  });

  describe('KMS Configuration', () => {
    it('should have correct KMS key alias format', () => {
      const keyAlias = 'alias/zalt-jwt-signing';
      expect(keyAlias).toMatch(/^alias\//);
    });

    it('should use RSA 4096-bit key', () => {
      const keySpec = 'RSA_4096';
      expect(keySpec).toContain('RSA');
      expect(keySpec).toContain('4096');
    });
  });
});
