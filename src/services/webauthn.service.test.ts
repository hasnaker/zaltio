/**
 * WebAuthn Service Unit Tests
 * 
 * Task 2.5: WebAuthn Service
 * Validates: Requirements 2.2 (MFA - WebAuthn)
 * 
 * SECURITY CRITICAL: WebAuthn is the primary defense against Evilginx2
 */

import {
  generateChallenge,
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  isValidCredentialId,
  generateCredentialId,
  WEBAUTHN_CONFIG,
  SUPPORTED_ALGORITHMS,
  WebAuthnCredential
} from './webauthn.service';

describe('WebAuthn Service', () => {
  describe('generateChallenge', () => {
    it('should generate base64url encoded challenge', () => {
      const challenge = generateChallenge();
      
      expect(challenge).toBeDefined();
      expect(typeof challenge).toBe('string');
      // Base64url characters only
      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate 32 byte (256 bit) challenge', () => {
      const challenge = generateChallenge();
      const decoded = Buffer.from(challenge, 'base64url');
      
      expect(decoded.length).toBe(32);
    });

    it('should generate unique challenges', () => {
      const challenges = new Set<string>();
      for (let i = 0; i < 100; i++) {
        challenges.add(generateChallenge());
      }
      
      expect(challenges.size).toBe(100);
    });

    it('should be cryptographically random', () => {
      const challenge1 = generateChallenge();
      const challenge2 = generateChallenge();
      
      expect(challenge1).not.toBe(challenge2);
    });
  });

  describe('generateRegistrationOptions', () => {
    const userId = 'user-123';
    const userEmail = 'dr.ayse@example.com';
    const userName = 'Dr. Ayşe Yılmaz';

    it('should generate valid registration options', () => {
      const options = generateRegistrationOptions(userId, userEmail, userName);
      
      expect(options).toBeDefined();
      expect(options.challenge).toBeDefined();
      expect(options.rp).toBeDefined();
      expect(options.user).toBeDefined();
      expect(options.pubKeyCredParams).toBeDefined();
    });

    it('should include RP information', () => {
      const options = generateRegistrationOptions(userId, userEmail, userName);
      
      expect(options.rp.name).toBe(WEBAUTHN_CONFIG.rpName);
      expect(options.rp.id).toBe(WEBAUTHN_CONFIG.rpId);
    });

    it('should include user information', () => {
      const options = generateRegistrationOptions(userId, userEmail, userName);
      
      expect(options.user.name).toBe(userEmail);
      expect(options.user.displayName).toBe(userName);
      expect(options.user.id).toBeDefined();
    });

    it('should encode user ID as base64url', () => {
      const options = generateRegistrationOptions(userId, userEmail, userName);
      const decodedId = Buffer.from(options.user.id, 'base64url').toString();
      
      expect(decodedId).toBe(userId);
    });

    it('should include supported algorithms', () => {
      const options = generateRegistrationOptions(userId, userEmail, userName);
      
      expect(options.pubKeyCredParams).toEqual(SUPPORTED_ALGORITHMS);
      expect(options.pubKeyCredParams).toContainEqual({ alg: -7, type: 'public-key' }); // ES256
      expect(options.pubKeyCredParams).toContainEqual({ alg: -257, type: 'public-key' }); // RS256
    });

    it('should set timeout', () => {
      const options = generateRegistrationOptions(userId, userEmail, userName);
      
      expect(options.timeout).toBe(WEBAUTHN_CONFIG.timeout);
    });

    it('should set attestation to none', () => {
      const options = generateRegistrationOptions(userId, userEmail, userName);
      
      expect(options.attestation).toBe('none');
    });

    it('should set authenticator selection', () => {
      const options = generateRegistrationOptions(userId, userEmail, userName);
      
      expect(options.authenticatorSelection).toBeDefined();
      expect(options.authenticatorSelection.userVerification).toBe('preferred');
      expect(options.authenticatorSelection.residentKey).toBe('preferred');
    });

    it('should exclude existing credentials', () => {
      const existingCredentials: WebAuthnCredential[] = [{
        id: 'cred-1',
        credentialId: Buffer.from('existing-credential-id'),
        publicKey: Buffer.from('public-key'),
        counter: 0,
        transports: ['internal'],
        createdAt: new Date().toISOString()
      }];

      const options = generateRegistrationOptions(
        userId, userEmail, userName, existingCredentials
      );
      
      expect(options.excludeCredentials).toBeDefined();
      expect(options.excludeCredentials).toHaveLength(1);
      expect(options.excludeCredentials![0].type).toBe('public-key');
    });

    it('should allow custom RP ID and name', () => {
      const customRpId = 'clinisyn.com';
      const customRpName = 'Clinisyn';

      const options = generateRegistrationOptions(
        userId, userEmail, userName, [], customRpId, customRpName
      );
      
      expect(options.rp.id).toBe(customRpId);
      expect(options.rp.name).toBe(customRpName);
    });
  });

  describe('generateAuthenticationOptions', () => {
    const mockCredentials: WebAuthnCredential[] = [{
      id: 'cred-1',
      credentialId: Buffer.from('credential-id-1'),
      publicKey: Buffer.from('public-key-1'),
      counter: 5,
      transports: ['internal'],
      createdAt: new Date().toISOString()
    }, {
      id: 'cred-2',
      credentialId: Buffer.from('credential-id-2'),
      publicKey: Buffer.from('public-key-2'),
      counter: 10,
      transports: ['usb', 'nfc'],
      createdAt: new Date().toISOString()
    }];

    it('should generate valid authentication options', () => {
      const options = generateAuthenticationOptions(mockCredentials);
      
      expect(options).toBeDefined();
      expect(options.challenge).toBeDefined();
      expect(options.rpId).toBe(WEBAUTHN_CONFIG.rpId);
      expect(options.timeout).toBe(WEBAUTHN_CONFIG.timeout);
    });

    it('should include allowed credentials', () => {
      const options = generateAuthenticationOptions(mockCredentials);
      
      expect(options.allowCredentials).toBeDefined();
      expect(options.allowCredentials).toHaveLength(2);
    });

    it('should include credential transports', () => {
      const options = generateAuthenticationOptions(mockCredentials);
      
      expect(options.allowCredentials![0].transports).toEqual(['internal']);
      expect(options.allowCredentials![1].transports).toEqual(['usb', 'nfc']);
    });

    it('should set user verification preference', () => {
      const options = generateAuthenticationOptions(mockCredentials);
      
      expect(options.userVerification).toBe('preferred');
    });

    it('should allow custom RP ID', () => {
      const customRpId = 'clinisyn.com';
      const options = generateAuthenticationOptions(mockCredentials, customRpId);
      
      expect(options.rpId).toBe(customRpId);
    });

    it('should handle empty credentials list', () => {
      const options = generateAuthenticationOptions([]);
      
      expect(options.allowCredentials).toBeUndefined();
    });
  });

  describe('verifyRegistrationResponse', () => {
    const expectedChallenge = generateChallenge();
    const expectedOrigin = 'https://zalt.io';
    const expectedRpId = 'zalt.io';

    it('should reject mismatched challenge', async () => {
      const mockResponse = {
        id: 'credential-id',
        rawId: 'credential-id',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.create',
            challenge: 'wrong-challenge',
            origin: expectedOrigin
          })).toString('base64url'),
          attestationObject: Buffer.from('mock-attestation').toString('base64url')
        },
        type: 'public-key' as const
      };

      const result = await verifyRegistrationResponse(
        mockResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRpId
      );

      expect(result.verified).toBe(false);
      expect(result.error).toContain('Challenge mismatch');
    });

    it('should reject mismatched origin (CRITICAL for phishing protection)', async () => {
      const mockResponse = {
        id: 'credential-id',
        rawId: 'credential-id',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.create',
            challenge: expectedChallenge,
            origin: 'https://evil-phishing-site.com'
          })).toString('base64url'),
          attestationObject: Buffer.from('mock-attestation').toString('base64url')
        },
        type: 'public-key' as const
      };

      const result = await verifyRegistrationResponse(
        mockResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRpId
      );

      expect(result.verified).toBe(false);
      expect(result.error).toContain('Origin mismatch');
    });

    it('should reject wrong client data type', async () => {
      const mockResponse = {
        id: 'credential-id',
        rawId: 'credential-id',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.get', // Wrong type for registration
            challenge: expectedChallenge,
            origin: expectedOrigin
          })).toString('base64url'),
          attestationObject: Buffer.from('mock-attestation').toString('base64url')
        },
        type: 'public-key' as const
      };

      const result = await verifyRegistrationResponse(
        mockResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRpId
      );

      expect(result.verified).toBe(false);
      expect(result.error).toContain('Invalid client data type');
    });
  });

  describe('verifyAuthenticationResponse', () => {
    const expectedChallenge = generateChallenge();
    const expectedOrigin = 'https://zalt.io';
    const expectedRpId = 'zalt.io';
    const mockCredential: WebAuthnCredential = {
      id: 'cred-1',
      credentialId: Buffer.from('credential-id'),
      publicKey: Buffer.from('public-key'),
      counter: 5,
      createdAt: new Date().toISOString()
    };

    it('should reject mismatched challenge', async () => {
      const mockResponse = {
        id: 'credential-id',
        rawId: 'credential-id',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.get',
            challenge: 'wrong-challenge',
            origin: expectedOrigin
          })).toString('base64url'),
          authenticatorData: Buffer.alloc(37).toString('base64url'),
          signature: Buffer.from('signature').toString('base64url')
        },
        type: 'public-key' as const
      };

      const result = await verifyAuthenticationResponse(
        mockResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRpId,
        mockCredential
      );

      expect(result.verified).toBe(false);
      expect(result.error).toContain('Challenge mismatch');
    });

    it('should reject mismatched origin (CRITICAL for phishing protection)', async () => {
      const mockResponse = {
        id: 'credential-id',
        rawId: 'credential-id',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.get',
            challenge: expectedChallenge,
            origin: 'https://evilginx-proxy.com'
          })).toString('base64url'),
          authenticatorData: Buffer.alloc(37).toString('base64url'),
          signature: Buffer.from('signature').toString('base64url')
        },
        type: 'public-key' as const
      };

      const result = await verifyAuthenticationResponse(
        mockResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRpId,
        mockCredential
      );

      expect(result.verified).toBe(false);
      expect(result.error).toContain('Origin mismatch');
    });

    it('should reject wrong client data type', async () => {
      const mockResponse = {
        id: 'credential-id',
        rawId: 'credential-id',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.create', // Wrong type for authentication
            challenge: expectedChallenge,
            origin: expectedOrigin
          })).toString('base64url'),
          authenticatorData: Buffer.alloc(37).toString('base64url'),
          signature: Buffer.from('signature').toString('base64url')
        },
        type: 'public-key' as const
      };

      const result = await verifyAuthenticationResponse(
        mockResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRpId,
        mockCredential
      );

      expect(result.verified).toBe(false);
      expect(result.error).toContain('Invalid client data type');
    });
  });

  describe('isValidCredentialId', () => {
    it('should accept valid credential IDs', () => {
      const validId = generateCredentialId().toString('base64url');
      
      expect(isValidCredentialId(validId)).toBe(true);
    });

    it('should reject too short credential IDs', () => {
      const shortId = Buffer.alloc(10).toString('base64url');
      
      expect(isValidCredentialId(shortId)).toBe(false);
    });

    it('should reject invalid base64url', () => {
      expect(isValidCredentialId('invalid!@#$%')).toBe(false);
    });

    it('should accept credential IDs up to 1023 bytes', () => {
      const maxId = Buffer.alloc(1023).toString('base64url');
      
      expect(isValidCredentialId(maxId)).toBe(true);
    });
  });

  describe('generateCredentialId', () => {
    it('should generate 32 byte credential ID', () => {
      const credentialId = generateCredentialId();
      
      expect(credentialId.length).toBe(32);
    });

    it('should generate unique credential IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateCredentialId().toString('hex'));
      }
      
      expect(ids.size).toBe(100);
    });
  });

  describe('WEBAUTHN_CONFIG', () => {
    it('should have correct configuration', () => {
      expect(WEBAUTHN_CONFIG.rpName).toBe('Zalt.io');
      expect(WEBAUTHN_CONFIG.rpId).toBe('zalt.io');
      expect(WEBAUTHN_CONFIG.challengeSize).toBe(32);
      expect(WEBAUTHN_CONFIG.timeout).toBe(60000);
      expect(WEBAUTHN_CONFIG.attestation).toBe('none');
      expect(WEBAUTHN_CONFIG.userVerification).toBe('preferred');
    });
  });

  describe('SUPPORTED_ALGORITHMS', () => {
    it('should support ES256 (preferred)', () => {
      const es256 = SUPPORTED_ALGORITHMS.find(a => a.alg === -7);
      
      expect(es256).toBeDefined();
      expect(es256!.type).toBe('public-key');
    });

    it('should support RS256 (fallback)', () => {
      const rs256 = SUPPORTED_ALGORITHMS.find(a => a.alg === -257);
      
      expect(rs256).toBeDefined();
      expect(rs256!.type).toBe('public-key');
    });
  });

  describe('Security: Phishing Protection', () => {
    it('should always validate origin in registration', async () => {
      const challenge = generateChallenge();
      const legitimateOrigin = 'https://zalt.io';
      const phishingOrigin = 'https://zalt-io.phishing.com';

      const mockResponse = {
        id: 'credential-id',
        rawId: 'credential-id',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.create',
            challenge,
            origin: phishingOrigin
          })).toString('base64url'),
          attestationObject: Buffer.from('mock').toString('base64url')
        },
        type: 'public-key' as const
      };

      const result = await verifyRegistrationResponse(
        mockResponse,
        challenge,
        legitimateOrigin,
        'zalt.io'
      );

      expect(result.verified).toBe(false);
      expect(result.error).toContain('Origin mismatch');
    });

    it('should always validate origin in authentication', async () => {
      const challenge = generateChallenge();
      const legitimateOrigin = 'https://zalt.io';
      const evilginxOrigin = 'https://zalt.io.attacker.com';

      const mockResponse = {
        id: 'credential-id',
        rawId: 'credential-id',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.get',
            challenge,
            origin: evilginxOrigin
          })).toString('base64url'),
          authenticatorData: Buffer.alloc(37).toString('base64url'),
          signature: Buffer.from('sig').toString('base64url')
        },
        type: 'public-key' as const
      };

      const mockCredential: WebAuthnCredential = {
        id: 'cred-1',
        credentialId: Buffer.from('cred'),
        publicKey: Buffer.from('key'),
        counter: 0,
        createdAt: new Date().toISOString()
      };

      const result = await verifyAuthenticationResponse(
        mockResponse,
        challenge,
        legitimateOrigin,
        'zalt.io',
        mockCredential
      );

      expect(result.verified).toBe(false);
      expect(result.error).toContain('Origin mismatch');
    });
  });
});
