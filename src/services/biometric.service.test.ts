/**
 * Biometric Authentication Service Tests
 * Validates: Requirements 28.1-28.4, 28.7
 * 
 * Tests for:
 * - iOS LocalAuthentication integration
 * - Android BiometricPrompt integration
 * - Liveness detection
 * - Device registration and management
 */

import {
  // Configuration
  BIOMETRIC_CONFIG,
  BiometricType,
  BiometricPlatform,
  BiometricStrength,
  LivenessMethod,
  BiometricErrorCode,
  
  // Challenge management
  generateChallenge,
  createBiometricChallenge,
  getChallenge,
  isChallengeValid,
  consumeChallenge,
  createLivenessChallenge,
  
  // Verification
  verifyBiometricResponse,
  verifyLiveness,
  
  // Device management
  registerBiometricDevice,
  listBiometricDevices,
  getBiometricDevice,
  getBiometricDeviceByKeyId,
  revokeBiometricDevice,
  suspendBiometricDevice,
  reactivateBiometricDevice,
  updateDeviceUsage,
  trustBiometricDevice,
  
  // Utilities
  isBiometricAvailable,
  getRecommendedBiometricType,
  validateDeviceInfo,
  getBiometricStrength,
  meetsSecurityRequirements,
  
  // Types
  BiometricChallenge,
  BiometricDeviceInfo,
  BiometricDevice,
  BiometricResponse,
  LivenessData,
  LivenessFrame,
  ActionResult,
  DeviceAttestation,
  
  // Testing utilities
  _testing,
} from './biometric.service';

describe('Biometric Service', () => {
  beforeEach(() => {
    // Clear stores before each test
    _testing.clearStores();
  });


  // ============================================
  // Challenge Generation Tests
  // ============================================

  describe('Challenge Generation', () => {
    it('should generate a cryptographically secure challenge', () => {
      const challenge = generateChallenge();
      
      expect(challenge).toBeDefined();
      expect(typeof challenge).toBe('string');
      expect(challenge.length).toBeGreaterThan(20); // Base64url encoded 32 bytes
    });

    it('should generate unique challenges', () => {
      const challenges = new Set<string>();
      
      for (let i = 0; i < 100; i++) {
        challenges.add(generateChallenge());
      }
      
      expect(challenges.size).toBe(100); // All unique
    });

    it('should create biometric challenge with all required fields', () => {
      const userId = 'user_123';
      const deviceId = 'device_456';
      
      const challenge = createBiometricChallenge(userId, deviceId, BiometricPlatform.IOS);
      
      expect(challenge.id).toBeDefined();
      expect(challenge.challenge).toBeDefined();
      expect(challenge.userId).toBe(userId);
      expect(challenge.deviceId).toBe(deviceId);
      expect(challenge.platform).toBe(BiometricPlatform.IOS);
      expect(challenge.createdAt).toBeDefined();
      expect(challenge.expiresAt).toBeDefined();
    });

    it('should create challenge with liveness when requested', () => {
      const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS, true);
      
      expect(challenge.livenessChallenge).toBeDefined();
      expect(challenge.livenessChallenge?.id).toBeDefined();
      expect(challenge.livenessChallenge?.method).toBeDefined();
    });

    it('should store challenge for retrieval', () => {
      const challenge = createBiometricChallenge('user_123');
      
      const retrieved = getChallenge(challenge.id);
      
      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(challenge.id);
      expect(retrieved?.challenge).toBe(challenge.challenge);
    });

    it('should validate challenge expiry correctly', () => {
      const challenge = createBiometricChallenge('user_123');
      
      expect(isChallengeValid(challenge)).toBe(true);
      
      // Create expired challenge
      const expiredChallenge: BiometricChallenge = {
        ...challenge,
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      };
      
      expect(isChallengeValid(expiredChallenge)).toBe(false);
    });

    it('should consume challenge after use', () => {
      const challenge = createBiometricChallenge('user_123');
      
      expect(getChallenge(challenge.id)).toBeDefined();
      
      const consumed = consumeChallenge(challenge.id);
      
      expect(consumed).toBe(true);
      expect(getChallenge(challenge.id)).toBeUndefined();
    });
  });

  // ============================================
  // Liveness Challenge Tests
  // ============================================

  describe('Liveness Challenge', () => {
    it('should create passive liveness challenge', () => {
      const challenge = createLivenessChallenge(LivenessMethod.PASSIVE);
      
      expect(challenge.id).toBeDefined();
      expect(challenge.method).toBe(LivenessMethod.PASSIVE);
      expect(challenge.timeout).toBeGreaterThan(0);
    });

    it('should create active liveness challenge with actions', () => {
      const challenge = createLivenessChallenge(LivenessMethod.ACTIVE);
      
      expect(challenge.method).toBe(LivenessMethod.ACTIVE);
      expect(challenge.actions).toBeDefined();
      expect(challenge.actions!.length).toBeGreaterThanOrEqual(2);
      expect(challenge.expectedSequence).toBeDefined();
    });

    it('should create challenge-response liveness with more actions', () => {
      const challenge = createLivenessChallenge(LivenessMethod.CHALLENGE_RESPONSE);
      
      expect(challenge.method).toBe(LivenessMethod.CHALLENGE_RESPONSE);
      expect(challenge.actions!.length).toBe(3);
    });

    it('should generate valid action types', () => {
      const challenge = createLivenessChallenge(LivenessMethod.ACTIVE);
      
      const validTypes = ['blink', 'smile', 'turn_head', 'nod', 'open_mouth'];
      
      for (const action of challenge.actions!) {
        expect(validTypes).toContain(action.type);
      }
    });
  });


  // ============================================
  // Biometric Response Verification Tests
  // ============================================

  describe('Biometric Response Verification', () => {
    it('should reject verification with non-existent challenge', async () => {
      const response: BiometricResponse = {
        challengeId: 'non_existent',
        signature: 'test_signature',
        keyId: 'key_123',
      };

      const result = await verifyBiometricResponse('non_existent', response);

      expect(result.verified).toBe(false);
      expect(result.errorCode).toBe(BiometricErrorCode.CHALLENGE_NOT_FOUND);
    });

    it('should reject verification with expired challenge', async () => {
      const challenge = createBiometricChallenge('user_123');
      
      // Manually expire the challenge
      const storedChallenge = getChallenge(challenge.id);
      if (storedChallenge) {
        storedChallenge.expiresAt = new Date(Date.now() - 1000).toISOString();
      }

      const response: BiometricResponse = {
        challengeId: challenge.id,
        signature: 'test_signature',
        keyId: 'key_123',
      };

      const result = await verifyBiometricResponse(challenge.id, response);

      expect(result.verified).toBe(false);
      expect(result.errorCode).toBe(BiometricErrorCode.CHALLENGE_EXPIRED);
    });

    it('should consume challenge after verification attempt', async () => {
      const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS);
      
      const response: BiometricResponse = {
        challengeId: challenge.id,
        signature: 'test_signature',
        keyId: 'key_123',
        assertion: Buffer.from('test_assertion').toString('base64'),
      };

      await verifyBiometricResponse(challenge.id, response);

      // Challenge should be consumed
      expect(getChallenge(challenge.id)).toBeUndefined();
    });

    describe('iOS Verification', () => {
      it('should require assertion for iOS platform', async () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS);
        
        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'test_signature',
          keyId: 'key_123',
          // Missing assertion
        };

        const result = await verifyBiometricResponse(challenge.id, response);

        expect(result.verified).toBe(false);
      });

      it('should verify iOS assertion with valid data', async () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS);
        
        // Create mock assertion with challenge hash
        const challengeHash = require('crypto')
          .createHash('sha256')
          .update(challenge.challenge)
          .digest();
        
        const mockAssertion = Buffer.concat([
          Buffer.alloc(32), // Padding
          challengeHash,
          Buffer.alloc(32), // More padding
        ]);

        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'test_signature',
          keyId: 'key_1234567890123456', // 16+ chars
          assertion: mockAssertion.toString('base64'),
        };

        const attestation: DeviceAttestation = {
          format: 'ios-app-attest',
          attestationData: 'valid_attestation_data',
          verified: false,
          securityLevel: 'secure_enclave',
        };

        const result = await verifyBiometricResponse(challenge.id, response, attestation);

        expect(result.verified).toBe(true);
      });
    });

    describe('Android Verification', () => {
      it('should require biometricSignature for Android platform', async () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.ANDROID);
        
        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'test_signature',
          keyId: 'key_123',
          // Missing biometricSignature
        };

        const result = await verifyBiometricResponse(challenge.id, response);

        expect(result.verified).toBe(false);
      });

      it('should verify Android signature with valid attestation', async () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.ANDROID);
        
        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'test_signature',
          keyId: 'key_1234567890123456',
          biometricSignature: Buffer.alloc(64).toString('base64'), // Valid length signature
        };

        const attestation: DeviceAttestation = {
          format: 'android-key-attestation',
          attestationData: 'valid_attestation_data',
          verified: false,
          securityLevel: 'tee',
          // Certificate chain with valid length certificates (100+ chars each)
          certificateChain: [
            'MIICpDCCAYwCCQDU+pQ4P6gB8jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Q=',
          ],
        };

        const result = await verifyBiometricResponse(challenge.id, response, attestation);

        expect(result.verified).toBe(true);
      });

      it('should reject Android with software security level', async () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.ANDROID);
        
        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'test_signature',
          keyId: 'key_1234567890123456',
          biometricSignature: Buffer.alloc(64).toString('base64'),
        };

        const attestation: DeviceAttestation = {
          format: 'android-key-attestation',
          attestationData: 'valid_attestation_data',
          verified: false,
          securityLevel: 'software', // Not acceptable
        };

        const result = await verifyBiometricResponse(challenge.id, response, attestation);

        expect(result.verified).toBe(false);
      });
    });

    describe('WebAuthn Verification', () => {
      it('should require WebAuthn fields for web platform', async () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.WEB);
        
        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'test_signature',
          keyId: 'key_123',
          // Missing authenticatorData and clientDataJSON
        };

        const result = await verifyBiometricResponse(challenge.id, response);

        expect(result.verified).toBe(false);
      });

      it('should verify WebAuthn response with user verification', async () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.WEB);
        
        // Create valid clientDataJSON
        const clientData = {
          type: 'webauthn.get',
          challenge: challenge.challenge,
          origin: 'https://zalt.io',
        };
        const clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString('base64url');

        // Create authenticator data with UP and UV flags set
        const authenticatorData = Buffer.alloc(37);
        authenticatorData[32] = 0x05; // UP (0x01) + UV (0x04) flags

        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'test_signature',
          keyId: 'key_123',
          authenticatorData: authenticatorData.toString('base64url'),
          clientDataJSON,
        };

        const result = await verifyBiometricResponse(challenge.id, response);

        expect(result.verified).toBe(true);
      });

      it('should reject WebAuthn without user verification flag', async () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.WEB);
        
        const clientData = {
          type: 'webauthn.get',
          challenge: challenge.challenge,
          origin: 'https://zalt.io',
        };
        const clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString('base64url');

        // Authenticator data with only UP flag (no UV)
        const authenticatorData = Buffer.alloc(37);
        authenticatorData[32] = 0x01; // Only UP flag

        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'test_signature',
          keyId: 'key_123',
          authenticatorData: authenticatorData.toString('base64url'),
          clientDataJSON,
        };

        const result = await verifyBiometricResponse(challenge.id, response);

        expect(result.verified).toBe(false);
      });
    });
  });


  // ============================================
  // Liveness Verification Tests
  // ============================================

  describe('Liveness Verification', () => {
    it('should reject liveness without challenge', () => {
      const livenessData: LivenessData = {
        challengeId: 'non_existent',
        method: LivenessMethod.PASSIVE,
        confidence: 0.9,
        timestamp: new Date().toISOString(),
      };

      const result = verifyLiveness('non_existent', livenessData);

      expect(result.verified).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should reject liveness with method mismatch', () => {
      const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS, true);
      
      // Force a specific method
      if (challenge.livenessChallenge) {
        challenge.livenessChallenge.method = LivenessMethod.ACTIVE;
      }

      const livenessData: LivenessData = {
        challengeId: challenge.id,
        method: LivenessMethod.PASSIVE, // Mismatch
        confidence: 0.9,
        timestamp: new Date().toISOString(),
      };

      const result = verifyLiveness(challenge.id, livenessData);

      expect(result.verified).toBe(false);
      expect(result.error).toContain('mismatch');
    });

    describe('Passive Liveness', () => {
      it('should verify passive liveness with good frames', () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS, true);
        
        if (challenge.livenessChallenge) {
          challenge.livenessChallenge.method = LivenessMethod.PASSIVE;
        }

        const frames: LivenessFrame[] = [];
        for (let i = 0; i < 10; i++) {
          frames.push({
            timestamp: Date.now() + i * 100,
            faceDetected: true,
            faceBox: { x: 100 + i * 0.5, y: 100 + i * 0.3, width: 200, height: 200 },
            quality: 0.85 + Math.random() * 0.1,
          });
        }

        const livenessData: LivenessData = {
          challengeId: challenge.id,
          method: LivenessMethod.PASSIVE,
          frames,
          confidence: 0.9,
          timestamp: new Date().toISOString(),
        };

        const result = verifyLiveness(challenge.id, livenessData);

        expect(result.confidence).toBeGreaterThan(0);
      });

      it('should detect static photo (no movement)', () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS, true);
        
        if (challenge.livenessChallenge) {
          challenge.livenessChallenge.method = LivenessMethod.PASSIVE;
        }

        // All frames have identical face position (static photo)
        const frames: LivenessFrame[] = [];
        for (let i = 0; i < 10; i++) {
          frames.push({
            timestamp: Date.now() + i * 100,
            faceDetected: true,
            faceBox: { x: 100, y: 100, width: 200, height: 200 }, // No movement
            quality: 0.9,
          });
        }

        const livenessData: LivenessData = {
          challengeId: challenge.id,
          method: LivenessMethod.PASSIVE,
          frames,
          confidence: 0.5,
          timestamp: new Date().toISOString(),
        };

        const result = verifyLiveness(challenge.id, livenessData);

        // Should have lower confidence due to no natural movement
        expect(result.confidence).toBeLessThan(BIOMETRIC_CONFIG.livenessThreshold);
      });
    });

    describe('Active Liveness', () => {
      it('should verify active liveness with completed actions', () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS, true);
        
        if (challenge.livenessChallenge) {
          challenge.livenessChallenge.method = LivenessMethod.ACTIVE;
          challenge.livenessChallenge.actions = [
            { type: 'blink' },
            { type: 'smile' },
          ];
          challenge.livenessChallenge.expectedSequence = ['blink', 'smile'];
        }

        const actionResults: ActionResult[] = [
          { action: { type: 'blink' }, completed: true, confidence: 0.95, timestamp: Date.now() },
          { action: { type: 'smile' }, completed: true, confidence: 0.92, timestamp: Date.now() + 1000 },
        ];

        const livenessData: LivenessData = {
          challengeId: challenge.id,
          method: LivenessMethod.ACTIVE,
          actionResults,
          confidence: 0.93,
          timestamp: new Date().toISOString(),
        };

        const result = verifyLiveness(challenge.id, livenessData);

        expect(result.verified).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(0.9);
      });

      it('should reject incomplete actions', () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS, true);
        
        if (challenge.livenessChallenge) {
          challenge.livenessChallenge.method = LivenessMethod.ACTIVE;
          challenge.livenessChallenge.actions = [
            { type: 'blink' },
            { type: 'smile' },
          ];
          challenge.livenessChallenge.expectedSequence = ['blink', 'smile'];
        }

        const actionResults: ActionResult[] = [
          { action: { type: 'blink' }, completed: true, confidence: 0.95, timestamp: Date.now() },
          { action: { type: 'smile' }, completed: false, confidence: 0.3, timestamp: Date.now() + 1000 },
        ];

        const livenessData: LivenessData = {
          challengeId: challenge.id,
          method: LivenessMethod.ACTIVE,
          actionResults,
          confidence: 0.5,
          timestamp: new Date().toISOString(),
        };

        const result = verifyLiveness(challenge.id, livenessData);

        expect(result.verified).toBe(false);
        expect(result.confidence).toBeLessThan(BIOMETRIC_CONFIG.livenessThreshold);
      });

      it('should reject wrong action sequence', () => {
        const challenge = createBiometricChallenge('user_123', undefined, BiometricPlatform.IOS, true);
        
        if (challenge.livenessChallenge) {
          challenge.livenessChallenge.method = LivenessMethod.ACTIVE;
          challenge.livenessChallenge.actions = [
            { type: 'blink' },
            { type: 'smile' },
          ];
          challenge.livenessChallenge.expectedSequence = ['blink', 'smile'];
        }

        // Wrong order
        const actionResults: ActionResult[] = [
          { action: { type: 'smile' }, completed: true, confidence: 0.95, timestamp: Date.now() },
          { action: { type: 'blink' }, completed: true, confidence: 0.92, timestamp: Date.now() + 1000 },
        ];

        const livenessData: LivenessData = {
          challengeId: challenge.id,
          method: LivenessMethod.ACTIVE,
          actionResults,
          confidence: 0.5,
          timestamp: new Date().toISOString(),
        };

        const result = verifyLiveness(challenge.id, livenessData);

        expect(result.confidence).toBeLessThan(BIOMETRIC_CONFIG.livenessThreshold);
      });
    });
  });


  // ============================================
  // Device Registration Tests
  // ============================================

  describe('Device Registration', () => {
    const validDeviceInfo: BiometricDeviceInfo = {
      platform: BiometricPlatform.IOS,
      model: 'iPhone 15 Pro',
      osVersion: '17.0',
      biometricTypes: [BiometricType.FACE_ID],
      secureEnclaveAvailable: true,
      deviceName: 'My iPhone',
    };

    const validAttestation: DeviceAttestation = {
      format: 'ios-app-attest',
      attestationData: 'valid_attestation_data_here',
      verified: false,
      securityLevel: 'secure_enclave',
    };

    it('should register a new biometric device', async () => {
      const result = await registerBiometricDevice(
        'user_123',
        'realm_456',
        validDeviceInfo,
        validAttestation,
        'public_key_data'
      );

      expect(result.device).toBeDefined();
      expect(result.device?.userId).toBe('user_123');
      expect(result.device?.realmId).toBe('realm_456');
      expect(result.device?.platform).toBe(BiometricPlatform.IOS);
      expect(result.device?.status).toBe('active');
      expect(result.device?.attestation.verified).toBe(true);
    });

    it('should generate device name if not provided', async () => {
      const deviceInfoWithoutName = { ...validDeviceInfo, deviceName: undefined };

      const result = await registerBiometricDevice(
        'user_123',
        'realm_456',
        deviceInfoWithoutName,
        validAttestation,
        'public_key_data'
      );

      expect(result.device?.name).toContain('Face ID');
    });

    it('should reject registration when max devices reached', async () => {
      // Register max devices
      for (let i = 0; i < BIOMETRIC_CONFIG.maxDevicesPerUser; i++) {
        await registerBiometricDevice(
          'user_max',
          'realm_456',
          validDeviceInfo,
          validAttestation,
          `public_key_${i}`
        );
      }

      // Try to register one more
      const result = await registerBiometricDevice(
        'user_max',
        'realm_456',
        validDeviceInfo,
        validAttestation,
        'public_key_extra'
      );

      expect(result.device).toBeUndefined();
      expect(result.errorCode).toBe(BiometricErrorCode.MAX_DEVICES_REACHED);
    });

    it('should reject registration with invalid attestation format', async () => {
      const invalidAttestation: DeviceAttestation = {
        ...validAttestation,
        format: 'android-key-attestation', // Wrong format for iOS
      };

      const result = await registerBiometricDevice(
        'user_123',
        'realm_456',
        validDeviceInfo,
        invalidAttestation,
        'public_key_data'
      );

      expect(result.device).toBeUndefined();
      expect(result.errorCode).toBe(BiometricErrorCode.ATTESTATION_FAILED);
    });

    it('should reject iOS registration without secure enclave', async () => {
      const weakAttestation: DeviceAttestation = {
        ...validAttestation,
        securityLevel: 'software',
      };

      const result = await registerBiometricDevice(
        'user_123',
        'realm_456',
        validDeviceInfo,
        weakAttestation,
        'public_key_data'
      );

      expect(result.device).toBeUndefined();
      expect(result.errorCode).toBe(BiometricErrorCode.ATTESTATION_FAILED);
    });

    describe('Android Registration', () => {
      const androidDeviceInfo: BiometricDeviceInfo = {
        platform: BiometricPlatform.ANDROID,
        model: 'Pixel 8 Pro',
        osVersion: '14',
        biometricTypes: [BiometricType.FINGERPRINT],
        secureEnclaveAvailable: true,
        strongBoxAvailable: true,
      };

      const androidAttestation: DeviceAttestation = {
        format: 'android-key-attestation',
        attestationData: 'valid_android_attestation',
        certificateChain: ['MIICpDCCAYwCCQDU+pQ4P6gB8jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Q='],
        verified: false,
        securityLevel: 'strongbox',
      };

      it('should register Android device with StrongBox', async () => {
        const result = await registerBiometricDevice(
          'user_android',
          'realm_456',
          androidDeviceInfo,
          androidAttestation,
          'android_public_key'
        );

        expect(result.device).toBeDefined();
        expect(result.device?.platform).toBe(BiometricPlatform.ANDROID);
        expect(result.device?.attestation.securityLevel).toBe('strongbox');
      });

      it('should register Android device with TEE', async () => {
        const teeAttestation: DeviceAttestation = {
          ...androidAttestation,
          securityLevel: 'tee',
        };

        const result = await registerBiometricDevice(
          'user_android_tee',
          'realm_456',
          androidDeviceInfo,
          teeAttestation,
          'android_public_key'
        );

        expect(result.device).toBeDefined();
        expect(result.device?.attestation.securityLevel).toBe('tee');
      });

      it('should reject Android with software security', async () => {
        const softwareAttestation: DeviceAttestation = {
          ...androidAttestation,
          securityLevel: 'software',
        };

        const result = await registerBiometricDevice(
          'user_android_soft',
          'realm_456',
          androidDeviceInfo,
          softwareAttestation,
          'android_public_key'
        );

        expect(result.device).toBeUndefined();
        expect(result.errorCode).toBe(BiometricErrorCode.ATTESTATION_FAILED);
      });
    });
  });


  // ============================================
  // Device Management Tests
  // ============================================

  describe('Device Management', () => {
    let testDevice: BiometricDevice;

    beforeEach(async () => {
      const result = await registerBiometricDevice(
        'user_mgmt',
        'realm_456',
        {
          platform: BiometricPlatform.IOS,
          model: 'iPhone 15',
          osVersion: '17.0',
          biometricTypes: [BiometricType.FACE_ID],
          secureEnclaveAvailable: true,
        },
        {
          format: 'ios-app-attest',
          attestationData: 'test_attestation',
          verified: false,
          securityLevel: 'secure_enclave',
        },
        'test_public_key'
      );
      testDevice = result.device!;
    });

    describe('listBiometricDevices', () => {
      it('should list all devices for a user', () => {
        const devices = listBiometricDevices('user_mgmt');

        expect(devices.length).toBe(1);
        expect(devices[0].id).toBe(testDevice.id);
      });

      it('should filter by realm', async () => {
        // Register device in different realm
        await registerBiometricDevice(
          'user_mgmt',
          'realm_other',
          {
            platform: BiometricPlatform.ANDROID,
            model: 'Pixel 8',
            osVersion: '14',
            biometricTypes: [BiometricType.FINGERPRINT],
            secureEnclaveAvailable: true,
          },
          {
            format: 'android-key-attestation',
            attestationData: 'test_attestation',
            certificateChain: ['MIICpDCCAYwCCQDU+pQ4P6gB8jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Q='],
            verified: false,
            securityLevel: 'tee',
          },
          'android_key'
        );

        const allDevices = listBiometricDevices('user_mgmt');
        const realmDevices = listBiometricDevices('user_mgmt', 'realm_456');

        expect(allDevices.length).toBe(2);
        expect(realmDevices.length).toBe(1);
        expect(realmDevices[0].realmId).toBe('realm_456');
      });

      it('should not list revoked devices', () => {
        revokeBiometricDevice('user_mgmt', testDevice.id);

        const devices = listBiometricDevices('user_mgmt');

        expect(devices.length).toBe(0);
      });

      it('should sort by creation date (newest first)', async () => {
        // Register another device
        await registerBiometricDevice(
          'user_mgmt',
          'realm_456',
          {
            platform: BiometricPlatform.IOS,
            model: 'iPad Pro',
            osVersion: '17.0',
            biometricTypes: [BiometricType.TOUCH_ID],
            secureEnclaveAvailable: true,
          },
          {
            format: 'ios-app-attest',
            attestationData: 'test_attestation_2',
            verified: false,
            securityLevel: 'secure_enclave',
          },
          'ipad_key'
        );

        const devices = listBiometricDevices('user_mgmt');

        expect(devices.length).toBe(2);
        expect(new Date(devices[0].createdAt).getTime())
          .toBeGreaterThanOrEqual(new Date(devices[1].createdAt).getTime());
      });
    });

    describe('getBiometricDevice', () => {
      it('should get device by ID', () => {
        const device = getBiometricDevice(testDevice.id);

        expect(device).toBeDefined();
        expect(device?.id).toBe(testDevice.id);
      });

      it('should return undefined for non-existent device', () => {
        const device = getBiometricDevice('non_existent');

        expect(device).toBeUndefined();
      });
    });

    describe('getBiometricDeviceByKeyId', () => {
      it('should get device by key ID', () => {
        const device = getBiometricDeviceByKeyId(testDevice.keyId);

        expect(device).toBeDefined();
        expect(device?.keyId).toBe(testDevice.keyId);
      });

      it('should not return revoked device', () => {
        revokeBiometricDevice('user_mgmt', testDevice.id);

        const device = getBiometricDeviceByKeyId(testDevice.keyId);

        expect(device).toBeUndefined();
      });
    });

    describe('revokeBiometricDevice', () => {
      it('should revoke device successfully', () => {
        const result = revokeBiometricDevice('user_mgmt', testDevice.id);

        expect(result.success).toBe(true);

        const device = getBiometricDevice(testDevice.id);
        expect(device?.status).toBe('revoked');
      });

      it('should fail for non-existent device', () => {
        const result = revokeBiometricDevice('user_mgmt', 'non_existent');

        expect(result.success).toBe(false);
        expect(result.errorCode).toBe(BiometricErrorCode.DEVICE_NOT_FOUND);
      });

      it('should fail for wrong user', () => {
        const result = revokeBiometricDevice('other_user', testDevice.id);

        expect(result.success).toBe(false);
        expect(result.errorCode).toBe(BiometricErrorCode.DEVICE_NOT_FOUND);
      });

      it('should fail for already revoked device', () => {
        revokeBiometricDevice('user_mgmt', testDevice.id);
        const result = revokeBiometricDevice('user_mgmt', testDevice.id);

        expect(result.success).toBe(false);
        expect(result.errorCode).toBe(BiometricErrorCode.DEVICE_REVOKED);
      });
    });

    describe('suspendBiometricDevice', () => {
      it('should suspend device successfully', () => {
        const result = suspendBiometricDevice('user_mgmt', testDevice.id);

        expect(result.success).toBe(true);

        const device = getBiometricDevice(testDevice.id);
        expect(device?.status).toBe('suspended');
      });

      it('should fail for revoked device', () => {
        revokeBiometricDevice('user_mgmt', testDevice.id);
        const result = suspendBiometricDevice('user_mgmt', testDevice.id);

        expect(result.success).toBe(false);
        expect(result.errorCode).toBe(BiometricErrorCode.DEVICE_REVOKED);
      });
    });

    describe('reactivateBiometricDevice', () => {
      it('should reactivate suspended device', () => {
        suspendBiometricDevice('user_mgmt', testDevice.id);
        const result = reactivateBiometricDevice('user_mgmt', testDevice.id);

        expect(result.success).toBe(true);

        const device = getBiometricDevice(testDevice.id);
        expect(device?.status).toBe('active');
      });

      it('should fail for revoked device', () => {
        revokeBiometricDevice('user_mgmt', testDevice.id);
        const result = reactivateBiometricDevice('user_mgmt', testDevice.id);

        expect(result.success).toBe(false);
        expect(result.errorCode).toBe(BiometricErrorCode.DEVICE_REVOKED);
      });
    });

    describe('updateDeviceUsage', () => {
      it('should update last used timestamp and count', () => {
        const initialCount = testDevice.usageCount;

        updateDeviceUsage(testDevice.id);

        const device = getBiometricDevice(testDevice.id);
        expect(device?.usageCount).toBe(initialCount + 1);
        expect(device?.lastUsedAt).toBeDefined();
      });
    });

    describe('trustBiometricDevice', () => {
      it('should trust device', () => {
        const result = trustBiometricDevice('user_mgmt', testDevice.id, true);

        expect(result.success).toBe(true);

        const device = getBiometricDevice(testDevice.id);
        expect(device?.trusted).toBe(true);
      });

      it('should untrust device', () => {
        trustBiometricDevice('user_mgmt', testDevice.id, true);
        const result = trustBiometricDevice('user_mgmt', testDevice.id, false);

        expect(result.success).toBe(true);

        const device = getBiometricDevice(testDevice.id);
        expect(device?.trusted).toBe(false);
      });
    });
  });


  // ============================================
  // Utility Function Tests
  // ============================================

  describe('Utility Functions', () => {
    describe('isBiometricAvailable', () => {
      it('should return true for device with biometrics and secure enclave', () => {
        const deviceInfo: BiometricDeviceInfo = {
          platform: BiometricPlatform.IOS,
          model: 'iPhone 15',
          osVersion: '17.0',
          biometricTypes: [BiometricType.FACE_ID],
          secureEnclaveAvailable: true,
        };

        expect(isBiometricAvailable(deviceInfo)).toBe(true);
      });

      it('should return false without biometric types', () => {
        const deviceInfo: BiometricDeviceInfo = {
          platform: BiometricPlatform.IOS,
          model: 'iPhone 15',
          osVersion: '17.0',
          biometricTypes: [],
          secureEnclaveAvailable: true,
        };

        expect(isBiometricAvailable(deviceInfo)).toBe(false);
      });

      it('should return false without secure enclave', () => {
        const deviceInfo: BiometricDeviceInfo = {
          platform: BiometricPlatform.IOS,
          model: 'iPhone 15',
          osVersion: '17.0',
          biometricTypes: [BiometricType.FACE_ID],
          secureEnclaveAvailable: false,
        };

        expect(isBiometricAvailable(deviceInfo)).toBe(false);
      });
    });

    describe('getRecommendedBiometricType', () => {
      it('should recommend Face ID for iOS', () => {
        expect(getRecommendedBiometricType(BiometricPlatform.IOS)).toBe(BiometricType.FACE_ID);
      });

      it('should recommend Fingerprint for Android', () => {
        expect(getRecommendedBiometricType(BiometricPlatform.ANDROID)).toBe(BiometricType.FINGERPRINT);
      });

      it('should recommend Fingerprint for Web', () => {
        expect(getRecommendedBiometricType(BiometricPlatform.WEB)).toBe(BiometricType.FINGERPRINT);
      });
    });

    describe('validateDeviceInfo', () => {
      it('should validate complete device info', () => {
        const deviceInfo: BiometricDeviceInfo = {
          platform: BiometricPlatform.IOS,
          model: 'iPhone 15',
          osVersion: '17.0',
          biometricTypes: [BiometricType.FACE_ID],
          secureEnclaveAvailable: true,
        };

        const result = validateDeviceInfo(deviceInfo);

        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject missing platform', () => {
        const deviceInfo = {
          model: 'iPhone 15',
          osVersion: '17.0',
          biometricTypes: [BiometricType.FACE_ID],
          secureEnclaveAvailable: true,
        } as BiometricDeviceInfo;

        const result = validateDeviceInfo(deviceInfo);

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Platform is required');
      });

      it('should reject missing model', () => {
        const deviceInfo = {
          platform: BiometricPlatform.IOS,
          osVersion: '17.0',
          biometricTypes: [BiometricType.FACE_ID],
          secureEnclaveAvailable: true,
        } as BiometricDeviceInfo;

        const result = validateDeviceInfo(deviceInfo);

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Device model is required');
      });

      it('should reject empty biometric types', () => {
        const deviceInfo: BiometricDeviceInfo = {
          platform: BiometricPlatform.IOS,
          model: 'iPhone 15',
          osVersion: '17.0',
          biometricTypes: [],
          secureEnclaveAvailable: true,
        };

        const result = validateDeviceInfo(deviceInfo);

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('At least one biometric type is required');
      });

      it('should reject without secure enclave', () => {
        const deviceInfo: BiometricDeviceInfo = {
          platform: BiometricPlatform.IOS,
          model: 'iPhone 15',
          osVersion: '17.0',
          biometricTypes: [BiometricType.FACE_ID],
          secureEnclaveAvailable: false,
        };

        const result = validateDeviceInfo(deviceInfo);

        expect(result.valid).toBe(false);
        expect(result.errors).toContain('Secure enclave/TEE is required for biometric authentication');
      });
    });

    describe('getBiometricStrength', () => {
      it('should return STRONG for secure enclave', async () => {
        const result = await registerBiometricDevice(
          'user_strength',
          'realm_456',
          {
            platform: BiometricPlatform.IOS,
            model: 'iPhone 15',
            osVersion: '17.0',
            biometricTypes: [BiometricType.FACE_ID],
            secureEnclaveAvailable: true,
          },
          {
            format: 'ios-app-attest',
            attestationData: 'test',
            verified: false,
            securityLevel: 'secure_enclave',
          },
          'key'
        );

        expect(getBiometricStrength(result.device!)).toBe(BiometricStrength.STRONG);
      });

      it('should return STRONG for StrongBox', async () => {
        const result = await registerBiometricDevice(
          'user_strongbox',
          'realm_456',
          {
            platform: BiometricPlatform.ANDROID,
            model: 'Pixel 8',
            osVersion: '14',
            biometricTypes: [BiometricType.FINGERPRINT],
            secureEnclaveAvailable: true,
          },
          {
            format: 'android-key-attestation',
            attestationData: 'test',
            certificateChain: ['MIICpDCCAYwCCQDU+pQ4P6gB8jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Q='],
            verified: false,
            securityLevel: 'strongbox',
          },
          'key'
        );

        expect(getBiometricStrength(result.device!)).toBe(BiometricStrength.STRONG);
      });

      it('should return STRONG for TEE', async () => {
        const result = await registerBiometricDevice(
          'user_tee',
          'realm_456',
          {
            platform: BiometricPlatform.ANDROID,
            model: 'Pixel 8',
            osVersion: '14',
            biometricTypes: [BiometricType.FINGERPRINT],
            secureEnclaveAvailable: true,
          },
          {
            format: 'android-key-attestation',
            attestationData: 'test',
            certificateChain: ['MIICpDCCAYwCCQDU+pQ4P6gB8jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Q='],
            verified: false,
            securityLevel: 'tee',
          },
          'key'
        );

        expect(getBiometricStrength(result.device!)).toBe(BiometricStrength.STRONG);
      });
    });

    describe('meetsSecurityRequirements', () => {
      it('should pass WEAK requirement for any device', async () => {
        const result = await registerBiometricDevice(
          'user_req',
          'realm_456',
          {
            platform: BiometricPlatform.IOS,
            model: 'iPhone 15',
            osVersion: '17.0',
            biometricTypes: [BiometricType.FACE_ID],
            secureEnclaveAvailable: true,
          },
          {
            format: 'ios-app-attest',
            attestationData: 'test',
            verified: false,
            securityLevel: 'secure_enclave',
          },
          'key'
        );

        expect(meetsSecurityRequirements(result.device!, BiometricStrength.WEAK)).toBe(true);
      });

      it('should pass STRONG requirement for secure enclave device', async () => {
        const result = await registerBiometricDevice(
          'user_req_strong',
          'realm_456',
          {
            platform: BiometricPlatform.IOS,
            model: 'iPhone 15',
            osVersion: '17.0',
            biometricTypes: [BiometricType.FACE_ID],
            secureEnclaveAvailable: true,
          },
          {
            format: 'ios-app-attest',
            attestationData: 'test',
            verified: false,
            securityLevel: 'secure_enclave',
          },
          'key'
        );

        expect(meetsSecurityRequirements(result.device!, BiometricStrength.STRONG)).toBe(true);
      });
    });
  });


  // ============================================
  // Integration Tests
  // ============================================

  describe('Integration Tests', () => {
    describe('Full iOS Biometric Flow', () => {
      it('should complete full iOS biometric authentication flow', async () => {
        // 1. Register device
        const deviceInfo: BiometricDeviceInfo = {
          platform: BiometricPlatform.IOS,
          model: 'iPhone 15 Pro',
          osVersion: '17.0',
          biometricTypes: [BiometricType.FACE_ID],
          secureEnclaveAvailable: true,
          localAuthenticationVersion: '1.0',
        };

        const attestation: DeviceAttestation = {
          format: 'ios-app-attest',
          attestationData: 'valid_ios_attestation_data',
          verified: false,
          securityLevel: 'secure_enclave',
        };

        const regResult = await registerBiometricDevice(
          'user_ios_flow',
          'realm_clinisyn',
          deviceInfo,
          attestation,
          'ios_public_key'
        );

        expect(regResult.device).toBeDefined();
        const device = regResult.device!;

        // 2. Create challenge
        const challenge = createBiometricChallenge(
          'user_ios_flow',
          device.id,
          BiometricPlatform.IOS,
          true // Include liveness
        );

        expect(challenge.livenessChallenge).toBeDefined();

        // 3. Simulate biometric response
        const challengeHash = require('crypto')
          .createHash('sha256')
          .update(challenge.challenge)
          .digest();

        const mockAssertion = Buffer.concat([
          Buffer.alloc(32),
          challengeHash,
          Buffer.alloc(32),
        ]);

        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'ios_signature',
          keyId: device.keyId,
          assertion: mockAssertion.toString('base64'),
        };

        // 4. Verify response
        const verifyResult = await verifyBiometricResponse(
          challenge.id,
          response,
          device.attestation
        );

        expect(verifyResult.verified).toBe(true);

        // 5. Update device usage
        updateDeviceUsage(device.id);

        const updatedDevice = getBiometricDevice(device.id);
        expect(updatedDevice?.usageCount).toBe(1);
        expect(updatedDevice?.lastUsedAt).toBeDefined();
      });
    });

    describe('Full Android Biometric Flow', () => {
      it('should complete full Android biometric authentication flow', async () => {
        // 1. Register device
        const deviceInfo: BiometricDeviceInfo = {
          platform: BiometricPlatform.ANDROID,
          model: 'Pixel 8 Pro',
          osVersion: '14',
          biometricTypes: [BiometricType.FINGERPRINT, BiometricType.FACE_RECOGNITION],
          secureEnclaveAvailable: true,
          biometricPromptVersion: '1.2.0',
          strongBoxAvailable: true,
        };

        const attestation: DeviceAttestation = {
          format: 'android-key-attestation',
          attestationData: 'valid_android_attestation',
          certificateChain: ['MIICpDCCAYwCCQDU+pQ4P6gB8jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Q=', 'MIICpDCCAYwCCQDU+pQ4P6gB8jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Q=', 'MIICpDCCAYwCCQDU+pQ4P6gB8jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Q='],
          verified: false,
          securityLevel: 'strongbox',
        };

        const regResult = await registerBiometricDevice(
          'user_android_flow',
          'realm_clinisyn',
          deviceInfo,
          attestation,
          'android_public_key'
        );

        expect(regResult.device).toBeDefined();
        const device = regResult.device!;

        // 2. Create challenge
        const challenge = createBiometricChallenge(
          'user_android_flow',
          device.id,
          BiometricPlatform.ANDROID
        );

        // 3. Simulate biometric response
        const response: BiometricResponse = {
          challengeId: challenge.id,
          signature: 'android_signature',
          keyId: device.keyId,
          biometricSignature: Buffer.alloc(64).toString('base64'),
        };

        // 4. Verify response
        const verifyResult = await verifyBiometricResponse(
          challenge.id,
          response,
          device.attestation
        );

        expect(verifyResult.verified).toBe(true);
      });
    });

    describe('Liveness Detection Flow', () => {
      it('should complete liveness verification with active challenge', () => {
        // 1. Create challenge with liveness
        const challenge = createBiometricChallenge(
          'user_liveness',
          undefined,
          BiometricPlatform.IOS,
          true
        );

        // Force active liveness
        if (challenge.livenessChallenge) {
          challenge.livenessChallenge.method = LivenessMethod.ACTIVE;
          challenge.livenessChallenge.actions = [
            { type: 'blink' },
            { type: 'turn_head', direction: 'left' },
          ];
          challenge.livenessChallenge.expectedSequence = ['blink', 'turn_head_left'];
        }

        // 2. Simulate user completing actions
        const actionResults: ActionResult[] = [
          {
            action: { type: 'blink' },
            completed: true,
            confidence: 0.95,
            timestamp: Date.now(),
          },
          {
            action: { type: 'turn_head', direction: 'left' },
            completed: true,
            confidence: 0.92,
            timestamp: Date.now() + 2000,
          },
        ];

        const livenessData: LivenessData = {
          challengeId: challenge.id,
          method: LivenessMethod.ACTIVE,
          actionResults,
          confidence: 0.93,
          timestamp: new Date().toISOString(),
        };

        // 3. Verify liveness
        const result = verifyLiveness(challenge.id, livenessData);

        expect(result.verified).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(0.9);
      });
    });

    describe('Device Lifecycle', () => {
      it('should handle complete device lifecycle', async () => {
        const userId = 'user_lifecycle';
        const realmId = 'realm_test';

        // 1. Register device
        const regResult = await registerBiometricDevice(
          userId,
          realmId,
          {
            platform: BiometricPlatform.IOS,
            model: 'iPhone 15',
            osVersion: '17.0',
            biometricTypes: [BiometricType.FACE_ID],
            secureEnclaveAvailable: true,
          },
          {
            format: 'ios-app-attest',
            attestationData: 'test',
            verified: false,
            securityLevel: 'secure_enclave',
          },
          'key'
        );

        const device = regResult.device!;
        expect(device.status).toBe('active');
        expect(device.trusted).toBe(false);

        // 2. Trust device
        trustBiometricDevice(userId, device.id, true);
        expect(getBiometricDevice(device.id)?.trusted).toBe(true);

        // 3. Suspend device
        suspendBiometricDevice(userId, device.id);
        expect(getBiometricDevice(device.id)?.status).toBe('suspended');

        // 4. Reactivate device
        reactivateBiometricDevice(userId, device.id);
        expect(getBiometricDevice(device.id)?.status).toBe('active');

        // 5. Revoke device
        revokeBiometricDevice(userId, device.id);
        expect(getBiometricDevice(device.id)?.status).toBe('revoked');

        // 6. Device should not appear in list
        const devices = listBiometricDevices(userId);
        expect(devices.find(d => d.id === device.id)).toBeUndefined();
      });
    });
  });
});
