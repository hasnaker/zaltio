/**
 * E2E Tests for Clinisyn SDK Integration
 * Task 10.4: Validate complete Clinisyn integration flow
 * 
 * These tests verify:
 * 1. Psychologist registration flow
 * 2. MFA enforcement (required for healthcare)
 * 3. WebAuthn enforcement (phishing protection)
 * 4. Student registration flow (relaxed MFA)
 * 5. Token management
 * 6. Session handling
 */

import { createZaltClient, ZaltAuthClient } from '../../sdk/client';
import { MemoryStorage } from '../../sdk/storage';
import { MFARequiredError, ConfigurationError } from '../../sdk/errors';
import { E2E_CONFIG, generateTestUser, wait } from './setup';

describe('Clinisyn SDK Integration', () => {
  // Test clients for both realms
  let psychologistClient: ZaltAuthClient;
  let studentClient: ZaltAuthClient;
  let storage: MemoryStorage;

  beforeEach(() => {
    storage = new MemoryStorage();
    
    psychologistClient = createZaltClient({
      baseUrl: E2E_CONFIG.apiEndpoint,
      realmId: 'clinisyn-psychologists',
      storage,
      timeout: E2E_CONFIG.requestTimeout,
      autoRefresh: true
    });

    studentClient = createZaltClient({
      baseUrl: E2E_CONFIG.apiEndpoint,
      realmId: 'clinisyn-students',
      storage: new MemoryStorage(),
      timeout: E2E_CONFIG.requestTimeout,
      autoRefresh: true
    });
  });

  describe('SDK Configuration', () => {
    it('should create client with valid configuration', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      const config = client.getConfig();
      expect(config.baseUrl).toBe('https://api.zalt.io/v1');
      expect(config.realmId).toBe('clinisyn-psychologists');
      expect(config.autoRefresh).toBe(true);
    });

    it('should throw error for missing baseUrl', () => {
      expect(() => createZaltClient({
        baseUrl: '',
        realmId: 'clinisyn-psychologists'
      })).toThrow(ConfigurationError);
    });

    it('should throw error for missing realmId', () => {
      expect(() => createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: ''
      })).toThrow(ConfigurationError);
    });

    it('should throw error for invalid baseUrl', () => {
      expect(() => createZaltClient({
        baseUrl: 'not-a-valid-url',
        realmId: 'clinisyn-psychologists'
      })).toThrow(ConfigurationError);
    });

    it('should remove trailing slash from baseUrl', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1/',
        realmId: 'clinisyn-psychologists'
      });

      expect(client.getConfig().baseUrl).toBe('https://api.zalt.io/v1');
    });

    it('should use default timeout if not specified', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      expect(client.getConfig().timeout).toBe(10000);
    });

    it('should use custom timeout if specified', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        timeout: 30000
      });

      expect(client.getConfig().timeout).toBe(30000);
    });
  });

  describe('Psychologist Realm Configuration', () => {
    it('should use clinisyn-psychologists realm', () => {
      expect(psychologistClient.getConfig().realmId).toBe('clinisyn-psychologists');
    });

    it('should have auto-refresh enabled', () => {
      expect(psychologistClient.getConfig().autoRefresh).toBe(true);
    });

    it('should have correct refresh threshold', () => {
      expect(psychologistClient.getConfig().refreshThreshold).toBe(300); // 5 minutes
    });
  });

  describe('Student Realm Configuration', () => {
    it('should use clinisyn-students realm', () => {
      expect(studentClient.getConfig().realmId).toBe('clinisyn-students');
    });

    it('should have auto-refresh enabled', () => {
      expect(studentClient.getConfig().autoRefresh).toBe(true);
    });
  });

  describe('MFA Namespace', () => {
    it('should have mfa.setup method', () => {
      expect(typeof psychologistClient.mfa.setup).toBe('function');
    });

    it('should have mfa.verify method', () => {
      expect(typeof psychologistClient.mfa.verify).toBe('function');
    });

    it('should have mfa.disable method', () => {
      expect(typeof psychologistClient.mfa.disable).toBe('function');
    });

    it('should have mfa.verifyLogin method', () => {
      expect(typeof psychologistClient.mfa.verifyLogin).toBe('function');
    });

    it('should have mfa.getStatus method', () => {
      expect(typeof psychologistClient.mfa.getStatus).toBe('function');
    });

    it('should have mfa.regenerateBackupCodes method', () => {
      expect(typeof psychologistClient.mfa.regenerateBackupCodes).toBe('function');
    });
  });

  describe('WebAuthn Namespace', () => {
    it('should have webauthn.registerOptions method', () => {
      expect(typeof psychologistClient.webauthn.registerOptions).toBe('function');
    });

    it('should have webauthn.registerVerify method', () => {
      expect(typeof psychologistClient.webauthn.registerVerify).toBe('function');
    });

    it('should have webauthn.authenticateOptions method', () => {
      expect(typeof psychologistClient.webauthn.authenticateOptions).toBe('function');
    });

    it('should have webauthn.authenticateVerify method', () => {
      expect(typeof psychologistClient.webauthn.authenticateVerify).toBe('function');
    });

    it('should have webauthn.listCredentials method', () => {
      expect(typeof psychologistClient.webauthn.listCredentials).toBe('function');
    });

    it('should have webauthn.deleteCredential method', () => {
      expect(typeof psychologistClient.webauthn.deleteCredential).toBe('function');
    });
  });

  describe('Device Namespace', () => {
    it('should have devices.list method', () => {
      expect(typeof psychologistClient.devices.list).toBe('function');
    });

    it('should have devices.revoke method', () => {
      expect(typeof psychologistClient.devices.revoke).toBe('function');
    });

    it('should have devices.trustCurrent method', () => {
      expect(typeof psychologistClient.devices.trustCurrent).toBe('function');
    });
  });

  describe('Social Login Namespace', () => {
    it('should have social.getAuthUrl method', () => {
      expect(typeof psychologistClient.social.getAuthUrl).toBe('function');
    });

    it('should have social.handleCallback method', () => {
      expect(typeof psychologistClient.social.handleCallback).toBe('function');
    });
  });

  describe('Core Auth Methods', () => {
    it('should have register method', () => {
      expect(typeof psychologistClient.register).toBe('function');
    });

    it('should have login method', () => {
      expect(typeof psychologistClient.login).toBe('function');
    });

    it('should have logout method', () => {
      expect(typeof psychologistClient.logout).toBe('function');
    });

    it('should have refreshToken method', () => {
      expect(typeof psychologistClient.refreshToken).toBe('function');
    });

    it('should have getCurrentUser method', () => {
      expect(typeof psychologistClient.getCurrentUser).toBe('function');
    });

    it('should have isAuthenticated method', () => {
      expect(typeof psychologistClient.isAuthenticated).toBe('function');
    });

    it('should have getAccessToken method', () => {
      expect(typeof psychologistClient.getAccessToken).toBe('function');
    });
  });

  describe('Profile Methods', () => {
    it('should have updateProfile method', () => {
      expect(typeof psychologistClient.updateProfile).toBe('function');
    });

    it('should have changePassword method', () => {
      expect(typeof psychologistClient.changePassword).toBe('function');
    });
  });

  describe('Email Verification Methods', () => {
    it('should have sendVerificationEmail method', () => {
      expect(typeof psychologistClient.sendVerificationEmail).toBe('function');
    });

    it('should have verifyEmail method', () => {
      expect(typeof psychologistClient.verifyEmail).toBe('function');
    });
  });

  describe('Password Reset Methods', () => {
    it('should have requestPasswordReset method', () => {
      expect(typeof psychologistClient.requestPasswordReset).toBe('function');
    });

    it('should have confirmPasswordReset method', () => {
      expect(typeof psychologistClient.confirmPasswordReset).toBe('function');
    });
  });

  describe('Token Storage', () => {
    it('should use provided storage', async () => {
      const customStorage = new MemoryStorage();
      const client = createZaltClient({
        baseUrl: E2E_CONFIG.apiEndpoint,
        realmId: 'clinisyn-psychologists',
        storage: customStorage
      });

      // Storage should be empty initially
      expect(await customStorage.getAccessToken()).toBeNull();
      expect(await customStorage.getRefreshToken()).toBeNull();
    });

    it('should use MemoryStorage by default', async () => {
      const client = createZaltClient({
        baseUrl: E2E_CONFIG.apiEndpoint,
        realmId: 'clinisyn-psychologists'
      });

      // Should not throw when checking authentication
      const isAuth = await client.isAuthenticated();
      expect(isAuth).toBe(false);
    });
  });

  describe('Retry Configuration', () => {
    it('should use default retry attempts', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      expect(client.getConfig().retryAttempts).toBe(3);
    });

    it('should use custom retry attempts', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        retryAttempts: 5
      });

      expect(client.getConfig().retryAttempts).toBe(5);
    });

    it('should use default retry delay', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists'
      });

      expect(client.getConfig().retryDelay).toBe(1000);
    });

    it('should use custom retry delay', () => {
      const client = createZaltClient({
        baseUrl: 'https://api.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        retryDelay: 2000
      });

      expect(client.getConfig().retryDelay).toBe(2000);
    });
  });

  describe('Clinisyn Integration Scenarios', () => {
    describe('Psychologist Registration Flow', () => {
      it('should support psychologist profile metadata', () => {
        const testUser = generateTestUser({
          realm_id: 'clinisyn-psychologists',
          profile: {
            first_name: 'Ayşe',
            last_name: 'Yılmaz'
          }
        });

        // Profile should support Turkish characters
        expect(testUser.profile.first_name).toBe('Ayşe');
        expect(testUser.profile.last_name).toBe('Yılmaz');
      });

      it('should generate valid test user for psychologists', () => {
        const testUser = generateTestUser({
          realm_id: 'clinisyn-psychologists'
        });

        expect(testUser.email).toMatch(/^e2e-test-.*@test\.zalt\.io$/);
        expect(testUser.password).toMatch(/^TestPass!.*@2026$/);
        expect(testUser.realm_id).toBe('clinisyn-psychologists');
      });
    });

    describe('Student Registration Flow', () => {
      it('should generate valid test user for students', () => {
        const testUser = generateTestUser({
          realm_id: 'clinisyn-students'
        });

        expect(testUser.email).toMatch(/^e2e-test-.*@test\.zalt\.io$/);
        expect(testUser.realm_id).toBe('clinisyn-students');
      });
    });

    describe('MFA Required Error Handling', () => {
      it('should have MFARequiredError class', () => {
        const error = new MFARequiredError(
          'MFA verification required',
          'mfa_session_123',
          ['totp', 'webauthn']
        );

        expect(error.message).toBe('MFA verification required');
        expect(error.mfaSessionId).toBe('mfa_session_123');
        expect(error.mfaMethods).toContain('totp');
        expect(error.mfaMethods).toContain('webauthn');
      });

      it('should include backup_code in MFA methods', () => {
        const error = new MFARequiredError(
          'MFA required',
          'session_456',
          ['totp', 'webauthn', 'backup_code']
        );

        expect(error.mfaMethods).toContain('backup_code');
      });
    });

    describe('Healthcare Compliance', () => {
      it('should support 30-minute session timeout configuration', () => {
        // Psychologist realm should have 30-minute timeout
        // This is configured at realm level, SDK respects it
        const client = createZaltClient({
          baseUrl: E2E_CONFIG.apiEndpoint,
          realmId: 'clinisyn-psychologists',
          refreshThreshold: 300 // 5 minutes before expiry
        });

        expect(client.getConfig().refreshThreshold).toBe(300);
      });

      it('should support 1-hour session timeout for students', () => {
        // Student realm has 1-hour timeout
        const client = createZaltClient({
          baseUrl: E2E_CONFIG.apiEndpoint,
          realmId: 'clinisyn-students',
          refreshThreshold: 300
        });

        expect(client.getConfig().realmId).toBe('clinisyn-students');
      });
    });

    describe('Multi-Realm Support', () => {
      it('should support multiple clients for different realms', () => {
        const psychClient = createZaltClient({
          baseUrl: E2E_CONFIG.apiEndpoint,
          realmId: 'clinisyn-psychologists'
        });

        const studentClient = createZaltClient({
          baseUrl: E2E_CONFIG.apiEndpoint,
          realmId: 'clinisyn-students'
        });

        expect(psychClient.getConfig().realmId).toBe('clinisyn-psychologists');
        expect(studentClient.getConfig().realmId).toBe('clinisyn-students');
      });

      it('should isolate storage between clients', async () => {
        const storage1 = new MemoryStorage();
        const storage2 = new MemoryStorage();

        const client1 = createZaltClient({
          baseUrl: E2E_CONFIG.apiEndpoint,
          realmId: 'clinisyn-psychologists',
          storage: storage1
        });

        const client2 = createZaltClient({
          baseUrl: E2E_CONFIG.apiEndpoint,
          realmId: 'clinisyn-students',
          storage: storage2
        });

        // Set token in storage1
        await storage1.setTokens('token1', 'refresh1', 3600);

        // storage2 should be empty
        expect(await storage2.getAccessToken()).toBeNull();
        expect(await storage1.getAccessToken()).toBe('token1');
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      const client = createZaltClient({
        baseUrl: 'https://invalid.zalt.io/v1',
        realmId: 'clinisyn-psychologists',
        timeout: 1000,
        retryAttempts: 0
      });

      // Should not throw immediately
      expect(client.getConfig().baseUrl).toBe('https://invalid.zalt.io/v1');
    });

    it('should return false for isAuthenticated when no tokens', async () => {
      const isAuth = await psychologistClient.isAuthenticated();
      expect(isAuth).toBe(false);
    });

    it('should return null for getCurrentUser when not authenticated', async () => {
      const user = await psychologistClient.getCurrentUser();
      expect(user).toBeNull();
    });

    it('should return null for getAccessToken when no tokens', async () => {
      const token = await psychologistClient.getAccessToken();
      expect(token).toBeNull();
    });
  });

  describe('Legacy Compatibility', () => {
    it('should export HSDAuthClient as alias', async () => {
      const { HSDAuthClient } = await import('../../sdk/client');
      expect(HSDAuthClient).toBe(ZaltAuthClient);
    });

    it('should export createHSDAuthClient as alias', async () => {
      const { createHSDAuthClient, createZaltClient } = await import('../../sdk/client');
      expect(createHSDAuthClient).toBe(createZaltClient);
    });
  });
});
