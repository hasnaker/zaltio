/**
 * Realm Service Tests - Multi-tenant Management
 * Task 9.1: Realm Service CRUD + Cross-realm Isolation
 */

import * as fc from 'fast-check';
import {
  createRealm,
  getRealm,
  updateRealm,
  deleteRealmWithCleanup,
  listRealms,
  getRealmStats,
  validateCrossRealmAccess,
  validateUserInRealm,
  validateSessionInRealm,
  isHealthcareRealm,
  getEffectiveMfaConfig,
  checkMfaEnforcement,
  checkMfaSetupRequired,
  validateMfaMethod,
  getRememberDeviceDuration
} from './realm.service';
import * as realmRepo from '../repositories/realm.repository';
import { dynamoDb } from './dynamodb.service';
import { Realm, DEFAULT_REALM_SETTINGS, HEALTHCARE_MFA_CONFIG } from '../models/realm.model';

// Mock dependencies
jest.mock('../repositories/realm.repository');
jest.mock('./dynamodb.service', () => ({
  dynamoDb: { send: jest.fn() },
  TableNames: {
    USERS: 'zalt-users',
    SESSIONS: 'zalt-sessions',
    DEVICES: 'zalt-devices',
    REALMS: 'zalt-realms'
  }
}));

const mockRealmRepo = realmRepo as jest.Mocked<typeof realmRepo>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const mockDynamoDb = dynamoDb as any;


// Test data generators
const realmNameArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'),
  { minLength: 3, maxLength: 20 }
).map(s => `test-${s}`);

const domainArb = fc.tuple(
  fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'), { minLength: 3, maxLength: 10 }),
  fc.constantFrom('com', 'io', 'org', 'net')
).map(([name, tld]) => `${name}.${tld}`);

const createMockRealm = (id: string, overrides: Partial<Realm> = {}): Realm => ({
  id,
  name: overrides.name || id,
  domain: overrides.domain || `${id}.example.com`,
  settings: overrides.settings || DEFAULT_REALM_SETTINGS,
  auth_providers: overrides.auth_providers || [{ type: 'email_password', enabled: true, config: {} }],
  created_at: overrides.created_at || new Date().toISOString(),
  updated_at: overrides.updated_at || new Date().toISOString()
});

describe('Realm Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('createRealm', () => {
    it('should create realm with valid input', async () => {
      const mockRealm = createMockRealm('test-realm');
      mockRealmRepo.realmExistsByName.mockResolvedValue(false);
      mockRealmRepo.createRealm.mockResolvedValue(mockRealm);

      const result = await createRealm({
        name: 'test-realm',  // Valid format: starts with letter, alphanumeric + hyphens
        domain: 'test.example.com'
      });

      if (!result.success) {
        console.log('Create realm error:', result.error);
      }
      expect(result.success).toBe(true);
      expect(result.realm).toBeDefined();
    });

    it('should reject realm name shorter than 3 characters', async () => {
      const result = await createRealm({
        name: 'ab',
        domain: 'test.example.com'
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('between 3 and 50 characters');
    });

    it('should reject realm name longer than 50 characters', async () => {
      const result = await createRealm({
        name: 'a'.repeat(51),
        domain: 'test.example.com'
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('between 3 and 50 characters');
    });


    it('should reject realm name with invalid characters', async () => {
      const result = await createRealm({
        name: 'test realm!',
        domain: 'test.example.com'
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('letters, numbers, and hyphens');
    });

    it('should reject duplicate realm name', async () => {
      mockRealmRepo.realmExistsByName.mockResolvedValue(true);

      const result = await createRealm({
        name: 'existing-realm',
        domain: 'test.example.com'
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('already exists');
    });

    it('should reject invalid domain format', async () => {
      mockRealmRepo.realmExistsByName.mockResolvedValue(false);

      const result = await createRealm({
        name: 'test-realm',
        domain: 'invalid-domain'
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid domain format');
    });

    it('should apply healthcare MFA config for healthcare realms', async () => {
      const mockRealm = createMockRealm('clinisyn-psychologists');
      mockRealmRepo.realmExistsByName.mockResolvedValue(false);
      mockRealmRepo.createRealm.mockResolvedValue(mockRealm);

      await createRealm({
        name: 'clinisyn-psychologists',
        domain: 'clinisyn.com'
      });

      expect(mockRealmRepo.createRealm).toHaveBeenCalledWith(
        expect.objectContaining({
          settings: expect.objectContaining({
            mfa_config: expect.objectContaining({
              policy: 'required'
            })
          })
        })
      );
    });

    it('should handle property-based realm creation', async () => {
      await fc.assert(
        fc.asyncProperty(realmNameArb, domainArb, async (name, domain) => {
          mockRealmRepo.realmExistsByName.mockResolvedValue(false);
          mockRealmRepo.createRealm.mockResolvedValue(createMockRealm(name));

          const result = await createRealm({ name, domain });
          
          // Should succeed for valid inputs
          expect(result.success).toBe(true);
          return true;
        }),
        { numRuns: 20 }
      );
    });
  });


  describe('getRealm', () => {
    it('should return realm when found', async () => {
      const mockRealm = createMockRealm('test-realm');
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);

      const result = await getRealm('test-realm');

      expect(result).toEqual(mockRealm);
    });

    it('should return null when realm not found', async () => {
      mockRealmRepo.findRealmById.mockResolvedValue(null);

      const result = await getRealm('non-existent');

      expect(result).toBeNull();
    });

    it('should return null for invalid realm ID', async () => {
      const result = await getRealm('ab');

      expect(result).toBeNull();
      expect(mockRealmRepo.findRealmById).not.toHaveBeenCalled();
    });
  });

  describe('updateRealm', () => {
    it('should update realm successfully', async () => {
      const mockRealm = createMockRealm('test-realm');
      const updatedRealm = { ...mockRealm, domain: 'newdomain.example.com' };
      
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);
      mockRealmRepo.updateRealm.mockResolvedValue(updatedRealm);

      const result = await updateRealm('test-realm', { domain: 'newdomain.example.com' });

      expect(result.success).toBe(true);
      expect(result.realm?.domain).toBe('newdomain.example.com');
    });

    it('should return error when realm not found', async () => {
      mockRealmRepo.findRealmById.mockResolvedValue(null);

      const result = await updateRealm('non-existent', { domain: 'new.example.com' });

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should reject invalid domain format', async () => {
      const mockRealm = createMockRealm('test-realm');
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);

      const result = await updateRealm('test-realm', { domain: 'invalid' });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Invalid domain format');
    });

    it('should prevent healthcare realms from disabling MFA', async () => {
      const mockRealm = createMockRealm('clinisyn-psychologists');
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);

      const result = await updateRealm('clinisyn-psychologists', {
        settings: { mfa_config: { policy: 'disabled' } as any }
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('HIPAA compliance');
    });

    it('should reject remember_device_days > 30', async () => {
      const mockRealm = createMockRealm('test-realm');
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);

      const result = await updateRealm('test-realm', {
        settings: { mfa_config: { remember_device_days: 31 } as any }
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('between 0 and 30');
    });
  });


  describe('deleteRealmWithCleanup', () => {
    it('should delete realm and all associated data', async () => {
      const mockRealm = createMockRealm('test-realm');
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);
      mockRealmRepo.deleteRealm.mockResolvedValue(true);
      
      // Mock scan for users, sessions, devices
      mockDynamoDb.send.mockResolvedValue({ Items: [], Count: 0 });

      const result = await deleteRealmWithCleanup('test-realm');

      expect(result.success).toBe(true);
      expect(result.deletedCounts).toBeDefined();
    });

    it('should return error when realm not found', async () => {
      mockRealmRepo.findRealmById.mockResolvedValue(null);

      const result = await deleteRealmWithCleanup('non-existent');

      expect(result.success).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should preserve audit logs for HIPAA compliance', async () => {
      const mockRealm = createMockRealm('clinisyn-psychologists');
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);
      mockRealmRepo.deleteRealm.mockResolvedValue(true);
      mockDynamoDb.send.mockResolvedValue({ Items: [], Count: 0 });

      const result = await deleteRealmWithCleanup('clinisyn-psychologists');

      expect(result.success).toBe(true);
      expect(result.deletedCounts?.auditLogs).toBe(0); // Preserved
    });
  });

  describe('listRealms', () => {
    it('should return all realms', async () => {
      const mockRealms = [
        createMockRealm('realm-1'),
        createMockRealm('realm-2')
      ];
      mockRealmRepo.listRealms.mockResolvedValue(mockRealms);

      const result = await listRealms();

      expect(result).toHaveLength(2);
    });

    it('should filter healthcare realms when requested', async () => {
      const mockRealms = [
        createMockRealm('clinisyn-psychologists'),
        createMockRealm('regular-realm')
      ];
      mockRealmRepo.listRealms.mockResolvedValue(mockRealms);

      const result = await listRealms({ healthcareOnly: true });

      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('clinisyn-psychologists');
    });
  });

  describe('getRealmStats', () => {
    it('should return realm statistics', async () => {
      const mockRealm = createMockRealm('test-realm');
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);
      mockDynamoDb.send.mockResolvedValue({ Count: 10, Items: [] });

      const result = await getRealmStats('test-realm');

      expect(result).toBeDefined();
      expect(result?.realmId).toBe('test-realm');
    });

    it('should return null when realm not found', async () => {
      mockRealmRepo.findRealmById.mockResolvedValue(null);

      const result = await getRealmStats('non-existent');

      expect(result).toBeNull();
    });
  });


  describe('Cross-Realm Isolation', () => {
    describe('validateCrossRealmAccess', () => {
      it('should allow access when realms match', () => {
        const result = validateCrossRealmAccess('realm-1', 'realm-1');

        expect(result.allowed).toBe(true);
      });

      it('should deny access when realms differ', () => {
        const result = validateCrossRealmAccess('realm-1', 'realm-2');

        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('Cross-realm access denied');
      });

      it('should handle property-based cross-realm checks', () => {
        fc.assert(
          fc.property(realmNameArb, realmNameArb, (realm1, realm2) => {
            const result = validateCrossRealmAccess(realm1, realm2);
            
            if (realm1 === realm2) {
              expect(result.allowed).toBe(true);
            } else {
              expect(result.allowed).toBe(false);
            }
            return true;
          }),
          { numRuns: 50 }
        );
      });
    });

    describe('validateUserInRealm', () => {
      it('should allow when user belongs to realm', async () => {
        mockDynamoDb.send.mockResolvedValue({
          Items: [{ pk: 'USER#user-1', realm_id: 'test-realm' }]
        });

        const result = await validateUserInRealm('user-1', 'test-realm');

        expect(result.allowed).toBe(true);
      });

      it('should deny when user belongs to different realm', async () => {
        mockDynamoDb.send.mockResolvedValue({
          Items: [{ pk: 'USER#user-1', realm_id: 'other-realm' }]
        });

        const result = await validateUserInRealm('user-1', 'test-realm');

        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('does not belong');
      });

      it('should deny when user not found', async () => {
        mockDynamoDb.send.mockResolvedValue({ Items: [] });

        const result = await validateUserInRealm('non-existent', 'test-realm');

        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('not found');
      });
    });

    describe('validateSessionInRealm', () => {
      it('should allow when session belongs to realm', async () => {
        mockDynamoDb.send.mockResolvedValue({
          Items: [{ pk: 'SESSION#session-1', realm_id: 'test-realm' }]
        });

        const result = await validateSessionInRealm('session-1', 'test-realm');

        expect(result.allowed).toBe(true);
      });

      it('should deny when session belongs to different realm', async () => {
        mockDynamoDb.send.mockResolvedValue({
          Items: [{ pk: 'SESSION#session-1', realm_id: 'other-realm' }]
        });

        const result = await validateSessionInRealm('session-1', 'test-realm');

        expect(result.allowed).toBe(false);
      });
    });
  });


  describe('Healthcare Realm Detection', () => {
    it('should detect clinisyn as healthcare realm', () => {
      expect(isHealthcareRealm('clinisyn-psychologists')).toBe(true);
      expect(isHealthcareRealm('clinisyn-students')).toBe(true);
    });

    it('should detect healthcare keywords', () => {
      expect(isHealthcareRealm('medical-center')).toBe(true);
      expect(isHealthcareRealm('hospital-xyz')).toBe(true);
      expect(isHealthcareRealm('clinic-abc')).toBe(true);
      expect(isHealthcareRealm('hipaa-compliant')).toBe(true);
    });

    it('should not detect regular realms as healthcare', () => {
      expect(isHealthcareRealm('regular-app')).toBe(false);
      expect(isHealthcareRealm('ecommerce-store')).toBe(false);
      expect(isHealthcareRealm('social-network')).toBe(false);
    });
  });

  describe('MFA Policy Enforcement', () => {
    const mockUser = {
      id: 'user-1',
      realm_id: 'test-realm',
      email: 'test@example.com',
      mfa_enabled: false,
      webauthn_credentials: [],
      created_at: new Date().toISOString()
    } as any;

    describe('getEffectiveMfaConfig', () => {
      it('should return stricter config for healthcare realms', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'optional' }
        });

        const config = await getEffectiveMfaConfig('clinisyn-psychologists');

        expect(config.policy).toBe('optional'); // Keeps optional but adds restrictions
        expect(config.require_webauthn_for_sensitive).toBe(true);
        expect(config.remember_device_days).toBeLessThanOrEqual(7);
      });

      it('should upgrade disabled to required for healthcare', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'disabled' }
        });

        const config = await getEffectiveMfaConfig('clinisyn-psychologists');

        expect(config.policy).toBe('required');
      });
    });

    describe('checkMfaEnforcement', () => {
      it('should not require MFA when policy is disabled', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'disabled' }
        });

        const result = await checkMfaEnforcement('regular-realm', mockUser);

        expect(result.mfaRequired).toBe(false);
        expect(result.reason).toBe('none');
      });

      it('should require MFA when policy is required and user has MFA', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'required' }
        });

        const userWithMfa = { ...mockUser, mfa_enabled: true };
        const result = await checkMfaEnforcement('test-realm', userWithMfa);

        expect(result.mfaRequired).toBe(true);
        expect(result.reason).toBe('policy_required');
      });

      it('should require MFA setup when policy is required and user has no MFA', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            policy: 'required',
            grace_period_hours: 0 // No grace period
          }
        });

        const result = await checkMfaEnforcement('test-realm', mockUser);

        expect(result.mfaRequired).toBe(true);
        expect(result.setupRequired).toBe(true);
      });

      it('should allow grace period for new users', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            policy: 'required',
            grace_period_hours: 72
          }
        });

        const newUser = { 
          ...mockUser, 
          created_at: new Date().toISOString() // Just created
        };
        const result = await checkMfaEnforcement('test-realm', newUser);

        expect(result.gracePeriodActive).toBe(true);
        expect(result.setupRequired).toBe(true);
      });

      it('should require WebAuthn for sensitive actions in healthcare', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...HEALTHCARE_MFA_CONFIG
          }
        });

        const userWithMfa = { ...mockUser, mfa_enabled: true };
        const result = await checkMfaEnforcement('clinisyn-psychologists', userWithMfa, {
          isSensitiveAction: true
        });

        expect(result.mfaRequired).toBe(true);
        expect(result.webauthnRequired).toBe(true);
        expect(result.allowedMethods).toEqual(['webauthn']);
      });

      it('should require MFA for new device login', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'optional' }
        });

        const userWithMfa = { ...mockUser, mfa_enabled: true };
        const result = await checkMfaEnforcement('test-realm', userWithMfa, {
          isNewDevice: true
        });

        expect(result.mfaRequired).toBe(true);
        expect(result.reason).toBe('new_device');
      });

      it('should skip MFA for trusted device', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            policy: 'required',
            remember_device_days: 30
          }
        });

        const userWithMfa = { ...mockUser, mfa_enabled: true };
        const result = await checkMfaEnforcement('test-realm', userWithMfa, {
          deviceTrusted: true
        });

        expect(result.mfaRequired).toBe(false);
      });
    });

    describe('checkMfaSetupRequired', () => {
      it('should not require setup when policy is optional', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'optional' }
        });

        const result = await checkMfaSetupRequired('test-realm', mockUser);

        expect(result.required).toBe(false);
      });

      it('should require setup when policy is required and no MFA', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            policy: 'required',
            grace_period_hours: 0
          }
        });

        const result = await checkMfaSetupRequired('test-realm', mockUser);

        expect(result.required).toBe(true);
        expect(result.message).toContain('required');
      });

      it('should not require setup when user already has MFA', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'required' }
        });

        const userWithMfa = { ...mockUser, mfa_enabled: true };
        const result = await checkMfaSetupRequired('test-realm', userWithMfa);

        expect(result.required).toBe(false);
      });
    });

    describe('validateMfaMethod', () => {
      it('should allow TOTP when in allowed methods', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            policy: 'optional',
            allowed_methods: ['totp', 'webauthn']
          }
        });

        const result = await validateMfaMethod('test-realm', 'totp');

        expect(result.allowed).toBe(true);
      });

      it('should reject method not in allowed list', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            policy: 'optional',
            allowed_methods: ['webauthn']
          }
        });

        const result = await validateMfaMethod('test-realm', 'totp');

        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('not allowed');
      });

      it('should reject all methods when MFA is disabled', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'disabled' }
        });

        const result = await validateMfaMethod('test-realm', 'totp');

        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('disabled');
      });
    });

    describe('getRememberDeviceDuration', () => {
      it('should return duration in seconds', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            remember_device_days: 30
          }
        });

        const duration = await getRememberDeviceDuration('test-realm');

        expect(duration).toBe(30 * 24 * 60 * 60); // 30 days in seconds
      });

      it('should return 0 when remember device is disabled', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            remember_device_days: 0
          }
        });

        const duration = await getRememberDeviceDuration('test-realm');

        expect(duration).toBe(0);
      });
    });
  });
});
