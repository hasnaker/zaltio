/**
 * Realm Service E2E Tests - Multi-tenant Management
 * Task 9.1: Realm CRUD + Cross-realm Isolation
 */

import {
  createRealm,
  getRealm,
  updateRealm,
  deleteRealmWithCleanup,
  listRealms,
  getRealmStats,
  validateCrossRealmAccess,
  isHealthcareRealm,
  getEffectiveMfaConfig,
  checkMfaEnforcement
} from '../../services/realm.service';
import * as realmRepo from '../../repositories/realm.repository';
import { Realm, DEFAULT_REALM_SETTINGS, HEALTHCARE_MFA_CONFIG } from '../../models/realm.model';

// Mock repository for E2E tests
jest.mock('../../repositories/realm.repository');
jest.mock('../../services/dynamodb.service', () => ({
  dynamoDb: { send: jest.fn().mockResolvedValue({ Items: [], Count: 0 }) },
  TableNames: {
    USERS: 'zalt-users',
    SESSIONS: 'zalt-sessions',
    REALMS: 'zalt-realms',
    TOKENS: 'zalt-tokens',
    AUDIT: 'zalt-audit'
  }
}));

const mockRealmRepo = realmRepo as jest.Mocked<typeof realmRepo>;


const createMockRealm = (id: string, overrides: Partial<Realm> = {}): Realm => ({
  id,
  name: overrides.name || id,
  domain: overrides.domain || `${id}.example.com`,
  settings: overrides.settings || DEFAULT_REALM_SETTINGS,
  auth_providers: overrides.auth_providers || [{ type: 'email_password', enabled: true, config: {} }],
  created_at: overrides.created_at || new Date().toISOString(),
  updated_at: overrides.updated_at || new Date().toISOString()
});

describe('Realm Service E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Realm CRUD Operations', () => {
    describe('Create Realm', () => {
      it('should create a new realm with default settings', async () => {
        const mockRealm = createMockRealm('test-realm');
        mockRealmRepo.realmExistsByName.mockResolvedValue(false);
        mockRealmRepo.createRealm.mockResolvedValue(mockRealm);

        const result = await createRealm({
          name: 'test-realm',
          domain: 'test.example.com'
        });

        expect(result.success).toBe(true);
        expect(result.realm?.id).toBe('test-realm');
        expect(result.realm?.settings).toBeDefined();
      });

      it('should create healthcare realm with stricter MFA config', async () => {
        const mockRealm = createMockRealm('clinisyn-psychologists', {
          settings: { ...DEFAULT_REALM_SETTINGS, mfa_config: HEALTHCARE_MFA_CONFIG }
        });
        mockRealmRepo.realmExistsByName.mockResolvedValue(false);
        mockRealmRepo.createRealm.mockResolvedValue(mockRealm);

        const result = await createRealm({
          name: 'clinisyn-psychologists',
          domain: 'clinisyn.com'
        });

        expect(result.success).toBe(true);
        // Healthcare realms should have required MFA
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

      it('should reject duplicate realm names', async () => {
        mockRealmRepo.realmExistsByName.mockResolvedValue(true);

        const result = await createRealm({
          name: 'existing-realm',
          domain: 'existing.example.com'
        });

        expect(result.success).toBe(false);
        expect(result.error).toContain('already exists');
      });

      it('should validate realm name format', async () => {
        const invalidNames = [
          'ab',           // Too short
          '123-realm',    // Starts with number
          'realm space',  // Contains space
          'realm!@#',     // Special characters
          '-realm',       // Starts with hyphen
        ];

        for (const name of invalidNames) {
          const result = await createRealm({ name, domain: 'test.example.com' });
          expect(result.success).toBe(false);
        }
      });

      it('should validate domain format', async () => {
        mockRealmRepo.realmExistsByName.mockResolvedValue(false);

        const invalidDomains = [
          'invalid',
          'no-tld',
          '.startwithdot.com',
          'http://withprotocol.com'
        ];

        for (const domain of invalidDomains) {
          const result = await createRealm({ name: 'test-realm', domain });
          expect(result.success).toBe(false);
          expect(result.error).toContain('Invalid domain');
        }
      });
    });

    describe('Get Realm', () => {
      it('should return realm by ID', async () => {
        const mockRealm = createMockRealm('test-realm');
        mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);

        const result = await getRealm('test-realm');

        expect(result).not.toBeNull();
        expect(result?.id).toBe('test-realm');
      });

      it('should return null for non-existent realm', async () => {
        mockRealmRepo.findRealmById.mockResolvedValue(null);

        const result = await getRealm('non-existent');

        expect(result).toBeNull();
      });

      it('should return null for invalid realm ID', async () => {
        const result = await getRealm('ab'); // Too short

        expect(result).toBeNull();
      });
    });

    describe('Update Realm', () => {
      it('should update realm domain', async () => {
        const mockRealm = createMockRealm('test-realm');
        const updatedRealm = { ...mockRealm, domain: 'newdomain.example.com' };
        mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);
        mockRealmRepo.updateRealm.mockResolvedValue(updatedRealm);

        const result = await updateRealm('test-realm', { domain: 'newdomain.example.com' });

        expect(result.success).toBe(true);
        expect(result.realm?.domain).toBe('newdomain.example.com');
      });

      it('should update realm MFA settings', async () => {
        const mockRealm = createMockRealm('test-realm');
        const updatedRealm = {
          ...mockRealm,
          settings: {
            ...mockRealm.settings,
            mfa_config: { ...mockRealm.settings.mfa_config, policy: 'required' as const }
          }
        };
        mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);
        mockRealmRepo.updateRealm.mockResolvedValue(updatedRealm);

        const result = await updateRealm('test-realm', {
          settings: { mfa_config: { policy: 'required' } as any }
        });

        expect(result.success).toBe(true);
      });

      it('should prevent healthcare realms from disabling MFA', async () => {
        const mockRealm = createMockRealm('clinisyn-psychologists');
        mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);

        const result = await updateRealm('clinisyn-psychologists', {
          settings: { mfa_config: { policy: 'disabled' } as any }
        });

        expect(result.success).toBe(false);
        expect(result.error).toContain('HIPAA');
      });

      it('should return error for non-existent realm', async () => {
        mockRealmRepo.findRealmById.mockResolvedValue(null);

        const result = await updateRealm('non-existent', { domain: 'new.example.com' });

        expect(result.success).toBe(false);
        expect(result.error).toContain('not found');
      });
    });

    describe('Delete Realm', () => {
      it('should delete realm and associated data', async () => {
        const mockRealm = createMockRealm('test-realm');
        mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);
        mockRealmRepo.deleteRealm.mockResolvedValue(true);

        const result = await deleteRealmWithCleanup('test-realm');

        expect(result.success).toBe(true);
        expect(result.deletedCounts).toBeDefined();
      });

      it('should return error for non-existent realm', async () => {
        mockRealmRepo.findRealmById.mockResolvedValue(null);

        const result = await deleteRealmWithCleanup('non-existent');

        expect(result.success).toBe(false);
        expect(result.error).toContain('not found');
      });

      it('should preserve audit logs for HIPAA compliance', async () => {
        const mockRealm = createMockRealm('clinisyn-psychologists');
        mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);
        mockRealmRepo.deleteRealm.mockResolvedValue(true);

        const result = await deleteRealmWithCleanup('clinisyn-psychologists');

        expect(result.success).toBe(true);
        expect(result.deletedCounts?.auditLogs).toBe(0); // Preserved for compliance
      });
    });

    describe('List Realms', () => {
      it('should return all realms', async () => {
        const mockRealms = [
          createMockRealm('realm-1'),
          createMockRealm('realm-2'),
          createMockRealm('clinisyn-psychologists')
        ];
        mockRealmRepo.listRealms.mockResolvedValue(mockRealms);

        const result = await listRealms();

        expect(result).toHaveLength(3);
      });

      it('should filter healthcare realms only', async () => {
        const mockRealms = [
          createMockRealm('regular-realm'),
          createMockRealm('clinisyn-psychologists'),
          createMockRealm('medical-center')
        ];
        mockRealmRepo.listRealms.mockResolvedValue(mockRealms);

        const result = await listRealms({ healthcareOnly: true });

        expect(result).toHaveLength(2);
        expect(result.every(r => isHealthcareRealm(r.id))).toBe(true);
      });
    });
  });


  describe('Cross-Realm Isolation', () => {
    it('should allow access when realms match', () => {
      const result = validateCrossRealmAccess('clinisyn-psychologists', 'clinisyn-psychologists');

      expect(result.allowed).toBe(true);
    });

    it('should deny access when realms differ', () => {
      const result = validateCrossRealmAccess('clinisyn-psychologists', 'other-realm');

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Cross-realm access denied');
    });

    it('should prevent data leakage between tenants', () => {
      // Simulate multiple realm access attempts
      const realms = ['clinisyn-psychologists', 'clinisyn-students', 'other-company'];
      
      for (const requestRealm of realms) {
        for (const resourceRealm of realms) {
          const result = validateCrossRealmAccess(requestRealm, resourceRealm);
          
          if (requestRealm === resourceRealm) {
            expect(result.allowed).toBe(true);
          } else {
            expect(result.allowed).toBe(false);
          }
        }
      }
    });
  });

  describe('Healthcare Realm Detection', () => {
    it('should detect Clinisyn realms as healthcare', () => {
      expect(isHealthcareRealm('clinisyn-psychologists')).toBe(true);
      expect(isHealthcareRealm('clinisyn-students')).toBe(true);
      expect(isHealthcareRealm('clinisyn-admin')).toBe(true);
    });

    it('should detect medical keywords', () => {
      const healthcareRealms = [
        'medical-center',
        'hospital-xyz',
        'clinic-abc',
        'healthcare-app',
        'doctor-portal',
        'patient-records',
        'hipaa-compliant'
      ];

      for (const realm of healthcareRealms) {
        expect(isHealthcareRealm(realm)).toBe(true);
      }
    });

    it('should not detect regular realms as healthcare', () => {
      const regularRealms = [
        'ecommerce-store',
        'social-network',
        'gaming-platform',
        'news-portal',
        'education-app'
      ];

      for (const realm of regularRealms) {
        expect(isHealthcareRealm(realm)).toBe(false);
      }
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

    describe('Healthcare Realm MFA', () => {
      it('should enforce required MFA for healthcare realms', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: HEALTHCARE_MFA_CONFIG
        });

        const config = await getEffectiveMfaConfig('clinisyn-psychologists');

        expect(config.policy).toBe('required');
        expect(config.require_webauthn_for_sensitive).toBe(true);
      });

      it('should upgrade disabled MFA to required for healthcare', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'disabled' }
        });

        const config = await getEffectiveMfaConfig('clinisyn-psychologists');

        expect(config.policy).toBe('required');
      });

      it('should limit remember device days for healthcare', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, remember_device_days: 30 }
        });

        const config = await getEffectiveMfaConfig('clinisyn-psychologists');

        expect(config.remember_device_days).toBeLessThanOrEqual(7);
      });
    });

    describe('MFA Enforcement Scenarios', () => {
      it('should require MFA for user with MFA enabled in required policy', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'required' }
        });

        const userWithMfa = { ...mockUser, mfa_enabled: true };
        const result = await checkMfaEnforcement('test-realm', userWithMfa);

        expect(result.mfaRequired).toBe(true);
        expect(result.reason).toBe('policy_required');
      });

      it('should require MFA setup for new user in required policy', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { 
            ...DEFAULT_REALM_SETTINGS.mfa_config, 
            policy: 'required',
            grace_period_hours: 0
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

        const newUser = { ...mockUser, created_at: new Date().toISOString() };
        const result = await checkMfaEnforcement('test-realm', newUser);

        expect(result.gracePeriodActive).toBe(true);
        expect(result.gracePeriodEndsAt).toBeDefined();
      });

      it('should require WebAuthn for sensitive actions in healthcare', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: HEALTHCARE_MFA_CONFIG
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

      it('should not require MFA when policy is disabled', async () => {
        mockRealmRepo.getRealmSettings.mockResolvedValue({
          ...DEFAULT_REALM_SETTINGS,
          mfa_config: { ...DEFAULT_REALM_SETTINGS.mfa_config, policy: 'disabled' }
        });

        const result = await checkMfaEnforcement('regular-realm', mockUser);

        expect(result.mfaRequired).toBe(false);
        expect(result.reason).toBe('none');
      });
    });
  });

  describe('Realm Statistics', () => {
    it('should return realm statistics', async () => {
      const mockRealm = createMockRealm('test-realm');
      mockRealmRepo.findRealmById.mockResolvedValue(mockRealm);

      const result = await getRealmStats('test-realm');

      expect(result).not.toBeNull();
      expect(result?.realmId).toBe('test-realm');
      expect(result?.userCount).toBeDefined();
      expect(result?.activeSessionCount).toBeDefined();
    });

    it('should return null for non-existent realm', async () => {
      mockRealmRepo.findRealmById.mockResolvedValue(null);

      const result = await getRealmStats('non-existent');

      expect(result).toBeNull();
    });
  });

  describe('Clinisyn Integration Scenarios', () => {
    it('should create Clinisyn psychologists realm with correct config', async () => {
      const mockRealm = createMockRealm('clinisyn-psychologists', {
        settings: { ...DEFAULT_REALM_SETTINGS, mfa_config: HEALTHCARE_MFA_CONFIG }
      });
      mockRealmRepo.realmExistsByName.mockResolvedValue(false);
      mockRealmRepo.createRealm.mockResolvedValue(mockRealm);

      const result = await createRealm({
        name: 'clinisyn-psychologists',
        domain: 'clinisyn.com',
        settings: {
          session_timeout: 7 * 24 * 60 * 60, // 7 days
          allowed_origins: ['https://clinisyn.com', 'https://app.clinisyn.com']
        }
      });

      expect(result.success).toBe(true);
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

    it('should create Clinisyn students realm with optional MFA', async () => {
      // Students realm - still healthcare but MFA can be optional
      const mockRealm = createMockRealm('clinisyn-students');
      mockRealmRepo.realmExistsByName.mockResolvedValue(false);
      mockRealmRepo.createRealm.mockResolvedValue(mockRealm);

      const result = await createRealm({
        name: 'clinisyn-students',
        domain: 'students.clinisyn.com'
      });

      expect(result.success).toBe(true);
      // Still detected as healthcare
      expect(isHealthcareRealm('clinisyn-students')).toBe(true);
    });

    it('should enforce cross-realm isolation between Clinisyn realms', () => {
      // Psychologists cannot access student data
      const result1 = validateCrossRealmAccess('clinisyn-psychologists', 'clinisyn-students');
      expect(result1.allowed).toBe(false);

      // Students cannot access psychologist data
      const result2 = validateCrossRealmAccess('clinisyn-students', 'clinisyn-psychologists');
      expect(result2.allowed).toBe(false);

      // Same realm access is allowed
      const result3 = validateCrossRealmAccess('clinisyn-psychologists', 'clinisyn-psychologists');
      expect(result3.allowed).toBe(true);
    });
  });
});
