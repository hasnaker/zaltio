/**
 * Clinisyn Realm Setup E2E Tests
 * Task 10.1: Clinisyn Realm Setup
 * 
 * Tests the Clinisyn realm configuration including:
 * - Single realm approach (professional standard like Auth0, Okta)
 * - MFA policy enforcement (ZORUNLU - Siberci kararı)
 * - WebAuthn requirements
 * - CORS configuration
 * - Healthcare compliance settings
 * 
 * TEK REALM YAKLAŞIMI:
 * - Realm: clinisyn
 * - Roller: user.profile.metadata.clinisyn_role ile yönetilir
 */

import { 
  CLINISYN_REALM_CONFIG,
  setupClinsynRealm,
  verifyRealm
} from '../../../scripts/clinisyn-realm-setup';

// Mock the realm service
jest.mock('../../services/realm.service');

import * as realmService from '../../services/realm.service';

const mockRealmService = realmService as jest.Mocked<typeof realmService>;

describe('Clinisyn Realm Setup E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Realm Configuration', () => {
    describe('clinisyn realm (single realm approach)', () => {
      it('should have correct realm ID', () => {
        expect(CLINISYN_REALM_CONFIG.id).toBe('clinisyn');
      });

      it('should have MFA policy set to required', () => {
        expect(CLINISYN_REALM_CONFIG.settings.mfa_config?.policy).toBe('required');
      });

      it('should require WebAuthn for sensitive actions (phishing protection)', () => {
        expect(CLINISYN_REALM_CONFIG.settings.mfa_config?.require_webauthn_for_sensitive).toBe(true);
      });

      it('should have 30-minute session timeout for HIPAA compliance', () => {
        expect(CLINISYN_REALM_CONFIG.settings.session_timeout).toBe(1800);
      });

      it('should have strong password policy', () => {
        const policy = CLINISYN_REALM_CONFIG.settings.password_policy;
        expect(policy?.min_length).toBeGreaterThanOrEqual(12);
        expect(policy?.require_uppercase).toBe(true);
        expect(policy?.require_lowercase).toBe(true);
        expect(policy?.require_numbers).toBe(true);
        expect(policy?.require_special_chars).toBe(true);
      });

      it('should have correct CORS origins', () => {
        const origins = CLINISYN_REALM_CONFIG.settings.allowed_origins;
        expect(origins).toContain('https://clinisyn.com');
        expect(origins).toContain('https://app.clinisyn.com');
        expect(origins).toContain('https://portal.clinisyn.com');
        expect(origins).toContain('https://admin.clinisyn.com');
        expect(origins).toContain('https://student.clinisyn.com');
      });

      it('should allow TOTP and WebAuthn methods', () => {
        const methods = CLINISYN_REALM_CONFIG.settings.mfa_config?.allowed_methods;
        expect(methods).toContain('totp');
        expect(methods).toContain('webauthn');
      });

      it('should have 7-day remember device period for healthcare', () => {
        expect(CLINISYN_REALM_CONFIG.settings.mfa_config?.remember_device_days).toBe(7);
      });

      it('should have 72-hour grace period for MFA setup', () => {
        expect(CLINISYN_REALM_CONFIG.settings.mfa_config?.grace_period_hours).toBe(72);
      });

      it('should have mfa_required flag set to true', () => {
        expect(CLINISYN_REALM_CONFIG.settings.mfa_required).toBe(true);
      });
    });
  });

  describe('Realm Setup Function', () => {
    it('should create new realm if it does not exist', async () => {
      mockRealmService.getRealm.mockResolvedValue(null);
      mockRealmService.createRealm.mockResolvedValue({ success: true, realm: { id: 'clinisyn' } as any });

      const result = await setupClinsynRealm();

      expect(result.success).toBe(true);
      expect(mockRealmService.createRealm).toHaveBeenCalled();
    });

    it('should update existing realm', async () => {
      mockRealmService.getRealm.mockResolvedValue({ id: 'clinisyn' } as any);
      mockRealmService.updateRealm.mockResolvedValue({ success: true, realm: { id: 'clinisyn' } as any });

      const result = await setupClinsynRealm();

      expect(result.success).toBe(true);
      expect(mockRealmService.updateRealm).toHaveBeenCalled();
    });

    it('should return error if creation fails', async () => {
      mockRealmService.getRealm.mockResolvedValue(null);
      mockRealmService.createRealm.mockResolvedValue({ success: false, error: 'Creation failed' });

      const result = await setupClinsynRealm();

      expect(result.success).toBe(false);
      expect(result.message).toContain('failed');
    });

    it('should return error if update fails', async () => {
      mockRealmService.getRealm.mockResolvedValue({ id: 'clinisyn' } as any);
      mockRealmService.updateRealm.mockResolvedValue({ success: false, error: 'Update failed' });

      const result = await setupClinsynRealm();

      expect(result.success).toBe(false);
      expect(result.message).toContain('failed');
    });
  });

  describe('Realm Verification', () => {
    it('should verify realm configuration', async () => {
      mockRealmService.getRealm.mockResolvedValue({
        id: 'clinisyn',
        settings: {
          mfa_config: {
            policy: 'required',
            require_webauthn_for_sensitive: true,
            allowed_methods: ['totp', 'webauthn'],
            remember_device_days: 7,
            grace_period_hours: 72
          },
          password_policy: {
            min_length: 12
          },
          allowed_origins: ['https://clinisyn.com'],
          session_timeout: 1800
        }
      } as any);

      const result = await verifyRealm();

      expect(result).toBe(true);
    });

    it('should fail verification if MFA policy is wrong', async () => {
      mockRealmService.getRealm.mockResolvedValue({
        id: 'clinisyn',
        settings: {
          mfa_config: {
            policy: 'optional', // Wrong!
          },
          password_policy: {
            min_length: 12
          },
          session_timeout: 1800
        }
      } as any);

      const result = await verifyRealm();

      expect(result).toBe(false);
    });

    it('should fail verification if realm not found', async () => {
      mockRealmService.getRealm.mockResolvedValue(null);

      const result = await verifyRealm();

      expect(result).toBe(false);
    });

    it('should fail verification if password policy is wrong', async () => {
      mockRealmService.getRealm.mockResolvedValue({
        id: 'clinisyn',
        settings: {
          mfa_config: {
            policy: 'required',
          },
          password_policy: {
            min_length: 8 // Wrong! Should be 12
          },
          session_timeout: 1800
        }
      } as any);

      const result = await verifyRealm();

      expect(result).toBe(false);
    });

    it('should fail verification if session timeout is wrong', async () => {
      mockRealmService.getRealm.mockResolvedValue({
        id: 'clinisyn',
        settings: {
          mfa_config: {
            policy: 'required',
          },
          password_policy: {
            min_length: 12
          },
          session_timeout: 3600 // Wrong! Should be 1800
        }
      } as any);

      const result = await verifyRealm();

      expect(result).toBe(false);
    });
  });

  describe('Security Compliance', () => {
    it('should meet HIPAA session requirements', () => {
      const sessionTimeout = CLINISYN_REALM_CONFIG.settings.session_timeout;
      
      // HIPAA requires automatic logoff after period of inactivity
      expect(sessionTimeout).toBeLessThanOrEqual(1800); // 30 min max
    });

    it('should require strong authentication', () => {
      const mfaConfig = CLINISYN_REALM_CONFIG.settings.mfa_config;
      
      // MFA required
      expect(mfaConfig?.policy).toBe('required');
      
      // WebAuthn required for sensitive actions (phishing-proof)
      expect(mfaConfig?.require_webauthn_for_sensitive).toBe(true);
    });

    it('should have HIPAA-compliant password requirements', () => {
      const policy = CLINISYN_REALM_CONFIG.settings.password_policy;
      expect(policy?.min_length).toBeGreaterThanOrEqual(12);
      expect(policy?.require_uppercase).toBe(true);
      expect(policy?.require_lowercase).toBe(true);
      expect(policy?.require_numbers).toBe(true);
      expect(policy?.require_special_chars).toBe(true);
    });

    it('should not allow SMS MFA (SS7 vulnerability)', () => {
      const methods = CLINISYN_REALM_CONFIG.settings.mfa_config?.allowed_methods || [];
      expect(methods).not.toContain('sms');
    });
  });

  describe('Role-Based Access (via metadata)', () => {
    it('should support role-based access via user metadata', () => {
      // Tek realm yaklaşımı - roller metadata ile yönetilir
      // user.profile.metadata.clinisyn_role
      const supportedRoles = [
        'root_admin',
        'admin',
        'seo_admin',
        'psychologist',
        'student',
        'client',
        'clinic_owner',
        'clinic_manager',
        'clinic_staff'
      ];
      
      // Config should support all user types in single realm
      expect(CLINISYN_REALM_CONFIG.id).toBe('clinisyn');
      expect(supportedRoles.length).toBeGreaterThan(0);
    });
  });
});
