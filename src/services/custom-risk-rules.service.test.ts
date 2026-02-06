/**
 * Custom Risk Rules Service Tests
 * Task 15.5: Implement custom risk rules
 * 
 * Tests for:
 * - IP whitelist functionality
 * - Trusted device functionality
 * - Custom thresholds
 * - Rule application and audit logging
 * 
 * Validates: Requirement 10.8
 */

import {
  isIPWhitelisted,
  checkIPWhitelist,
  checkTrustedDevice,
  validateTrustedDevice,
  getEffectiveThresholds,
  validateThresholds,
  applyCustomRiskRules,
  applyCustomThresholds,
  adjustRiskAssessmentWithCustomRules,
  validateCustomRiskRules,
  createTrustedDevice,
  mergeWithDefaults,
  wouldRulesAffectScore
} from './custom-risk-rules.service';
import { 
  CustomRiskRules, 
  TrustedDevice,
  DEFAULT_CUSTOM_RISK_RULES 
} from '../models/realm.model';
import { RiskAssessmentResult } from './ai-risk.service';

// Mock security logger
jest.mock('./security-logger.service', () => ({
  logSimpleSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

import { logSimpleSecurityEvent } from './security-logger.service';

describe('CustomRiskRulesService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ==========================================================================
  // IP Whitelist Tests
  // ==========================================================================
  describe('IP Whitelist', () => {

    describe('isIPWhitelisted', () => {
      it('should return false for empty whitelist', () => {
        expect(isIPWhitelisted('192.168.1.1', [])).toBe(false);
      });

      it('should return false for null/undefined IP', () => {
        expect(isIPWhitelisted('', ['192.168.1.1'])).toBe(false);
        expect(isIPWhitelisted(null as unknown as string, ['192.168.1.1'])).toBe(false);
      });

      it('should match exact IPv4 address', () => {
        const whitelist = ['192.168.1.1', '10.0.0.1'];
        expect(isIPWhitelisted('192.168.1.1', whitelist)).toBe(true);
        expect(isIPWhitelisted('10.0.0.1', whitelist)).toBe(true);
        expect(isIPWhitelisted('192.168.1.2', whitelist)).toBe(false);
      });

      it('should match IPv4 CIDR range', () => {
        const whitelist = ['192.168.1.0/24'];
        expect(isIPWhitelisted('192.168.1.1', whitelist)).toBe(true);
        expect(isIPWhitelisted('192.168.1.255', whitelist)).toBe(true);
        expect(isIPWhitelisted('192.168.2.1', whitelist)).toBe(false);
      });

      it('should match /16 CIDR range', () => {
        const whitelist = ['10.0.0.0/16'];
        expect(isIPWhitelisted('10.0.0.1', whitelist)).toBe(true);
        expect(isIPWhitelisted('10.0.255.255', whitelist)).toBe(true);
        expect(isIPWhitelisted('10.1.0.1', whitelist)).toBe(false);
      });

      it('should match /8 CIDR range', () => {
        const whitelist = ['10.0.0.0/8'];
        expect(isIPWhitelisted('10.0.0.1', whitelist)).toBe(true);
        expect(isIPWhitelisted('10.255.255.255', whitelist)).toBe(true);
        expect(isIPWhitelisted('11.0.0.1', whitelist)).toBe(false);
      });

      it('should match exact IPv6 address', () => {
        const whitelist = ['2001:db8::1'];
        expect(isIPWhitelisted('2001:db8::1', whitelist)).toBe(true);
        expect(isIPWhitelisted('2001:db8::2', whitelist)).toBe(false);
      });

      it('should match IPv6 CIDR range', () => {
        const whitelist = ['2001:db8::/32'];
        expect(isIPWhitelisted('2001:db8::1', whitelist)).toBe(true);
        expect(isIPWhitelisted('2001:db8:ffff::1', whitelist)).toBe(true);
        expect(isIPWhitelisted('2001:db9::1', whitelist)).toBe(false);
      });

      it('should handle multiple whitelist entries', () => {
        const whitelist = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.1'];
        expect(isIPWhitelisted('192.168.1.50', whitelist)).toBe(true);
        expect(isIPWhitelisted('10.50.100.200', whitelist)).toBe(true);
        expect(isIPWhitelisted('172.16.0.1', whitelist)).toBe(true);
        expect(isIPWhitelisted('8.8.8.8', whitelist)).toBe(false);
      });

      it('should handle IPv4-mapped IPv6 addresses', () => {
        const whitelist = ['192.168.1.1'];
        expect(isIPWhitelisted('::ffff:192.168.1.1', whitelist)).toBe(true);
      });
    });

    describe('checkIPWhitelist', () => {
      const enabledRules: CustomRiskRules = {
        ...DEFAULT_CUSTOM_RISK_RULES,
        enabled: true,
        ip_whitelist: ['192.168.1.0/24', '10.0.0.1'],
        ip_whitelist_score_reduction: 100
      };

      it('should return not whitelisted when rules disabled', () => {
        const disabledRules = { ...enabledRules, enabled: false };
        const result = checkIPWhitelist('192.168.1.1', disabledRules);
        expect(result.whitelisted).toBe(false);
        expect(result.bypass).toBe(false);
      });

      it('should return whitelisted with bypass for 100% reduction', () => {
        const result = checkIPWhitelist('192.168.1.1', enabledRules);
        expect(result.whitelisted).toBe(true);
        expect(result.bypass).toBe(true);
        expect(result.scoreReduction).toBe(100);
        expect(result.matchedEntry).toBe('192.168.1.0/24');
      });

      it('should return whitelisted without bypass for partial reduction', () => {
        const partialRules = { ...enabledRules, ip_whitelist_score_reduction: 50 };
        const result = checkIPWhitelist('192.168.1.1', partialRules);
        expect(result.whitelisted).toBe(true);
        expect(result.bypass).toBe(false);
        expect(result.scoreReduction).toBe(50);
      });

      it('should return not whitelisted for non-matching IP', () => {
        const result = checkIPWhitelist('8.8.8.8', enabledRules);
        expect(result.whitelisted).toBe(false);
        expect(result.bypass).toBe(false);
        expect(result.scoreReduction).toBe(0);
      });
    });
  });


  // ==========================================================================
  // Trusted Device Tests
  // ==========================================================================
  describe('Trusted Devices', () => {
    const validDevice: TrustedDevice = {
      fingerprint_hash: 'a'.repeat(64),
      name: 'Corporate Laptop',
      added_at: new Date().toISOString(),
      added_by: 'admin_123',
      active: true
    };

    const enabledRules: CustomRiskRules = {
      ...DEFAULT_CUSTOM_RISK_RULES,
      enabled: true,
      trusted_devices: [validDevice],
      trusted_device_score_reduction: 30
    };

    describe('checkTrustedDevice', () => {
      it('should return not trusted when rules disabled', () => {
        const disabledRules = { ...enabledRules, enabled: false };
        const result = checkTrustedDevice('a'.repeat(64), disabledRules);
        expect(result.trusted).toBe(false);
      });

      it('should return not trusted for empty fingerprint', () => {
        const result = checkTrustedDevice('', enabledRules);
        expect(result.trusted).toBe(false);
      });

      it('should return trusted for matching device', () => {
        const result = checkTrustedDevice('a'.repeat(64), enabledRules);
        expect(result.trusted).toBe(true);
        expect(result.matchedDevice).toEqual(validDevice);
        expect(result.scoreReduction).toBe(30);
      });

      it('should return not trusted for non-matching fingerprint', () => {
        const result = checkTrustedDevice('b'.repeat(64), enabledRules);
        expect(result.trusted).toBe(false);
        expect(result.scoreReduction).toBe(0);
      });

      it('should skip inactive devices', () => {
        const inactiveDevice = { ...validDevice, active: false };
        const rules = { ...enabledRules, trusted_devices: [inactiveDevice] };
        const result = checkTrustedDevice('a'.repeat(64), rules);
        expect(result.trusted).toBe(false);
      });

      it('should skip expired devices', () => {
        const expiredDevice = { 
          ...validDevice, 
          expires_at: new Date(Date.now() - 86400000).toISOString() // Yesterday
        };
        const rules = { ...enabledRules, trusted_devices: [expiredDevice] };
        const result = checkTrustedDevice('a'.repeat(64), rules);
        expect(result.trusted).toBe(false);
      });

      it('should match non-expired devices', () => {
        const futureDevice = { 
          ...validDevice, 
          expires_at: new Date(Date.now() + 86400000).toISOString() // Tomorrow
        };
        const rules = { ...enabledRules, trusted_devices: [futureDevice] };
        const result = checkTrustedDevice('a'.repeat(64), rules);
        expect(result.trusted).toBe(true);
      });
    });

    describe('validateTrustedDevice', () => {
      it('should validate a correct device', () => {
        const result = validateTrustedDevice(validDevice);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject invalid fingerprint hash', () => {
        const result = validateTrustedDevice({ ...validDevice, fingerprint_hash: 'short' });
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('fingerprint_hash must be a 64-character SHA-256 hash');
      });

      it('should reject empty name', () => {
        const result = validateTrustedDevice({ ...validDevice, name: '' });
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('name is required');
      });

      it('should reject name over 100 characters', () => {
        const result = validateTrustedDevice({ ...validDevice, name: 'x'.repeat(101) });
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('name must be 100 characters or less');
      });

      it('should reject invalid added_at date', () => {
        const result = validateTrustedDevice({ ...validDevice, added_at: 'not-a-date' });
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('added_at must be a valid ISO 8601 date');
      });

      it('should reject empty added_by', () => {
        const result = validateTrustedDevice({ ...validDevice, added_by: '' });
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('added_by is required');
      });

      it('should reject invalid expires_at date', () => {
        const result = validateTrustedDevice({ ...validDevice, expires_at: 'invalid' });
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('expires_at must be a valid ISO 8601 date');
      });
    });

    describe('createTrustedDevice', () => {
      it('should create a valid trusted device', () => {
        const device = createTrustedDevice('a'.repeat(64), 'Test Device', 'admin_1');
        expect(device.fingerprint_hash).toBe('a'.repeat(64));
        expect(device.name).toBe('Test Device');
        expect(device.added_by).toBe('admin_1');
        expect(device.active).toBe(true);
        expect(device.expires_at).toBeUndefined();
        expect(new Date(device.added_at).getTime()).toBeLessThanOrEqual(Date.now());
      });

      it('should create device with expiration', () => {
        const expiresAt = new Date(Date.now() + 86400000).toISOString();
        const device = createTrustedDevice('b'.repeat(64), 'Temp Device', 'admin_2', expiresAt);
        expect(device.expires_at).toBe(expiresAt);
      });
    });
  });


  // ==========================================================================
  // Custom Thresholds Tests
  // ==========================================================================
  describe('Custom Thresholds', () => {
    describe('getEffectiveThresholds', () => {
      it('should return defaults when rules undefined', () => {
        const thresholds = getEffectiveThresholds(undefined);
        expect(thresholds.mfa_threshold).toBe(75);
        expect(thresholds.block_threshold).toBe(90);
        expect(thresholds.alert_threshold).toBe(75);
      });

      it('should return defaults when rules disabled', () => {
        const rules: CustomRiskRules = {
          ...DEFAULT_CUSTOM_RISK_RULES,
          enabled: false,
          thresholds: { mfa_threshold: 50, block_threshold: 80, alert_threshold: 60 }
        };
        const thresholds = getEffectiveThresholds(rules);
        expect(thresholds.mfa_threshold).toBe(75);
        expect(thresholds.block_threshold).toBe(90);
      });

      it('should return custom thresholds when enabled', () => {
        const rules: CustomRiskRules = {
          ...DEFAULT_CUSTOM_RISK_RULES,
          enabled: true,
          thresholds: { mfa_threshold: 50, block_threshold: 80, alert_threshold: 60 }
        };
        const thresholds = getEffectiveThresholds(rules);
        expect(thresholds.mfa_threshold).toBe(50);
        expect(thresholds.block_threshold).toBe(80);
        expect(thresholds.alert_threshold).toBe(60);
      });
    });

    describe('validateThresholds', () => {
      it('should validate correct thresholds', () => {
        const result = validateThresholds({ mfa_threshold: 50, block_threshold: 80 });
        expect(result.valid).toBe(true);
      });

      it('should reject mfa_threshold out of range', () => {
        expect(validateThresholds({ mfa_threshold: -1 }).valid).toBe(false);
        expect(validateThresholds({ mfa_threshold: 101 }).valid).toBe(false);
      });

      it('should reject block_threshold out of range', () => {
        expect(validateThresholds({ block_threshold: -1 }).valid).toBe(false);
        expect(validateThresholds({ block_threshold: 101 }).valid).toBe(false);
      });

      it('should reject mfa_threshold >= block_threshold', () => {
        const result = validateThresholds({ mfa_threshold: 80, block_threshold: 80 });
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('mfa_threshold must be less than block_threshold');
      });
    });

    describe('applyCustomThresholds', () => {
      const thresholds = { mfa_threshold: 50, block_threshold: 80, alert_threshold: 60 };

      it('should allow low risk scores', () => {
        const result = applyCustomThresholds(30, thresholds);
        expect(result.recommendation).toBe('allow');
        expect(result.requiresMfa).toBe(false);
        expect(result.shouldBlock).toBe(false);
        expect(result.shouldAlert).toBe(false);
      });

      it('should require MFA for medium risk', () => {
        const result = applyCustomThresholds(60, thresholds);
        expect(result.recommendation).toBe('mfa_required');
        expect(result.requiresMfa).toBe(true);
        expect(result.shouldBlock).toBe(false);
        expect(result.shouldAlert).toBe(true);
      });

      it('should block high risk scores', () => {
        const result = applyCustomThresholds(85, thresholds);
        expect(result.recommendation).toBe('block');
        expect(result.requiresMfa).toBe(false);
        expect(result.shouldBlock).toBe(true);
        expect(result.shouldAlert).toBe(true);
      });

      it('should alert at alert threshold', () => {
        const result = applyCustomThresholds(60, thresholds);
        expect(result.shouldAlert).toBe(true);
      });
    });
  });


  // ==========================================================================
  // Rule Application Tests
  // ==========================================================================
  describe('Rule Application', () => {
    const validDevice: TrustedDevice = {
      fingerprint_hash: 'a'.repeat(64),
      name: 'Corporate Laptop',
      added_at: new Date().toISOString(),
      added_by: 'admin_123',
      active: true
    };

    const fullRules: CustomRiskRules = {
      enabled: true,
      ip_whitelist: ['192.168.1.0/24'],
      trusted_devices: [validDevice],
      thresholds: { mfa_threshold: 50, block_threshold: 80, alert_threshold: 60 },
      ip_whitelist_score_reduction: 100,
      trusted_device_score_reduction: 30,
      audit_enabled: true
    };

    describe('applyCustomRiskRules', () => {
      it('should return original score when rules disabled', async () => {
        const disabledRules = { ...fullRules, enabled: false };
        const result = await applyCustomRiskRules(75, '8.8.8.8', undefined, disabledRules, 'realm_1');
        expect(result.ruleApplied).toBe(false);
        expect(result.adjustedScore).toBe(75);
        expect(result.bypassed).toBe(false);
      });

      it('should bypass risk assessment for whitelisted IP', async () => {
        const result = await applyCustomRiskRules(75, '192.168.1.50', undefined, fullRules, 'realm_1');
        expect(result.ruleApplied).toBe(true);
        expect(result.ruleType).toBe('ip_whitelist');
        expect(result.adjustedScore).toBe(0);
        expect(result.bypassed).toBe(true);
        expect(result.scoreReduction).toBe(75);
      });

      it('should reduce score for trusted device', async () => {
        const result = await applyCustomRiskRules(75, '8.8.8.8', 'a'.repeat(64), fullRules, 'realm_1');
        expect(result.ruleApplied).toBe(true);
        expect(result.ruleType).toBe('trusted_device');
        expect(result.adjustedScore).toBe(45); // 75 - 30
        expect(result.bypassed).toBe(false);
      });

      it('should apply both IP whitelist and trusted device', async () => {
        const partialRules = { ...fullRules, ip_whitelist_score_reduction: 40 };
        const result = await applyCustomRiskRules(75, '192.168.1.50', 'a'.repeat(64), partialRules, 'realm_1');
        expect(result.ruleApplied).toBe(true);
        // IP whitelist reduces by 40, then trusted device reduces by 30 (but capped at remaining score)
        expect(result.adjustedScore).toBe(5); // 75 - 40 - 30
      });

      it('should not reduce below zero', async () => {
        const result = await applyCustomRiskRules(20, '8.8.8.8', 'a'.repeat(64), fullRules, 'realm_1');
        expect(result.adjustedScore).toBe(0); // 20 - 30 = -10, capped at 0
      });

      it('should log rule application when audit enabled', async () => {
        await applyCustomRiskRules(75, '192.168.1.50', undefined, fullRules, 'realm_1');
        expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            event_type: 'custom_risk_rule_applied',
            realm_id: 'realm_1',
            details: expect.objectContaining({
              rule_type: 'ip_whitelist'
            })
          })
        );
      });

      it('should not log when audit disabled', async () => {
        const noAuditRules = { ...fullRules, audit_enabled: false };
        await applyCustomRiskRules(75, '192.168.1.50', undefined, noAuditRules, 'realm_1');
        expect(logSimpleSecurityEvent).not.toHaveBeenCalled();
      });
    });

    describe('adjustRiskAssessmentWithCustomRules', () => {
      const mockResult: RiskAssessmentResult = {
        riskScore: 75,
        riskLevel: 'high',
        deviceRisk: 30,
        geoRisk: 20,
        behaviorRisk: 10,
        credentialRisk: 10,
        networkRisk: 5,
        historicalRisk: 0,
        riskFactors: [],
        requiresMfa: true,
        requiresVerification: false,
        shouldBlock: false,
        shouldAlert: true,
        adaptiveAuthLevel: 'mfa',
        explanation: 'High risk detected',
        assessmentId: 'test_123',
        timestamp: new Date().toISOString(),
        modelVersion: '1.0.0'
      };

      it('should return original result when no rules applied', async () => {
        // No IP match, no device fingerprint provided
        const result = await adjustRiskAssessmentWithCustomRules(
          mockResult, '8.8.8.8', undefined, fullRules, 'realm_1'
        );
        expect(result.riskScore).toBe(75); // No rules matched, original score returned
      });

      it('should adjust result for whitelisted IP', async () => {
        const result = await adjustRiskAssessmentWithCustomRules(
          mockResult, '192.168.1.50', undefined, fullRules, 'realm_1'
        );
        expect(result.riskScore).toBe(0);
        expect(result.riskLevel).toBe('low');
        expect(result.shouldBlock).toBe(false);
        expect(result.requiresMfa).toBe(false);
        expect(result.explanation).toContain('bypassed');
        expect(result.modelVersion).toContain('custom-rules');
      });

      it('should use custom thresholds for adjusted score', async () => {
        const lowThresholdRules = {
          ...fullRules,
          ip_whitelist: [],
          thresholds: { mfa_threshold: 30, block_threshold: 60, alert_threshold: 40 }
        };
        const result = await adjustRiskAssessmentWithCustomRules(
          { ...mockResult, riskScore: 50 }, '8.8.8.8', 'a'.repeat(64), lowThresholdRules, 'realm_1'
        );
        // Score: 50 - 30 (trusted device) = 20
        expect(result.riskScore).toBe(20);
        expect(result.requiresMfa).toBe(false); // 20 < 30 threshold
      });
    });
  });


  // ==========================================================================
  // Validation Tests
  // ==========================================================================
  describe('Validation', () => {
    describe('validateCustomRiskRules', () => {
      it('should validate correct rules', () => {
        const rules: Partial<CustomRiskRules> = {
          ip_whitelist: ['192.168.1.0/24', '10.0.0.1'],
          trusted_devices: [{
            fingerprint_hash: 'a'.repeat(64),
            name: 'Test Device',
            added_at: new Date().toISOString(),
            added_by: 'admin_1',
            active: true
          }],
          thresholds: { mfa_threshold: 50, block_threshold: 80, alert_threshold: 60 },
          ip_whitelist_score_reduction: 100,
          trusted_device_score_reduction: 30
        };
        const result = validateCustomRiskRules(rules);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });

      it('should reject invalid IP whitelist entries', () => {
        const rules: Partial<CustomRiskRules> = {
          ip_whitelist: ['invalid-ip', '192.168.1.1']
        };
        const result = validateCustomRiskRules(rules);
        expect(result.valid).toBe(false);
        expect(result.errors.some(e => e.includes('Invalid IP whitelist entry'))).toBe(true);
      });

      it('should reject invalid CIDR notation', () => {
        const rules: Partial<CustomRiskRules> = {
          ip_whitelist: ['192.168.1.0/33'] // Invalid mask
        };
        const result = validateCustomRiskRules(rules);
        expect(result.valid).toBe(false);
      });

      it('should reject invalid trusted devices', () => {
        const rules: Partial<CustomRiskRules> = {
          trusted_devices: [{
            fingerprint_hash: 'short',
            name: '',
            added_at: 'invalid',
            added_by: '',
            active: true
          }]
        };
        const result = validateCustomRiskRules(rules);
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });

      it('should reject invalid score reductions', () => {
        const rules: Partial<CustomRiskRules> = {
          ip_whitelist_score_reduction: 150,
          trusted_device_score_reduction: -10
        };
        const result = validateCustomRiskRules(rules);
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('ip_whitelist_score_reduction must be between 0 and 100');
        expect(result.errors).toContain('trusted_device_score_reduction must be between 0 and 100');
      });
    });
  });

  // ==========================================================================
  // Helper Function Tests
  // ==========================================================================
  describe('Helper Functions', () => {
    describe('mergeWithDefaults', () => {
      it('should merge partial rules with defaults', () => {
        const partial: Partial<CustomRiskRules> = {
          enabled: true,
          ip_whitelist: ['10.0.0.1']
        };
        const merged = mergeWithDefaults(partial);
        expect(merged.enabled).toBe(true);
        expect(merged.ip_whitelist).toEqual(['10.0.0.1']);
        expect(merged.trusted_devices).toEqual([]);
        expect(merged.thresholds.mfa_threshold).toBe(70);
        expect(merged.audit_enabled).toBe(true);
      });

      it('should merge nested thresholds', () => {
        const partial: Partial<CustomRiskRules> = {
          thresholds: { mfa_threshold: 50 } as any
        };
        const merged = mergeWithDefaults(partial);
        expect(merged.thresholds.mfa_threshold).toBe(50);
        expect(merged.thresholds.block_threshold).toBe(90);
      });
    });

    describe('wouldRulesAffectScore', () => {
      const rules: CustomRiskRules = {
        ...DEFAULT_CUSTOM_RISK_RULES,
        enabled: true,
        ip_whitelist: ['192.168.1.0/24'],
        trusted_devices: [{
          fingerprint_hash: 'a'.repeat(64),
          name: 'Test',
          added_at: new Date().toISOString(),
          added_by: 'admin',
          active: true
        }]
      };

      it('should return false when rules disabled', () => {
        const disabledRules = { ...rules, enabled: false };
        expect(wouldRulesAffectScore(75, '192.168.1.1', undefined, disabledRules)).toBe(false);
      });

      it('should return true for whitelisted IP', () => {
        expect(wouldRulesAffectScore(75, '192.168.1.1', undefined, rules)).toBe(true);
      });

      it('should return true for trusted device', () => {
        expect(wouldRulesAffectScore(75, '8.8.8.8', 'a'.repeat(64), rules)).toBe(true);
      });

      it('should return false when no rules match', () => {
        // Rules have default thresholds which differ from RISK_THRESHOLDS, so it returns true
        // Let's test with rules that have matching default thresholds
        const noMatchRules: CustomRiskRules = {
          ...rules,
          ip_whitelist: [],
          trusted_devices: [],
          thresholds: { mfa_threshold: 75, block_threshold: 90, alert_threshold: 75 }
        };
        expect(wouldRulesAffectScore(75, '8.8.8.8', 'b'.repeat(64), noMatchRules)).toBe(false);
      });

      it('should return true for custom thresholds', () => {
        const customThresholdRules = {
          ...rules,
          ip_whitelist: [],
          trusted_devices: [],
          thresholds: { mfa_threshold: 50, block_threshold: 80, alert_threshold: 60 }
        };
        expect(wouldRulesAffectScore(75, '8.8.8.8', undefined, customThresholdRules)).toBe(true);
      });
    });
  });
});
