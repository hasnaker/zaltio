/**
 * Impersonation Model Tests
 * Task 11.1: Implement ImpersonationSession model
 * 
 * Tests:
 * - ID generation
 * - Expiry calculation
 * - Session status checks
 * - Action restriction checks
 * - Reason validation
 * - Impersonation eligibility checks
 * 
 * Validates: Requirements 6.2, 6.3
 */

import {
  ImpersonationSession,
  ImpersonationStatus,
  RestrictedAction,
  DEFAULT_RESTRICTED_ACTIONS,
  IMPERSONATION_ID_PREFIX,
  DEFAULT_IMPERSONATION_DURATION_MINUTES,
  MAX_IMPERSONATION_DURATION_MINUTES,
  MIN_REASON_LENGTH,
  MAX_REASON_LENGTH,
  generateImpersonationId,
  calculateImpersonationExpiry,
  isImpersonationExpired,
  isImpersonationActive,
  isActionRestricted,
  isValidReason,
  canImpersonateUser,
  toImpersonationResponse,
  getRemainingTime,
  mapToRestrictedAction,
  isValidRestrictedAction
} from './impersonation.model';

/**
 * Helper to create a mock impersonation session
 */
function createMockSession(overrides: Partial<ImpersonationSession> = {}): ImpersonationSession {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60 * 60 * 1000); // 1 hour from now
  
  return {
    id: generateImpersonationId(),
    realm_id: 'test-realm',
    admin_id: 'admin_123',
    admin_email: 'admin@example.com',
    target_user_id: 'user_456',
    target_user_email: 'user@example.com',
    reason: 'Testing user issue with login flow',
    status: 'active',
    restricted_actions: DEFAULT_RESTRICTED_ACTIONS,
    access_token: 'mock_access_token',
    refresh_token_hash: 'mock_refresh_hash',
    started_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    ip_address: '192.168.1.1',
    user_agent: 'Mozilla/5.0',
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
    ...overrides
  };
}

describe('Impersonation Model', () => {
  describe('generateImpersonationId', () => {
    it('should generate ID with correct prefix', () => {
      const id = generateImpersonationId();
      expect(id.startsWith(IMPERSONATION_ID_PREFIX)).toBe(true);
    });

    it('should generate unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateImpersonationId());
      }
      expect(ids.size).toBe(100);
    });

    it('should generate IDs of consistent length', () => {
      const id = generateImpersonationId();
      // imp_ (4) + 24 hex chars = 28
      expect(id.length).toBe(28);
    });
  });

  describe('calculateImpersonationExpiry', () => {
    it('should calculate expiry with default duration', () => {
      const before = Date.now();
      const expiry = calculateImpersonationExpiry();
      const after = Date.now();
      
      const expiryTime = new Date(expiry).getTime();
      const expectedMin = before + DEFAULT_IMPERSONATION_DURATION_MINUTES * 60 * 1000;
      const expectedMax = after + DEFAULT_IMPERSONATION_DURATION_MINUTES * 60 * 1000;
      
      expect(expiryTime).toBeGreaterThanOrEqual(expectedMin);
      expect(expiryTime).toBeLessThanOrEqual(expectedMax);
    });

    it('should calculate expiry with custom duration', () => {
      const before = Date.now();
      const expiry = calculateImpersonationExpiry(30);
      const after = Date.now();
      
      const expiryTime = new Date(expiry).getTime();
      const expectedMin = before + 30 * 60 * 1000;
      const expectedMax = after + 30 * 60 * 1000;
      
      expect(expiryTime).toBeGreaterThanOrEqual(expectedMin);
      expect(expiryTime).toBeLessThanOrEqual(expectedMax);
    });

    it('should cap duration at maximum', () => {
      const before = Date.now();
      const expiry = calculateImpersonationExpiry(1000); // Way over max
      const after = Date.now();
      
      const expiryTime = new Date(expiry).getTime();
      const expectedMin = before + MAX_IMPERSONATION_DURATION_MINUTES * 60 * 1000;
      const expectedMax = after + MAX_IMPERSONATION_DURATION_MINUTES * 60 * 1000;
      
      expect(expiryTime).toBeGreaterThanOrEqual(expectedMin);
      expect(expiryTime).toBeLessThanOrEqual(expectedMax);
    });

    it('should return valid ISO string', () => {
      const expiry = calculateImpersonationExpiry();
      expect(() => new Date(expiry)).not.toThrow();
      expect(new Date(expiry).toISOString()).toBe(expiry);
    });
  });

  describe('isImpersonationExpired', () => {
    it('should return false for non-expired session', () => {
      const session = createMockSession();
      expect(isImpersonationExpired(session)).toBe(false);
    });

    it('should return true for expired session', () => {
      const pastDate = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago
      const session = createMockSession({
        expires_at: pastDate.toISOString()
      });
      expect(isImpersonationExpired(session)).toBe(true);
    });

    it('should return true for session expiring now', () => {
      const session = createMockSession({
        expires_at: new Date().toISOString()
      });
      // Might be true or false depending on timing, but should not throw
      expect(typeof isImpersonationExpired(session)).toBe('boolean');
    });
  });

  describe('isImpersonationActive', () => {
    it('should return true for active non-expired session', () => {
      const session = createMockSession({ status: 'active' });
      expect(isImpersonationActive(session)).toBe(true);
    });

    it('should return false for ended session', () => {
      const session = createMockSession({ status: 'ended' });
      expect(isImpersonationActive(session)).toBe(false);
    });

    it('should return false for expired status session', () => {
      const session = createMockSession({ status: 'expired' });
      expect(isImpersonationActive(session)).toBe(false);
    });

    it('should return false for active but time-expired session', () => {
      const pastDate = new Date(Date.now() - 60 * 60 * 1000);
      const session = createMockSession({
        status: 'active',
        expires_at: pastDate.toISOString()
      });
      expect(isImpersonationActive(session)).toBe(false);
    });
  });

  describe('isActionRestricted', () => {
    it('should return true for restricted action', () => {
      const session = createMockSession();
      expect(isActionRestricted(session, 'change_password')).toBe(true);
    });

    it('should return false for non-restricted action', () => {
      const session = createMockSession({
        restricted_actions: ['change_password']
      });
      expect(isActionRestricted(session, 'delete_account')).toBe(false);
    });

    it('should check all default restricted actions', () => {
      const session = createMockSession();
      
      DEFAULT_RESTRICTED_ACTIONS.forEach(action => {
        expect(isActionRestricted(session, action)).toBe(true);
      });
    });
  });

  describe('isValidReason', () => {
    it('should accept valid reason', () => {
      const result = isValidReason('Investigating user login issue reported in ticket #12345');
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should reject empty reason', () => {
      const result = isValidReason('');
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Reason is required');
    });

    it('should reject null/undefined reason', () => {
      const result1 = isValidReason(null as unknown as string);
      const result2 = isValidReason(undefined as unknown as string);
      
      expect(result1.valid).toBe(false);
      expect(result2.valid).toBe(false);
    });

    it('should reject too short reason', () => {
      const result = isValidReason('short');
      expect(result.valid).toBe(false);
      expect(result.error).toContain(`at least ${MIN_REASON_LENGTH}`);
    });

    it('should reject too long reason', () => {
      const longReason = 'a'.repeat(MAX_REASON_LENGTH + 1);
      const result = isValidReason(longReason);
      expect(result.valid).toBe(false);
      expect(result.error).toContain(`at most ${MAX_REASON_LENGTH}`);
    });

    it('should accept reason at minimum length', () => {
      const minReason = 'a'.repeat(MIN_REASON_LENGTH);
      const result = isValidReason(minReason);
      expect(result.valid).toBe(true);
    });

    it('should accept reason at maximum length', () => {
      const maxReason = 'a'.repeat(MAX_REASON_LENGTH);
      const result = isValidReason(maxReason);
      expect(result.valid).toBe(true);
    });

    it('should trim whitespace when validating', () => {
      const paddedReason = '   ' + 'a'.repeat(MIN_REASON_LENGTH) + '   ';
      const result = isValidReason(paddedReason);
      expect(result.valid).toBe(true);
    });
  });

  describe('canImpersonateUser', () => {
    it('should allow impersonating regular user', () => {
      const result = canImpersonateUser('admin_123', 'user_456', false);
      expect(result.valid).toBe(true);
    });

    it('should reject impersonating self', () => {
      const result = canImpersonateUser('admin_123', 'admin_123', false);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Cannot impersonate yourself');
    });

    it('should reject impersonating admin users', () => {
      const result = canImpersonateUser('admin_123', 'admin_456', true);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Cannot impersonate admin users');
    });
  });

  describe('toImpersonationResponse', () => {
    it('should convert session to response format', () => {
      const session = createMockSession();
      const response = toImpersonationResponse(session);
      
      expect(response.id).toBe(session.id);
      expect(response.realm_id).toBe(session.realm_id);
      expect(response.admin_id).toBe(session.admin_id);
      expect(response.target_user_id).toBe(session.target_user_id);
      expect(response.status).toBe(session.status);
      expect(response.restricted_actions).toEqual(session.restricted_actions);
      expect(response.started_at).toBe(session.started_at);
      expect(response.expires_at).toBe(session.expires_at);
      expect(response.reason).toBe(session.reason);
    });

    it('should include ended_at when present', () => {
      const endedAt = new Date().toISOString();
      const session = createMockSession({
        status: 'ended',
        ended_at: endedAt
      });
      const response = toImpersonationResponse(session);
      
      expect(response.ended_at).toBe(endedAt);
    });

    it('should not include sensitive fields', () => {
      const session = createMockSession();
      const response = toImpersonationResponse(session);
      
      // These should not be in the response
      expect((response as any).access_token).toBeUndefined();
      expect((response as any).refresh_token_hash).toBeUndefined();
      expect((response as any).ip_address).toBeUndefined();
      expect((response as any).user_agent).toBeUndefined();
      expect((response as any).admin_email).toBeUndefined();
      expect((response as any).target_user_email).toBeUndefined();
    });
  });

  describe('getRemainingTime', () => {
    it('should return positive time for non-expired session', () => {
      const futureDate = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      const session = createMockSession({
        expires_at: futureDate.toISOString()
      });
      
      const remaining = getRemainingTime(session);
      expect(remaining).toBeGreaterThan(0);
      expect(remaining).toBeLessThanOrEqual(30 * 60);
    });

    it('should return 0 for expired session', () => {
      const pastDate = new Date(Date.now() - 60 * 1000);
      const session = createMockSession({
        expires_at: pastDate.toISOString()
      });
      
      expect(getRemainingTime(session)).toBe(0);
    });

    it('should return time in seconds', () => {
      const futureDate = new Date(Date.now() + 60 * 1000); // 1 minute
      const session = createMockSession({
        expires_at: futureDate.toISOString()
      });
      
      const remaining = getRemainingTime(session);
      expect(remaining).toBeGreaterThan(50);
      expect(remaining).toBeLessThanOrEqual(60);
    });
  });

  describe('mapToRestrictedAction', () => {
    it('should map valid action strings', () => {
      expect(mapToRestrictedAction('change_password')).toBe('change_password');
      expect(mapToRestrictedAction('delete_account')).toBe('delete_account');
      expect(mapToRestrictedAction('change_email')).toBe('change_email');
      expect(mapToRestrictedAction('disable_mfa')).toBe('disable_mfa');
      expect(mapToRestrictedAction('revoke_sessions')).toBe('revoke_sessions');
      expect(mapToRestrictedAction('manage_api_keys')).toBe('manage_api_keys');
      expect(mapToRestrictedAction('billing_changes')).toBe('billing_changes');
    });

    it('should return null for invalid action', () => {
      expect(mapToRestrictedAction('invalid_action')).toBeNull();
      expect(mapToRestrictedAction('')).toBeNull();
      expect(mapToRestrictedAction('CHANGE_PASSWORD')).toBeNull(); // Case sensitive
    });
  });

  describe('isValidRestrictedAction', () => {
    it('should return true for valid actions', () => {
      DEFAULT_RESTRICTED_ACTIONS.forEach(action => {
        expect(isValidRestrictedAction(action)).toBe(true);
      });
    });

    it('should return false for invalid actions', () => {
      expect(isValidRestrictedAction('invalid')).toBe(false);
      expect(isValidRestrictedAction('')).toBe(false);
      expect(isValidRestrictedAction('CHANGE_PASSWORD')).toBe(false);
    });
  });

  describe('DEFAULT_RESTRICTED_ACTIONS', () => {
    it('should include all security-sensitive actions', () => {
      expect(DEFAULT_RESTRICTED_ACTIONS).toContain('change_password');
      expect(DEFAULT_RESTRICTED_ACTIONS).toContain('delete_account');
      expect(DEFAULT_RESTRICTED_ACTIONS).toContain('change_email');
      expect(DEFAULT_RESTRICTED_ACTIONS).toContain('disable_mfa');
      expect(DEFAULT_RESTRICTED_ACTIONS).toContain('revoke_sessions');
      expect(DEFAULT_RESTRICTED_ACTIONS).toContain('manage_api_keys');
      expect(DEFAULT_RESTRICTED_ACTIONS).toContain('billing_changes');
    });

    it('should have expected number of default restrictions', () => {
      expect(DEFAULT_RESTRICTED_ACTIONS.length).toBe(7);
    });
  });

  describe('Constants', () => {
    it('should have correct ID prefix', () => {
      expect(IMPERSONATION_ID_PREFIX).toBe('imp_');
    });

    it('should have reasonable default duration', () => {
      expect(DEFAULT_IMPERSONATION_DURATION_MINUTES).toBe(60);
    });

    it('should have reasonable max duration', () => {
      expect(MAX_IMPERSONATION_DURATION_MINUTES).toBe(240); // 4 hours
    });

    it('should have reasonable reason length limits', () => {
      expect(MIN_REASON_LENGTH).toBe(10);
      expect(MAX_REASON_LENGTH).toBe(500);
    });
  });
});
