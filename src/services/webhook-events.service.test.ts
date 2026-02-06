/**
 * Webhook Events Service Tests
 * Validates: Requirements 12.2, 11.8, 11.9
 */

// Mock the webhook service before importing
const mockDispatchWebhook = jest.fn();

jest.mock('./webhook.service', () => ({
  dispatchWebhook: mockDispatchWebhook
}));

import {
  dispatchUserCreated,
  dispatchUserUpdated,
  dispatchUserDeleted,
  dispatchSessionCreated,
  dispatchSessionRevoked,
  dispatchTenantCreated,
  dispatchTenantUpdated,
  dispatchMemberInvited,
  dispatchMemberJoined,
  dispatchMemberRemoved,
  dispatchMfaEnabled,
  dispatchMfaDisabled,
  dispatchHighRiskLogin,
  dispatchBatch,
  isUserEvent,
  isSessionEvent,
  isTenantEvent,
  isMemberEvent,
  isMfaEvent,
  isSecurityEvent,
  HighRiskLoginEventPayload
} from './webhook-events.service';

describe('Webhook Events Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockDispatchWebhook.mockResolvedValue({ webhooks_triggered: 1, delivery_ids: ['del_123'] });
  });

  describe('User Events', () => {
    it('should dispatch user.created event', async () => {
      const result = await dispatchUserCreated('realm_123', {
        user_id: 'user_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        first_name: 'John',
        last_name: 'Doe'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'user.created',
        expect.objectContaining({
          type: 'user.created',
          user_id: 'user_123',
          email: 'test@example.com'
        })
      );
      expect(result.webhooks_triggered).toBe(1);
    });

    it('should dispatch user.updated event', async () => {
      await dispatchUserUpdated('realm_123', {
        user_id: 'user_123',
        realm_id: 'realm_123',
        changes: { first_name: 'Jane' }
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'user.updated',
        expect.objectContaining({
          type: 'user.updated',
          user_id: 'user_123'
        })
      );
    });

    it('should dispatch user.deleted event', async () => {
      await dispatchUserDeleted('realm_123', {
        user_id: 'user_123',
        realm_id: 'realm_123'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'user.deleted',
        expect.objectContaining({
          type: 'user.deleted',
          user_id: 'user_123'
        })
      );
    });

    it('should sanitize sensitive data from user payload', async () => {
      await dispatchUserCreated('realm_123', {
        user_id: 'user_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        password: 'secret123', // Should be removed
        password_hash: 'hash123' // Should be removed
      } as any);

      const callArgs = mockDispatchWebhook.mock.calls[0][2];
      expect(callArgs.password).toBeUndefined();
      expect(callArgs.password_hash).toBeUndefined();
    });
  });

  describe('Session Events', () => {
    it('should dispatch session.created event', async () => {
      await dispatchSessionCreated('realm_123', {
        session_id: 'sess_123',
        user_id: 'user_123',
        realm_id: 'realm_123',
        device_id: 'dev_123',
        ip_address: '192.168.1.1'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'session.created',
        expect.objectContaining({
          type: 'session.created',
          session_id: 'sess_123',
          user_id: 'user_123'
        })
      );
    });

    it('should dispatch session.revoked event', async () => {
      await dispatchSessionRevoked('realm_123', {
        session_id: 'sess_123',
        user_id: 'user_123',
        realm_id: 'realm_123',
        reason: 'logout'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'session.revoked',
        expect.objectContaining({
          type: 'session.revoked',
          session_id: 'sess_123',
          reason: 'logout'
        })
      );
    });

    /**
     * Validates: Requirement 13.8
     * THE Zalt_Platform SHALL trigger session.revoked webhook
     * Include session_id, user_id, realm_id, reason in payload
     * Support reasons: logout, force_logout, impossible_travel, session_limit_exceeded
     */
    describe('session.revoked webhook reasons (Requirement 13.8)', () => {
      it('should dispatch session.revoked with logout reason', async () => {
        await dispatchSessionRevoked('realm_123', {
          session_id: 'sess_logout',
          user_id: 'user_123',
          realm_id: 'realm_123',
          reason: 'logout'
        });

        expect(mockDispatchWebhook).toHaveBeenCalledWith(
          'realm_123',
          'session.revoked',
          expect.objectContaining({
            type: 'session.revoked',
            session_id: 'sess_logout',
            user_id: 'user_123',
            realm_id: 'realm_123',
            reason: 'logout'
          })
        );
      });

      it('should dispatch session.revoked with force_logout reason', async () => {
        await dispatchSessionRevoked('realm_123', {
          session_id: 'sess_force',
          user_id: 'user_123',
          realm_id: 'realm_123',
          reason: 'force_logout'
        });

        expect(mockDispatchWebhook).toHaveBeenCalledWith(
          'realm_123',
          'session.revoked',
          expect.objectContaining({
            type: 'session.revoked',
            session_id: 'sess_force',
            user_id: 'user_123',
            realm_id: 'realm_123',
            reason: 'force_logout'
          })
        );
      });

      it('should dispatch session.revoked with impossible_travel reason', async () => {
        await dispatchSessionRevoked('realm_123', {
          session_id: 'sess_travel',
          user_id: 'user_123',
          realm_id: 'realm_123',
          reason: 'impossible_travel'
        });

        expect(mockDispatchWebhook).toHaveBeenCalledWith(
          'realm_123',
          'session.revoked',
          expect.objectContaining({
            type: 'session.revoked',
            session_id: 'sess_travel',
            user_id: 'user_123',
            realm_id: 'realm_123',
            reason: 'impossible_travel'
          })
        );
      });

      it('should dispatch session.revoked with session_limit_exceeded reason', async () => {
        await dispatchSessionRevoked('realm_123', {
          session_id: 'sess_limit',
          user_id: 'user_123',
          realm_id: 'realm_123',
          reason: 'session_limit_exceeded'
        });

        expect(mockDispatchWebhook).toHaveBeenCalledWith(
          'realm_123',
          'session.revoked',
          expect.objectContaining({
            type: 'session.revoked',
            session_id: 'sess_limit',
            user_id: 'user_123',
            realm_id: 'realm_123',
            reason: 'session_limit_exceeded'
          })
        );
      });

      it('should dispatch session.revoked with password_change reason', async () => {
        await dispatchSessionRevoked('realm_123', {
          session_id: 'sess_pwd',
          user_id: 'user_123',
          realm_id: 'realm_123',
          reason: 'password_change'
        });

        expect(mockDispatchWebhook).toHaveBeenCalledWith(
          'realm_123',
          'session.revoked',
          expect.objectContaining({
            type: 'session.revoked',
            session_id: 'sess_pwd',
            user_id: 'user_123',
            realm_id: 'realm_123',
            reason: 'password_change'
          })
        );
      });

      it('should dispatch session.revoked with security reason', async () => {
        await dispatchSessionRevoked('realm_123', {
          session_id: 'sess_sec',
          user_id: 'user_123',
          realm_id: 'realm_123',
          reason: 'security'
        });

        expect(mockDispatchWebhook).toHaveBeenCalledWith(
          'realm_123',
          'session.revoked',
          expect.objectContaining({
            type: 'session.revoked',
            session_id: 'sess_sec',
            user_id: 'user_123',
            realm_id: 'realm_123',
            reason: 'security'
          })
        );
      });

      it('should dispatch session.revoked with expired reason', async () => {
        await dispatchSessionRevoked('realm_123', {
          session_id: 'sess_exp',
          user_id: 'user_123',
          realm_id: 'realm_123',
          reason: 'expired'
        });

        expect(mockDispatchWebhook).toHaveBeenCalledWith(
          'realm_123',
          'session.revoked',
          expect.objectContaining({
            type: 'session.revoked',
            session_id: 'sess_exp',
            user_id: 'user_123',
            realm_id: 'realm_123',
            reason: 'expired'
          })
        );
      });

      it('should dispatch session.revoked without reason (optional)', async () => {
        await dispatchSessionRevoked('realm_123', {
          session_id: 'sess_no_reason',
          user_id: 'user_123',
          realm_id: 'realm_123'
        });

        expect(mockDispatchWebhook).toHaveBeenCalledWith(
          'realm_123',
          'session.revoked',
          expect.objectContaining({
            type: 'session.revoked',
            session_id: 'sess_no_reason',
            user_id: 'user_123',
            realm_id: 'realm_123'
          })
        );
      });

      it('should include all required fields in session.revoked payload', async () => {
        await dispatchSessionRevoked('realm_test', {
          session_id: 'sess_full',
          user_id: 'user_full',
          realm_id: 'realm_test',
          reason: 'logout'
        });

        const callArgs = mockDispatchWebhook.mock.calls[0][2];
        
        // Verify all required fields are present
        expect(callArgs).toHaveProperty('type', 'session.revoked');
        expect(callArgs).toHaveProperty('session_id', 'sess_full');
        expect(callArgs).toHaveProperty('user_id', 'user_full');
        expect(callArgs).toHaveProperty('realm_id', 'realm_test');
        expect(callArgs).toHaveProperty('reason', 'logout');
      });
    });
  });

  describe('Tenant Events', () => {
    it('should dispatch tenant.created event', async () => {
      await dispatchTenantCreated('realm_123', {
        tenant_id: 'tenant_123',
        realm_id: 'realm_123',
        name: 'Acme Corp',
        slug: 'acme-corp'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'tenant.created',
        expect.objectContaining({
          type: 'tenant.created',
          tenant_id: 'tenant_123',
          name: 'Acme Corp'
        })
      );
    });

    it('should dispatch tenant.updated event', async () => {
      await dispatchTenantUpdated('realm_123', {
        tenant_id: 'tenant_123',
        realm_id: 'realm_123',
        name: 'Acme Corporation',
        changes: { name: 'Acme Corporation' }
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'tenant.updated',
        expect.objectContaining({
          type: 'tenant.updated',
          tenant_id: 'tenant_123'
        })
      );
    });
  });

  describe('Member Events', () => {
    it('should dispatch member.invited event (Requirement 11.8)', async () => {
      await dispatchMemberInvited('realm_123', {
        invitation_id: 'inv_123',
        tenant_id: 'tenant_123',
        realm_id: 'realm_123',
        email: 'invitee@example.com',
        role: 'member',
        invited_by: 'user_123',
        status: 'pending'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'member.invited',
        expect.objectContaining({
          type: 'member.invited',
          invitation_id: 'inv_123',
          email: 'invitee@example.com'
        })
      );
    });

    it('should dispatch member.joined event (Requirement 11.9)', async () => {
      await dispatchMemberJoined('realm_123', {
        membership_id: 'mem_123',
        user_id: 'user_456',
        tenant_id: 'tenant_123',
        realm_id: 'realm_123',
        role: 'member',
        invitation_id: 'inv_123'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'member.joined',
        expect.objectContaining({
          type: 'member.joined',
          membership_id: 'mem_123',
          user_id: 'user_456'
        })
      );
    });

    it('should dispatch member.removed event', async () => {
      await dispatchMemberRemoved('realm_123', {
        membership_id: 'mem_123',
        user_id: 'user_456',
        tenant_id: 'tenant_123',
        realm_id: 'realm_123',
        removed_by: 'admin_123',
        reason: 'Terminated'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'member.removed',
        expect.objectContaining({
          type: 'member.removed',
          membership_id: 'mem_123',
          removed_by: 'admin_123'
        })
      );
    });
  });

  describe('MFA Events', () => {
    it('should dispatch mfa.enabled event', async () => {
      await dispatchMfaEnabled('realm_123', {
        user_id: 'user_123',
        realm_id: 'realm_123',
        mfa_type: 'totp'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'mfa.enabled',
        expect.objectContaining({
          type: 'mfa.enabled',
          user_id: 'user_123',
          mfa_type: 'totp'
        })
      );
    });

    it('should dispatch mfa.disabled event', async () => {
      await dispatchMfaDisabled('realm_123', {
        user_id: 'user_123',
        realm_id: 'realm_123',
        mfa_type: 'totp',
        disabled_by: 'admin_123'
      });

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'mfa.disabled',
        expect.objectContaining({
          type: 'mfa.disabled',
          user_id: 'user_123',
          disabled_by: 'admin_123'
        })
      );
    });
  });

  describe('Batch Dispatch', () => {
    it('should dispatch multiple events', async () => {
      const events = [
        { realmId: 'realm_123', eventType: 'user.created' as any, data: { user_id: 'user_1' } },
        { realmId: 'realm_123', eventType: 'user.created' as any, data: { user_id: 'user_2' } }
      ];

      const results = await dispatchBatch(events);

      expect(mockDispatchWebhook).toHaveBeenCalledTimes(2);
      expect(results).toHaveLength(2);
    });

    it('should handle partial failures in batch', async () => {
      mockDispatchWebhook
        .mockResolvedValueOnce({ webhooks_triggered: 1, delivery_ids: ['del_1'] })
        .mockRejectedValueOnce(new Error('Failed'));

      const events = [
        { realmId: 'realm_123', eventType: 'user.created' as any, data: { user_id: 'user_1' } },
        { realmId: 'realm_123', eventType: 'user.created' as any, data: { user_id: 'user_2' } }
      ];

      const results = await dispatchBatch(events);

      expect(results[0].webhooks_triggered).toBe(1);
      expect(results[1].webhooks_triggered).toBe(0);
    });
  });

  describe('Event Type Guards', () => {
    it('should identify user events', () => {
      expect(isUserEvent('user.created')).toBe(true);
      expect(isUserEvent('user.updated')).toBe(true);
      expect(isUserEvent('user.deleted')).toBe(true);
      expect(isUserEvent('session.created')).toBe(false);
    });

    it('should identify session events', () => {
      expect(isSessionEvent('session.created')).toBe(true);
      expect(isSessionEvent('session.revoked')).toBe(true);
      expect(isSessionEvent('user.created')).toBe(false);
    });

    it('should identify tenant events', () => {
      expect(isTenantEvent('tenant.created')).toBe(true);
      expect(isTenantEvent('tenant.updated')).toBe(true);
      expect(isTenantEvent('user.created')).toBe(false);
    });

    it('should identify member events', () => {
      expect(isMemberEvent('member.invited')).toBe(true);
      expect(isMemberEvent('member.joined')).toBe(true);
      expect(isMemberEvent('member.removed')).toBe(true);
      expect(isMemberEvent('user.created')).toBe(false);
    });

    it('should identify MFA events', () => {
      expect(isMfaEvent('mfa.enabled')).toBe(true);
      expect(isMfaEvent('mfa.disabled')).toBe(true);
      expect(isMfaEvent('user.created')).toBe(false);
    });

    it('should identify security events', () => {
      expect(isSecurityEvent('security.high_risk_login')).toBe(true);
      expect(isSecurityEvent('security.suspicious_activity')).toBe(true);
      expect(isSecurityEvent('user.created')).toBe(false);
    });
  });

  describe('Security Events (Requirement 10.9)', () => {
    it('should dispatch security.high_risk_login event when login is blocked', async () => {
      const payload: HighRiskLoginEventPayload = {
        user_id: 'user_123',
        realm_id: 'realm_123',
        email: 'test@example.com',
        risk_score: 95,
        risk_level: 'critical',
        risk_factors: [
          {
            type: 'impossible_travel',
            severity: 'critical',
            score: 80,
            description: 'Impossible travel detected'
          },
          {
            type: 'new_device',
            severity: 'medium',
            score: 40,
            description: 'Login from new/unrecognized device'
          }
        ],
        recommendation: 'block',
        ip_address: '203.0.113.1',
        location: {
          city: 'Istanbul',
          country: 'Turkey',
          country_code: 'TR'
        },
        device: {
          user_agent: 'Mozilla/5.0 Chrome/120.0.0.0',
          is_new_device: true
        },
        action_taken: 'blocked',
        assessment_id: 'risk_123456_abc',
        timestamp: '2026-01-16T12:00:00Z'
      };

      await dispatchHighRiskLogin('realm_123', payload);

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'security.high_risk_login',
        expect.objectContaining({
          type: 'security.high_risk_login',
          user_id: 'user_123',
          risk_score: 95,
          risk_level: 'critical',
          action_taken: 'blocked'
        })
      );
    });

    it('should dispatch security.high_risk_login event when MFA is required', async () => {
      const payload: HighRiskLoginEventPayload = {
        user_id: 'user_456',
        realm_id: 'realm_123',
        email: 'user@example.com',
        risk_score: 75,
        risk_level: 'high',
        risk_factors: [
          {
            type: 'vpn_detected',
            severity: 'medium',
            score: 30,
            description: 'VPN connection detected'
          },
          {
            type: 'unusual_time',
            severity: 'low',
            score: 15,
            description: 'Login at unusual hour'
          }
        ],
        recommendation: 'mfa_required',
        ip_address: '198.51.100.1',
        action_taken: 'mfa_required',
        assessment_id: 'risk_789012_def',
        timestamp: '2026-01-16T03:00:00Z'
      };

      await dispatchHighRiskLogin('realm_123', payload);

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'security.high_risk_login',
        expect.objectContaining({
          type: 'security.high_risk_login',
          risk_score: 75,
          risk_level: 'high',
          recommendation: 'mfa_required',
          action_taken: 'mfa_required'
        })
      );
    });

    it('should include all risk factors in the webhook payload', async () => {
      const riskFactors = [
        { type: 'new_device', severity: 'medium' as const, score: 40, description: 'New device' },
        { type: 'tor_detected', severity: 'high' as const, score: 60, description: 'Tor exit node' },
        { type: 'failed_attempts', severity: 'medium' as const, score: 30, description: '3 failed attempts' }
      ];

      const payload: HighRiskLoginEventPayload = {
        user_id: 'user_789',
        realm_id: 'realm_123',
        email: 'risky@example.com',
        risk_score: 85,
        risk_level: 'high',
        risk_factors: riskFactors,
        recommendation: 'mfa_required',
        ip_address: '192.0.2.1',
        action_taken: 'mfa_required',
        assessment_id: 'risk_test_123',
        timestamp: new Date().toISOString()
      };

      await dispatchHighRiskLogin('realm_123', payload);

      const callArgs = mockDispatchWebhook.mock.calls[0][2];
      expect(callArgs.risk_factors).toHaveLength(3);
      expect(callArgs.risk_factors[0].type).toBe('new_device');
      expect(callArgs.risk_factors[1].type).toBe('tor_detected');
      expect(callArgs.risk_factors[2].type).toBe('failed_attempts');
    });

    it('should include location data when available', async () => {
      const payload: HighRiskLoginEventPayload = {
        user_id: 'user_geo',
        realm_id: 'realm_123',
        email: 'geo@example.com',
        risk_score: 80,
        risk_level: 'high',
        risk_factors: [],
        recommendation: 'mfa_required',
        ip_address: '203.0.113.50',
        location: {
          city: 'New York',
          country: 'United States',
          country_code: 'US'
        },
        action_taken: 'mfa_required',
        assessment_id: 'risk_geo_123',
        timestamp: new Date().toISOString()
      };

      await dispatchHighRiskLogin('realm_123', payload);

      const callArgs = mockDispatchWebhook.mock.calls[0][2];
      expect(callArgs.location).toEqual({
        city: 'New York',
        country: 'United States',
        country_code: 'US'
      });
    });

    it('should handle missing optional fields gracefully', async () => {
      const payload: HighRiskLoginEventPayload = {
        user_id: 'user_minimal',
        realm_id: 'realm_123',
        email: 'minimal@example.com',
        risk_score: 92,
        risk_level: 'critical',
        risk_factors: [],
        recommendation: 'block',
        ip_address: '10.0.0.1',
        action_taken: 'blocked',
        assessment_id: 'risk_minimal_123',
        timestamp: new Date().toISOString()
      };

      await dispatchHighRiskLogin('realm_123', payload);

      expect(mockDispatchWebhook).toHaveBeenCalledWith(
        'realm_123',
        'security.high_risk_login',
        expect.objectContaining({
          type: 'security.high_risk_login',
          user_id: 'user_minimal',
          risk_score: 92
        })
      );
    });

    it('should sanitize sensitive data from high-risk login payload', async () => {
      const payload = {
        user_id: 'user_sensitive',
        realm_id: 'realm_123',
        email: 'sensitive@example.com',
        risk_score: 88,
        risk_level: 'high' as const,
        risk_factors: [],
        recommendation: 'mfa_required' as const,
        ip_address: '192.168.1.1',
        action_taken: 'mfa_required' as const,
        assessment_id: 'risk_sensitive_123',
        timestamp: new Date().toISOString(),
        // These should be removed by sanitization
        password: 'secret123',
        token: 'jwt_token_xxx',
        secret: 'webhook_secret'
      } as HighRiskLoginEventPayload & { password: string; token: string; secret: string };

      await dispatchHighRiskLogin('realm_123', payload);

      const callArgs = mockDispatchWebhook.mock.calls[0][2];
      expect(callArgs.password).toBeUndefined();
      expect(callArgs.token).toBeUndefined();
      expect(callArgs.secret).toBeUndefined();
    });
  });

  describe('Security - Payload Sanitization', () => {
    it('should remove password from payload', async () => {
      await dispatchUserCreated('realm_123', {
        user_id: 'user_123',
        realm_id: 'realm_123',
        password: 'secret' // Should be removed
      } as any);

      const payload = mockDispatchWebhook.mock.calls[0][2];
      expect(payload.password).toBeUndefined();
    });

    it('should remove token from payload', async () => {
      await dispatchSessionCreated('realm_123', {
        session_id: 'sess_123',
        user_id: 'user_123',
        realm_id: 'realm_123',
        token: 'jwt_token', // Should be removed
        access_token: 'access', // Should be removed
        refresh_token: 'refresh' // Should be removed
      } as any);

      const payload = mockDispatchWebhook.mock.calls[0][2];
      expect(payload.token).toBeUndefined();
      expect(payload.access_token).toBeUndefined();
      expect(payload.refresh_token).toBeUndefined();
    });

    it('should remove api_key from payload', async () => {
      await dispatchUserUpdated('realm_123', {
        user_id: 'user_123',
        realm_id: 'realm_123',
        api_key: 'zalt_key_xxx' // Should be removed
      } as any);

      const payload = mockDispatchWebhook.mock.calls[0][2];
      expect(payload.api_key).toBeUndefined();
    });
  });
});
