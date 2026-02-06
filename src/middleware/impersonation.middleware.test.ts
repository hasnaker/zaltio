/**
 * Impersonation Restrictions Middleware Tests
 * Task 11.4: Impersonation restrictions middleware
 * 
 * Validates: Requirements 6.8 (Impersonation Restrictions)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  impersonationRestrictionsMiddleware,
  matchRestrictedEndpoint,
  isActionRestrictedForSession,
  getImpersonationContext,
  withImpersonationRestrictions,
  ENDPOINT_RESTRICTIONS
} from './impersonation.middleware';

// Mock dependencies
jest.mock('../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../services/audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue(undefined),
  AuditEventType: {
    ADMIN_ACTION: 'admin_action'
  },
  AuditResult: {
    SUCCESS: 'success',
    FAILURE: 'failure'
  }
}));

jest.mock('../services/impersonation.service', () => {
  const mockService = {
    validateToken: jest.fn(),
    logBlockedAction: jest.fn().mockResolvedValue(undefined)
  };
  
  return {
    ImpersonationService: jest.fn(() => mockService),
    DEFAULT_RESTRICTED_ACTIONS: [
      'change_password',
      'delete_account',
      'change_email',
      'disable_mfa',
      'revoke_sessions',
      'manage_api_keys',
      'billing_changes'
    ]
  };
});

import { verifyAccessToken } from '../utils/jwt';
import { logAuditEvent } from '../services/audit.service';
import { ImpersonationService } from '../services/impersonation.service';

const mockVerifyAccessToken = verifyAccessToken as jest.Mock;
const mockLogAuditEvent = logAuditEvent as jest.Mock;
const mockImpersonationService = new ImpersonationService() as jest.Mocked<ImpersonationService>;

/**
 * Create mock API Gateway event
 */
function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    httpMethod: 'PUT',
    path: '/me/password',
    pathParameters: null,
    queryStringParameters: null,
    headers: {
      Authorization: 'Bearer valid-token'
    },
    body: null,
    requestContext: {
      identity: {
        sourceIp: '192.168.1.100'
      }
    } as APIGatewayProxyEvent['requestContext'],
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    stageVariables: null,
    resource: '',
    isBase64Encoded: false,
    ...overrides
  };
}

describe('Impersonation Restrictions Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default: not impersonating
    mockImpersonationService.validateToken.mockResolvedValue(null);
    mockVerifyAccessToken.mockResolvedValue({
      sub: 'user-123',
      realm_id: 'test-realm-123',
      is_admin: false
    });
  });

  describe('matchRestrictedEndpoint', () => {
    it('should match password change endpoint', () => {
      const result = matchRestrictedEndpoint('/me/password', 'PUT');
      
      expect(result.matched).toBe(true);
      expect(result.action).toBe('change_password');
    });

    it('should match email change endpoint', () => {
      const result = matchRestrictedEndpoint('/me/email', 'PATCH');
      
      expect(result.matched).toBe(true);
      expect(result.action).toBe('change_email');
    });

    it('should match account deletion endpoint', () => {
      const result = matchRestrictedEndpoint('/me/delete', 'DELETE');
      
      expect(result.matched).toBe(true);
      expect(result.action).toBe('delete_account');
    });

    it('should match MFA disable endpoint', () => {
      const result = matchRestrictedEndpoint('/mfa/disable', 'POST');
      
      expect(result.matched).toBe(true);
      expect(result.action).toBe('disable_mfa');
    });

    it('should match session revoke endpoint', () => {
      const result = matchRestrictedEndpoint('/sessions/revoke-all', 'POST');
      
      expect(result.matched).toBe(true);
      expect(result.action).toBe('revoke_sessions');
    });

    it('should match API keys endpoint', () => {
      const result = matchRestrictedEndpoint('/api-keys', 'POST');
      
      expect(result.matched).toBe(true);
      expect(result.action).toBe('manage_api_keys');
    });

    it('should match billing endpoints', () => {
      expect(matchRestrictedEndpoint('/billing/subscribe', 'POST').action).toBe('billing_changes');
      expect(matchRestrictedEndpoint('/billing/cancel', 'POST').action).toBe('billing_changes');
    });

    it('should not match unrestricted endpoints', () => {
      expect(matchRestrictedEndpoint('/me/profile', 'GET').matched).toBe(false);
      expect(matchRestrictedEndpoint('/users', 'GET').matched).toBe(false);
      expect(matchRestrictedEndpoint('/sessions', 'GET').matched).toBe(false);
    });

    it('should not match wrong HTTP methods', () => {
      expect(matchRestrictedEndpoint('/me/password', 'GET').matched).toBe(false);
      expect(matchRestrictedEndpoint('/me/delete', 'GET').matched).toBe(false);
    });

    it('should be case insensitive for paths', () => {
      expect(matchRestrictedEndpoint('/ME/PASSWORD', 'PUT').matched).toBe(true);
      expect(matchRestrictedEndpoint('/Me/Email', 'PATCH').matched).toBe(true);
    });

    it('should match paths with trailing slashes', () => {
      expect(matchRestrictedEndpoint('/me/password/', 'PUT').matched).toBe(true);
    });
  });

  describe('impersonationRestrictionsMiddleware', () => {
    describe('when not impersonating', () => {
      it('should allow restricted endpoints', async () => {
        const event = createMockEvent({
          path: '/me/password',
          httpMethod: 'PUT'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).toBeNull();
      });

      it('should allow unrestricted endpoints', async () => {
        const event = createMockEvent({
          path: '/me/profile',
          httpMethod: 'GET'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).toBeNull();
      });
    });

    describe('when impersonating', () => {
      beforeEach(() => {
        mockImpersonationService.validateToken.mockResolvedValue({
          id: 'imp_test123',
          realm_id: 'test-realm-123',
          admin_id: 'admin-001',
          admin_email: 'admin@example.com',
          target_user_id: 'user-123',
          target_user_email: 'user@example.com',
          reason: 'Test',
          status: 'active',
          restricted_actions: [
            'change_password',
            'delete_account',
            'change_email',
            'disable_mfa',
            'revoke_sessions',
            'manage_api_keys',
            'billing_changes'
          ],
          access_token: 'imp-token',
          refresh_token_hash: 'hash',
          started_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
          ip_address: '127.0.0.1',
          user_agent: 'Test',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        });
      });

      it('should block password change', async () => {
        const event = createMockEvent({
          path: '/me/password',
          httpMethod: 'PUT'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
        
        const body = JSON.parse(result!.body);
        expect(body.error.code).toBe('IMPERSONATION_RESTRICTED');
        expect(body.error.restricted_action).toBe('change_password');
      });

      it('should block account deletion', async () => {
        const event = createMockEvent({
          path: '/me/delete',
          httpMethod: 'DELETE'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
        
        const body = JSON.parse(result!.body);
        expect(body.error.restricted_action).toBe('delete_account');
      });

      it('should block email change', async () => {
        const event = createMockEvent({
          path: '/me/email',
          httpMethod: 'PATCH'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
        
        const body = JSON.parse(result!.body);
        expect(body.error.restricted_action).toBe('change_email');
      });

      it('should block MFA disable', async () => {
        const event = createMockEvent({
          path: '/mfa/disable',
          httpMethod: 'POST'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
        
        const body = JSON.parse(result!.body);
        expect(body.error.restricted_action).toBe('disable_mfa');
      });

      it('should block session revocation', async () => {
        const event = createMockEvent({
          path: '/sessions/revoke-all',
          httpMethod: 'POST'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
        
        const body = JSON.parse(result!.body);
        expect(body.error.restricted_action).toBe('revoke_sessions');
      });

      it('should block API key management', async () => {
        const event = createMockEvent({
          path: '/api-keys',
          httpMethod: 'POST'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
        
        const body = JSON.parse(result!.body);
        expect(body.error.restricted_action).toBe('manage_api_keys');
      });

      it('should block billing changes', async () => {
        const event = createMockEvent({
          path: '/billing/subscribe',
          httpMethod: 'POST'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
        
        const body = JSON.parse(result!.body);
        expect(body.error.restricted_action).toBe('billing_changes');
      });

      it('should allow unrestricted endpoints', async () => {
        const event = createMockEvent({
          path: '/me/profile',
          httpMethod: 'GET'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).toBeNull();
      });

      it('should log blocked actions', async () => {
        const event = createMockEvent({
          path: '/me/password',
          httpMethod: 'PUT'
        });
        
        await impersonationRestrictionsMiddleware(event);
        
        expect(mockLogAuditEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'impersonation_action_blocked',
            result: 'failure'
          })
        );
        
        expect(mockImpersonationService.logBlockedAction).toHaveBeenCalledWith(
          'imp_test123',
          'change_password'
        );
      });

      it('should include session ID in error response', async () => {
        const event = createMockEvent({
          path: '/me/password',
          httpMethod: 'PUT'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        const body = JSON.parse(result!.body);
        
        expect(body.error.impersonation_session_id).toBe('imp_test123');
      });

      it('should allow actions not in restricted list', async () => {
        // Session with limited restrictions
        mockImpersonationService.validateToken.mockResolvedValue({
          id: 'imp_test123',
          realm_id: 'test-realm-123',
          admin_id: 'admin-001',
          admin_email: 'admin@example.com',
          target_user_id: 'user-123',
          target_user_email: 'user@example.com',
          reason: 'Test',
          status: 'active',
          restricted_actions: ['change_password'], // Only password change restricted
          access_token: 'imp-token',
          refresh_token_hash: 'hash',
          started_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
          ip_address: '127.0.0.1',
          user_agent: 'Test',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        });
        
        // Email change should be allowed
        const event = createMockEvent({
          path: '/me/email',
          httpMethod: 'PATCH'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).toBeNull();
      });
    });

    describe('with JWT impersonation claims', () => {
      beforeEach(() => {
        mockImpersonationService.validateToken.mockResolvedValue(null);
        mockVerifyAccessToken.mockResolvedValue({
          sub: 'user-123',
          realm_id: 'test-realm-123',
          is_impersonation: true,
          impersonation_session_id: 'imp_jwt123',
          admin_id: 'admin-001',
          restricted_actions: ['change_password', 'delete_account']
        });
      });

      it('should block restricted actions from JWT claims', async () => {
        const event = createMockEvent({
          path: '/me/password',
          httpMethod: 'PUT'
        });
        
        const result = await impersonationRestrictionsMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
      });
    });
  });

  describe('isActionRestrictedForSession', () => {
    it('should return false when not impersonating', async () => {
      const event = createMockEvent();
      
      const result = await isActionRestrictedForSession(event, 'change_password');
      
      expect(result).toBe(false);
    });

    it('should return true for restricted action when impersonating', async () => {
      mockImpersonationService.validateToken.mockResolvedValue({
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-123',
        target_user_email: 'user@example.com',
        reason: 'Test',
        status: 'active',
        restricted_actions: ['change_password'],
        access_token: 'imp-token',
        refresh_token_hash: 'hash',
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      
      const event = createMockEvent();
      
      const result = await isActionRestrictedForSession(event, 'change_password');
      
      expect(result).toBe(true);
    });

    it('should return false for non-restricted action when impersonating', async () => {
      mockImpersonationService.validateToken.mockResolvedValue({
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-123',
        target_user_email: 'user@example.com',
        reason: 'Test',
        status: 'active',
        restricted_actions: ['change_password'], // Only password restricted
        access_token: 'imp-token',
        refresh_token_hash: 'hash',
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      
      const event = createMockEvent();
      
      const result = await isActionRestrictedForSession(event, 'delete_account');
      
      expect(result).toBe(false);
    });
  });

  describe('getImpersonationContext', () => {
    it('should return null when not impersonating', async () => {
      const event = createMockEvent();
      
      const result = await getImpersonationContext(event);
      
      expect(result).toBeNull();
    });

    it('should return context when impersonating', async () => {
      mockImpersonationService.validateToken.mockResolvedValue({
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-123',
        target_user_email: 'user@example.com',
        reason: 'Test',
        status: 'active',
        restricted_actions: ['change_password'],
        access_token: 'imp-token',
        refresh_token_hash: 'hash',
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      
      const event = createMockEvent();
      
      const result = await getImpersonationContext(event);
      
      expect(result).not.toBeNull();
      expect(result!.isImpersonating).toBe(true);
      expect(result!.sessionId).toBe('imp_test123');
      expect(result!.adminId).toBe('admin-001');
      expect(result!.targetUserId).toBe('user-123');
    });
  });

  describe('withImpersonationRestrictions', () => {
    it('should call handler when not restricted', async () => {
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });
      
      const wrappedHandler = withImpersonationRestrictions(mockHandler);
      const event = createMockEvent({
        path: '/me/profile',
        httpMethod: 'GET'
      });
      
      const result = await wrappedHandler(event);
      
      expect(mockHandler).toHaveBeenCalledWith(event);
      expect(result.statusCode).toBe(200);
    });

    it('should block handler when restricted during impersonation', async () => {
      mockImpersonationService.validateToken.mockResolvedValue({
        id: 'imp_test123',
        realm_id: 'test-realm-123',
        admin_id: 'admin-001',
        admin_email: 'admin@example.com',
        target_user_id: 'user-123',
        target_user_email: 'user@example.com',
        reason: 'Test',
        status: 'active',
        restricted_actions: ['change_password'],
        access_token: 'imp-token',
        refresh_token_hash: 'hash',
        started_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        ip_address: '127.0.0.1',
        user_agent: 'Test',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      
      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });
      
      const wrappedHandler = withImpersonationRestrictions(mockHandler);
      const event = createMockEvent({
        path: '/me/password',
        httpMethod: 'PUT'
      });
      
      const result = await wrappedHandler(event);
      
      expect(mockHandler).not.toHaveBeenCalled();
      expect(result.statusCode).toBe(403);
    });
  });

  describe('ENDPOINT_RESTRICTIONS', () => {
    it('should have all required restricted endpoints', () => {
      expect(ENDPOINT_RESTRICTIONS['/me/password']).toBeDefined();
      expect(ENDPOINT_RESTRICTIONS['/me/email']).toBeDefined();
      expect(ENDPOINT_RESTRICTIONS['/me/delete']).toBeDefined();
      expect(ENDPOINT_RESTRICTIONS['/mfa/disable']).toBeDefined();
      expect(ENDPOINT_RESTRICTIONS['/sessions/revoke-all']).toBeDefined();
      expect(ENDPOINT_RESTRICTIONS['/api-keys']).toBeDefined();
      expect(ENDPOINT_RESTRICTIONS['/billing/subscribe']).toBeDefined();
    });

    it('should map to correct restricted actions', () => {
      expect(ENDPOINT_RESTRICTIONS['/me/password'].action).toBe('change_password');
      expect(ENDPOINT_RESTRICTIONS['/me/email'].action).toBe('change_email');
      expect(ENDPOINT_RESTRICTIONS['/me/delete'].action).toBe('delete_account');
      expect(ENDPOINT_RESTRICTIONS['/mfa/disable'].action).toBe('disable_mfa');
      expect(ENDPOINT_RESTRICTIONS['/sessions/revoke-all'].action).toBe('revoke_sessions');
      expect(ENDPOINT_RESTRICTIONS['/api-keys'].action).toBe('manage_api_keys');
      expect(ENDPOINT_RESTRICTIONS['/billing/subscribe'].action).toBe('billing_changes');
    });
  });
});
