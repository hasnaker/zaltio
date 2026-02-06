/**
 * SSO Enforcement Middleware Tests
 * Task 19.5: Implement SSO enforcement
 * 
 * Tests for SSO enforcement middleware that blocks password login
 * when SSO is enforced for an organization.
 * 
 * Validates: Requirements 9.4, 9.6 (SSO Enforcement)
 */

import { APIGatewayProxyEvent } from 'aws-lambda';
import {
  ssoEnforcementMiddleware,
  withSSOEnforcement,
  checkSSOEnforcementForEmail,
  isSSOEnforcedForEmail,
  getSSORedirectUrlForEmail,
  getSSOEnforcementDetails,
  generateSSORedirectUrl,
  generateSAMLRedirectUrl,
  generateOIDCRedirectUrl,
  SSO_ENFORCEMENT_ERROR_CODES,
  SSOEnforcementMiddlewareOptions
} from './sso-enforcement.middleware';

// Mock dependencies
jest.mock('../services/domain-verification.service', () => ({
  checkSSOEnforcement: jest.fn()
}));

jest.mock('../services/audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue(undefined),
  AuditEventType: {
    CONFIG_CHANGE: 'config_change',
    LOGIN_FAILURE: 'login_failure',
    SUSPICIOUS_ACTIVITY: 'suspicious_activity'
  },
  AuditResult: {
    SUCCESS: 'success',
    FAILURE: 'failure'
  }
}));

import { checkSSOEnforcement } from '../services/domain-verification.service';
import { logAuditEvent } from '../services/audit.service';

const mockCheckSSOEnforcement = checkSSOEnforcement as jest.MockedFunction<typeof checkSSOEnforcement>;
const mockLogAuditEvent = logAuditEvent as jest.MockedFunction<typeof logAuditEvent>;

// ============================================================================
// TEST HELPERS
// ============================================================================

function createMockEvent(overrides: Partial<APIGatewayProxyEvent> = {}): APIGatewayProxyEvent {
  return {
    body: JSON.stringify({ email: 'user@acme.com', realm_id: 'realm_123', password: 'password123' }),
    headers: {
      'Content-Type': 'application/json'
    },
    httpMethod: 'POST',
    path: '/v1/auth/login',
    pathParameters: null,
    queryStringParameters: null,
    multiValueHeaders: {},
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      accountId: '123456789',
      apiId: 'api123',
      authorizer: null,
      protocol: 'HTTP/1.1',
      httpMethod: 'POST',
      identity: {
        accessKey: null,
        accountId: null,
        apiKey: null,
        apiKeyId: null,
        caller: null,
        clientCert: null,
        cognitoAuthenticationProvider: null,
        cognitoAuthenticationType: null,
        cognitoIdentityId: null,
        cognitoIdentityPoolId: null,
        principalOrgId: null,
        sourceIp: '192.168.1.1',
        user: null,
        userAgent: 'test-agent',
        userArn: null
      },
      path: '/v1/auth/login',
      stage: 'test',
      requestId: 'req_123',
      requestTimeEpoch: Date.now(),
      resourceId: 'resource123',
      resourcePath: '/v1/auth/login'
    },
    resource: '/v1/auth/login',
    isBase64Encoded: false,
    ...overrides
  };
}

// ============================================================================
// TESTS
// ============================================================================

describe('SSO Enforcement Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ==========================================================================
  // URL Generation Tests
  // ==========================================================================

  describe('generateSSORedirectUrl', () => {
    it('should generate SAML redirect URL', () => {
      const url = generateSSORedirectUrl('tenant_123', 'saml');
      
      expect(url).toContain('/sso/saml/initiate');
      expect(url).toContain('tenant_id=tenant_123');
    });

    it('should generate OIDC redirect URL', () => {
      const url = generateSSORedirectUrl('tenant_456', 'oidc');
      
      expect(url).toContain('/sso/oidc/initiate');
      expect(url).toContain('tenant_id=tenant_456');
    });

    it('should include login_hint when email provided', () => {
      const url = generateSSORedirectUrl('tenant_123', 'saml', 'user@acme.com');
      
      expect(url).toContain('login_hint=user%40acme.com');
    });

    it('should not include login_hint when email not provided', () => {
      const url = generateSSORedirectUrl('tenant_123', 'saml');
      
      expect(url).not.toContain('login_hint');
    });
  });

  describe('generateSAMLRedirectUrl', () => {
    it('should generate SAML redirect URL', () => {
      const url = generateSAMLRedirectUrl('tenant_123');
      
      expect(url).toContain('/sso/saml/initiate');
      expect(url).toContain('tenant_id=tenant_123');
    });

    it('should include login_hint when email provided', () => {
      const url = generateSAMLRedirectUrl('tenant_123', 'user@acme.com');
      
      expect(url).toContain('login_hint=user%40acme.com');
    });
  });

  describe('generateOIDCRedirectUrl', () => {
    it('should generate OIDC redirect URL', () => {
      const url = generateOIDCRedirectUrl('tenant_456');
      
      expect(url).toContain('/sso/oidc/initiate');
      expect(url).toContain('tenant_id=tenant_456');
    });

    it('should include login_hint when email provided', () => {
      const url = generateOIDCRedirectUrl('tenant_456', 'user@company.com');
      
      expect(url).toContain('login_hint=user%40company.com');
    });
  });

  // ==========================================================================
  // checkSSOEnforcementForEmail Tests
  // ==========================================================================

  describe('checkSSOEnforcementForEmail', () => {
    it('should return not enforced when SSO is not configured', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: false,
        reason: 'No SSO enforcement for this domain'
      });

      const result = await checkSSOEnforcementForEmail('user@example.com');

      expect(result.enforced).toBe(false);
      expect(result.reason).toBe('No SSO enforcement for this domain');
      expect(result.redirectUrl).toBeUndefined();
    });

    it('should return enforced with SAML redirect URL', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'saml',
        providerName: 'Okta'
      });

      const result = await checkSSOEnforcementForEmail('user@acme.com');

      expect(result.enforced).toBe(true);
      expect(result.tenantId).toBe('tenant_123');
      expect(result.ssoType).toBe('saml');
      expect(result.providerName).toBe('Okta');
      expect(result.redirectUrl).toContain('/sso/saml/initiate');
      expect(result.redirectUrl).toContain('tenant_id=tenant_123');
      expect(result.redirectUrl).toContain('login_hint=user%40acme.com');
    });

    it('should return enforced with OIDC redirect URL', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_456',
        ssoType: 'oidc',
        providerName: 'Google Workspace'
      });

      const result = await checkSSOEnforcementForEmail('user@company.com');

      expect(result.enforced).toBe(true);
      expect(result.ssoType).toBe('oidc');
      expect(result.redirectUrl).toContain('/sso/oidc/initiate');
    });
  });

  // ==========================================================================
  // ssoEnforcementMiddleware Tests
  // ==========================================================================

  describe('ssoEnforcementMiddleware', () => {
    describe('when SSO is not enforced', () => {
      beforeEach(() => {
        mockCheckSSOEnforcement.mockResolvedValue({
          enforced: false,
          reason: 'No SSO enforcement for this domain'
        });
      });

      it('should return null to allow password login', async () => {
        const event = createMockEvent();
        
        const result = await ssoEnforcementMiddleware(event);
        
        expect(result).toBeNull();
      });

      it('should not log audit event for allowed login', async () => {
        const event = createMockEvent();
        
        await ssoEnforcementMiddleware(event);
        
        expect(mockLogAuditEvent).not.toHaveBeenCalled();
      });
    });

    describe('when SSO is enforced', () => {
      beforeEach(() => {
        mockCheckSSOEnforcement.mockResolvedValue({
          enforced: true,
          tenantId: 'tenant_123',
          ssoType: 'saml',
          providerName: 'Okta'
        });
      });

      it('should return 403 with SSO_REQUIRED error', async () => {
        const event = createMockEvent();
        
        const result = await ssoEnforcementMiddleware(event);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
        
        const body = JSON.parse(result!.body);
        expect(body.error.code).toBe(SSO_ENFORCEMENT_ERROR_CODES.SSO_REQUIRED);
        expect(body.error.sso_required).toBe(true);
      });

      it('should include redirect URL in response', async () => {
        const event = createMockEvent();
        
        const result = await ssoEnforcementMiddleware(event);
        
        const body = JSON.parse(result!.body);
        expect(body.error.redirect_url).toContain('/sso/saml/initiate');
        expect(body.error.redirect_url).toContain('tenant_id=tenant_123');
      });

      it('should include SSO type and provider name', async () => {
        const event = createMockEvent();
        
        const result = await ssoEnforcementMiddleware(event);
        
        const body = JSON.parse(result!.body);
        expect(body.error.sso_type).toBe('saml');
        expect(body.error.provider_name).toBe('Okta');
        expect(body.error.tenant_id).toBe('tenant_123');
      });

      it('should log audit event for blocked login', async () => {
        const event = createMockEvent();
        
        await ssoEnforcementMiddleware(event);
        
        expect(mockLogAuditEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'password_login_blocked_sso_enforced',
            details: expect.objectContaining({
              email_domain: 'acme.com',
              tenant_id: 'tenant_123',
              sso_type: 'saml',
              provider_name: 'Okta'
            })
          })
        );
      });

      it('should include security headers in response', async () => {
        const event = createMockEvent();
        
        const result = await ssoEnforcementMiddleware(event);
        
        expect(result!.headers).toMatchObject({
          'Content-Type': 'application/json',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Cache-Control': 'no-store'
        });
      });
    });

    describe('when request has no email', () => {
      it('should return null to let handler validate', async () => {
        const event = createMockEvent({
          body: JSON.stringify({ realm_id: 'realm_123', password: 'password123' })
        });
        
        const result = await ssoEnforcementMiddleware(event);
        
        expect(result).toBeNull();
        expect(mockCheckSSOEnforcement).not.toHaveBeenCalled();
      });
    });

    describe('when request body is invalid', () => {
      it('should return null for invalid JSON', async () => {
        const event = createMockEvent({
          body: 'invalid json'
        });
        
        const result = await ssoEnforcementMiddleware(event);
        
        expect(result).toBeNull();
      });

      it('should return null for null body', async () => {
        const event = createMockEvent({
          body: null
        });
        
        const result = await ssoEnforcementMiddleware(event);
        
        expect(result).toBeNull();
      });
    });

    describe('with skipEnforcement option', () => {
      it('should skip enforcement check when option is true', async () => {
        mockCheckSSOEnforcement.mockResolvedValue({
          enforced: true,
          tenantId: 'tenant_123',
          ssoType: 'saml',
          providerName: 'Okta'
        });

        const event = createMockEvent();
        const options: SSOEnforcementMiddlewareOptions = { skipEnforcement: true };
        
        const result = await ssoEnforcementMiddleware(event, options);
        
        expect(result).toBeNull();
        expect(mockCheckSSOEnforcement).not.toHaveBeenCalled();
      });
    });

    describe('with bypassEmails option', () => {
      it('should bypass enforcement for listed emails', async () => {
        mockCheckSSOEnforcement.mockResolvedValue({
          enforced: true,
          tenantId: 'tenant_123',
          ssoType: 'saml',
          providerName: 'Okta'
        });

        const event = createMockEvent({
          body: JSON.stringify({ email: 'admin@acme.com', realm_id: 'realm_123', password: 'password123' })
        });
        const options: SSOEnforcementMiddlewareOptions = { 
          bypassEmails: ['admin@acme.com', 'support@acme.com'] 
        };
        
        const result = await ssoEnforcementMiddleware(event, options);
        
        expect(result).toBeNull();
        expect(mockLogAuditEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'sso_enforcement_bypassed',
            details: expect.objectContaining({
              bypass_reason: 'admin_override'
            })
          })
        );
      });

      it('should enforce for emails not in bypass list', async () => {
        mockCheckSSOEnforcement.mockResolvedValue({
          enforced: true,
          tenantId: 'tenant_123',
          ssoType: 'saml',
          providerName: 'Okta'
        });

        const event = createMockEvent();
        const options: SSOEnforcementMiddlewareOptions = { 
          bypassEmails: ['admin@acme.com'] 
        };
        
        const result = await ssoEnforcementMiddleware(event, options);
        
        expect(result).not.toBeNull();
        expect(result!.statusCode).toBe(403);
      });
    });

    describe('error handling', () => {
      it('should fail open on enforcement check error', async () => {
        mockCheckSSOEnforcement.mockRejectedValue(new Error('Database error'));

        const event = createMockEvent();
        
        const result = await ssoEnforcementMiddleware(event);
        
        expect(result).toBeNull();
        expect(mockLogAuditEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            action: 'sso_enforcement_check_error',
            errorMessage: 'Database error'
          })
        );
      });
    });
  });

  // ==========================================================================
  // withSSOEnforcement Wrapper Tests
  // ==========================================================================

  describe('withSSOEnforcement', () => {
    it('should call handler when SSO is not enforced', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: false,
        reason: 'No SSO enforcement'
      });

      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });

      const wrappedHandler = withSSOEnforcement(mockHandler);
      const event = createMockEvent();
      
      const result = await wrappedHandler(event);
      
      expect(mockHandler).toHaveBeenCalledWith(event);
      expect(result.statusCode).toBe(200);
    });

    it('should block handler when SSO is enforced', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'saml',
        providerName: 'Okta'
      });

      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });

      const wrappedHandler = withSSOEnforcement(mockHandler);
      const event = createMockEvent();
      
      const result = await wrappedHandler(event);
      
      expect(mockHandler).not.toHaveBeenCalled();
      expect(result.statusCode).toBe(403);
    });

    it('should pass options to middleware', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'saml',
        providerName: 'Okta'
      });

      const mockHandler = jest.fn().mockResolvedValue({
        statusCode: 200,
        body: JSON.stringify({ success: true })
      });

      const wrappedHandler = withSSOEnforcement(mockHandler, { skipEnforcement: true });
      const event = createMockEvent();
      
      const result = await wrappedHandler(event);
      
      expect(mockHandler).toHaveBeenCalled();
      expect(result.statusCode).toBe(200);
    });
  });

  // ==========================================================================
  // Utility Function Tests
  // ==========================================================================

  describe('isSSOEnforcedForEmail', () => {
    it('should return true when SSO is enforced', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'saml',
        providerName: 'Okta'
      });

      const result = await isSSOEnforcedForEmail('user@acme.com');

      expect(result).toBe(true);
    });

    it('should return false when SSO is not enforced', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: false,
        reason: 'No SSO enforcement'
      });

      const result = await isSSOEnforcedForEmail('user@example.com');

      expect(result).toBe(false);
    });
  });

  describe('getSSORedirectUrlForEmail', () => {
    it('should return redirect URL when SSO is enforced', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'saml',
        providerName: 'Okta'
      });

      const result = await getSSORedirectUrlForEmail('user@acme.com');

      expect(result).not.toBeNull();
      expect(result).toContain('/sso/saml/initiate');
    });

    it('should return null when SSO is not enforced', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: false,
        reason: 'No SSO enforcement'
      });

      const result = await getSSORedirectUrlForEmail('user@example.com');

      expect(result).toBeNull();
    });
  });

  describe('getSSOEnforcementDetails', () => {
    it('should return full enforcement details', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'oidc',
        providerName: 'Google Workspace'
      });

      const result = await getSSOEnforcementDetails('user@company.com');

      expect(result).toMatchObject({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'oidc',
        providerName: 'Google Workspace'
      });
      expect(result.redirectUrl).toContain('/sso/oidc/initiate');
    });
  });

  // ==========================================================================
  // Security Tests
  // ==========================================================================

  describe('Security', () => {
    it('should not leak SSO configuration details in error message', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'saml',
        providerName: 'Okta'
      });

      const event = createMockEvent();
      const result = await ssoEnforcementMiddleware(event);
      
      const body = JSON.parse(result!.body);
      
      // Should not include sensitive configuration details
      expect(body.error.message).not.toContain('certificate');
      expect(body.error.message).not.toContain('secret');
      expect(body.error.message).not.toContain('key');
    });

    it('should include no-store cache control header', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'saml',
        providerName: 'Okta'
      });

      const event = createMockEvent();
      const result = await ssoEnforcementMiddleware(event);
      
      expect(result!.headers!['Cache-Control']).toBe('no-store');
    });

    it('should handle email case insensitively', async () => {
      mockCheckSSOEnforcement.mockResolvedValue({
        enforced: true,
        tenantId: 'tenant_123',
        ssoType: 'saml',
        providerName: 'Okta'
      });

      const event = createMockEvent({
        body: JSON.stringify({ email: 'USER@ACME.COM', realm_id: 'realm_123', password: 'password123' })
      });
      
      await ssoEnforcementMiddleware(event);
      
      // Should have been called with lowercase email
      expect(mockCheckSSOEnforcement).toHaveBeenCalledWith('user@acme.com');
    });
  });
});
