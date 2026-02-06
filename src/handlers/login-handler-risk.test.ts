/**
 * Login Handler Risk Assessment Integration Tests
 * Task 15.4: Integrate risk assessment with login flow
 * 
 * Tests:
 * - Risk score calculation on login attempt
 * - Score > 70: Require MFA regardless of user settings
 * - Score > 90: Block login and notify admin
 * - Risk score stored in audit log for all attempts
 * - Graceful error handling (fail open with logging)
 * 
 * Validates: Requirements 10.3, 10.4, 10.10
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { handler } from './login-handler';

// Mock dependencies
jest.mock('../repositories/user.repository');
jest.mock('../repositories/realm.repository');
jest.mock('../repositories/session.repository');
jest.mock('../services/ratelimit.service');
jest.mock('../services/security-logger.service');
jest.mock('../services/realm.service');
jest.mock('../services/session-task-integration.service');
jest.mock('../services/ai-risk.service');
jest.mock('../services/geo-velocity.service');
jest.mock('../utils/password');
jest.mock('../utils/jwt');

import { findUserByEmail, updateUserLoginAttempts } from '../repositories/user.repository';
import { findRealmById, getRealmSettings } from '../repositories/realm.repository';
import { createSession, createMfaSession } from '../repositories/session.repository';
import { checkRateLimit } from '../services/ratelimit.service';
import { logSecurityEvent } from '../services/security-logger.service';
import { checkMfaEnforcement, checkMfaSetupRequired } from '../services/realm.service';
import { sessionTaskIntegrationService } from '../services/session-task-integration.service';
import { createAIRiskService, RiskAssessmentResult, RiskFactorType } from '../services/ai-risk.service';
import { lookupIpLocation } from '../services/geo-velocity.service';
import { verifyPassword, needsRehash } from '../utils/password';
import { generateTokenPair } from '../utils/jwt';

// ============================================================================
// Test Fixtures
// ============================================================================

const mockUser = {
  id: 'user_123',
  realm_id: 'test-realm',
  email: 'test@example.com',
  password_hash: '$argon2id$v=19$m=32768,t=5,p=2$...',
  email_verified: true,
  status: 'active',
  mfa_enabled: false,
  failed_login_attempts: 0,
  created_at: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
  profile: { name: 'Test User' }
};

const mockRealm = {
  id: 'test-realm',
  name: 'Test Realm',
  status: 'active'
};

const mockRealmSettings = {
  session_timeout: 900,
  mfa_policy: 'optional'
};

const createMockEvent = (body: Record<string, unknown>): APIGatewayProxyEvent => ({
  body: JSON.stringify(body),
  headers: {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
  },
  httpMethod: 'POST',
  isBase64Encoded: false,
  path: '/login',
  pathParameters: null,
  queryStringParameters: null,
  multiValueQueryStringParameters: null,
  multiValueHeaders: {},
  stageVariables: null,
  requestContext: {
    accountId: '123456789',
    apiId: 'api123',
    authorizer: null,
    protocol: 'HTTP/1.1',
    httpMethod: 'POST',
    identity: {
      sourceIp: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
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
      user: null,
      userArn: null
    },
    path: '/login',
    stage: 'test',
    requestId: 'req_123',
    requestTimeEpoch: Date.now(),
    resourceId: 'resource123',
    resourcePath: '/login'
  },
  resource: '/login'
});

const createLowRiskAssessment = (): RiskAssessmentResult => ({
  riskScore: 25,
  riskLevel: 'low',
  deviceRisk: 10,
  geoRisk: 5,
  behaviorRisk: 5,
  credentialRisk: 0,
  networkRisk: 5,
  historicalRisk: 0,
  riskFactors: [],
  requiresMfa: false,
  requiresVerification: false,
  shouldBlock: false,
  shouldAlert: false,
  adaptiveAuthLevel: 'none',
  explanation: 'No risk factors detected',
  assessmentId: 'risk_123',
  timestamp: new Date().toISOString(),
  modelVersion: '1.0.0'
});

const createMediumRiskAssessment = (): RiskAssessmentResult => ({
  riskScore: 75,
  riskLevel: 'high',
  deviceRisk: 40,
  geoRisk: 30,
  behaviorRisk: 20,
  credentialRisk: 0,
  networkRisk: 10,
  historicalRisk: 0,
  riskFactors: [
    {
      type: RiskFactorType.NEW_DEVICE,
      severity: 'medium',
      score: 40,
      description: 'Login from new device'
    },
    {
      type: RiskFactorType.VPN_DETECTED,
      severity: 'medium',
      score: 30,
      description: 'VPN connection detected'
    }
  ],
  requiresMfa: true,
  requiresVerification: false,
  shouldBlock: false,
  shouldAlert: true,
  adaptiveAuthLevel: 'mfa',
  explanation: 'High risk: Login from new device; VPN connection detected',
  assessmentId: 'risk_456',
  timestamp: new Date().toISOString(),
  modelVersion: '1.0.0'
});

const createHighRiskAssessment = (): RiskAssessmentResult => ({
  riskScore: 95,
  riskLevel: 'critical',
  deviceRisk: 60,
  geoRisk: 80,
  behaviorRisk: 30,
  credentialRisk: 0,
  networkRisk: 50,
  historicalRisk: 20,
  riskFactors: [
    {
      type: RiskFactorType.TOR_DETECTED,
      severity: 'critical',
      score: 60,
      description: 'Tor exit node detected'
    },
    {
      type: RiskFactorType.IMPOSSIBLE_TRAVEL,
      severity: 'critical',
      score: 80,
      description: 'Impossible travel detected'
    },
    {
      type: RiskFactorType.FAILED_ATTEMPTS,
      severity: 'high',
      score: 30,
      description: '5 failed login attempts'
    }
  ],
  requiresMfa: true,
  requiresVerification: true,
  shouldBlock: true,
  shouldAlert: true,
  adaptiveAuthLevel: 'block',
  explanation: 'Critical risk: Tor exit node detected; Impossible travel detected',
  assessmentId: 'risk_789',
  timestamp: new Date().toISOString(),
  modelVersion: '1.0.0'
});

// ============================================================================
// Test Setup
// ============================================================================

describe('Login Handler - Risk Assessment Integration', () => {
  let mockRiskService: {
    assessLoginRisk: jest.Mock;
  };

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup default mocks
    (checkRateLimit as jest.Mock).mockResolvedValue({
      allowed: true,
      remaining: 4,
      resetAt: Date.now() + 900000
    });

    (findRealmById as jest.Mock).mockResolvedValue(mockRealm);
    (getRealmSettings as jest.Mock).mockResolvedValue(mockRealmSettings);
    (findUserByEmail as jest.Mock).mockResolvedValue(mockUser);
    (verifyPassword as jest.Mock).mockResolvedValue(true);
    (needsRehash as jest.Mock).mockReturnValue(false);
    (logSecurityEvent as jest.Mock).mockResolvedValue(undefined);
    (updateUserLoginAttempts as jest.Mock).mockResolvedValue(undefined);
    (lookupIpLocation as jest.Mock).mockResolvedValue({
      latitude: 41.0082,
      longitude: 28.9784,
      city: 'Istanbul',
      country: 'Turkey',
      countryCode: 'TR'
    });

    (checkMfaEnforcement as jest.Mock).mockResolvedValue({
      mfaRequired: false,
      setupRequired: false,
      gracePeriodActive: false,
      allowedMethods: ['totp', 'webauthn'],
      webauthnRequired: false,
      reason: 'optional'
    });

    (checkMfaSetupRequired as jest.Mock).mockResolvedValue({
      required: false
    });

    (generateTokenPair as jest.Mock).mockResolvedValue({
      access_token: 'mock_access_token',
      refresh_token: 'mock_refresh_token',
      expires_in: 900
    });

    (createSession as jest.Mock).mockResolvedValue({
      id: 'session_123'
    });

    (createMfaSession as jest.Mock).mockResolvedValue(undefined);

    (sessionTaskIntegrationService.evaluateAndCreateTasks as jest.Mock).mockResolvedValue({
      tasks: [],
      hasBlockingTasks: false
    });

    // Setup risk service mock
    mockRiskService = {
      assessLoginRisk: jest.fn()
    };
    (createAIRiskService as jest.Mock).mockReturnValue(mockRiskService);
  });

  // ==========================================================================
  // Low Risk Tests
  // ==========================================================================

  describe('Low Risk Login (score < 70)', () => {
    beforeEach(() => {
      mockRiskService.assessLoginRisk.mockResolvedValue(createLowRiskAssessment());
    });

    it('should allow login without MFA for low risk score', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Login successful');
      expect(body.tokens).toBeDefined();
      expect(body.mfa_required).toBeUndefined();
    });

    it('should log risk assessment for low risk login', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      // Verify risk assessment was logged
      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'risk_assessment',
          details: expect.objectContaining({
            risk_score: 25,
            risk_level: 'low'
          })
        })
      );
    });

    it('should include risk score in successful login log', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      // Verify login success includes risk score
      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'login_success',
          details: expect.objectContaining({
            risk_score: 25,
            risk_level: 'low'
          })
        })
      );
    });
  });

  // ==========================================================================
  // Medium Risk Tests (score > 70)
  // ==========================================================================

  describe('Medium-High Risk Login (score > 70)', () => {
    beforeEach(() => {
      mockRiskService.assessLoginRisk.mockResolvedValue(createMediumRiskAssessment());
    });

    it('should require MFA when risk score exceeds 70 (Requirement 10.3)', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.mfa_required).toBe(true);
      expect(body.mfa_session_id).toBeDefined();
      expect(body.risk_triggered).toBe(true);
      expect(body.risk_score).toBe(75);
      expect(body.risk_level).toBe('high');
    });

    it('should require MFA even when user has MFA disabled', async () => {
      // User has MFA disabled
      (findUserByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        mfa_enabled: false
      });

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.mfa_required).toBe(true);
      expect(body.risk_triggered).toBe(true);
    });

    it('should log MFA required by risk event', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'mfa_required_by_risk',
          details: expect.objectContaining({
            risk_score: 75,
            risk_level: 'high',
            threshold: 70
          })
        })
      );
    });

    it('should log MFA challenge with risk information', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'mfa_challenge_issued',
          details: expect.objectContaining({
            reason: 'risk_score_elevated',
            risk_triggered: true,
            risk_score: 75
          })
        })
      );
    });
  });

  // ==========================================================================
  // High Risk Tests (score > 90)
  // ==========================================================================

  describe('Critical Risk Login (score > 90)', () => {
    beforeEach(() => {
      mockRiskService.assessLoginRisk.mockResolvedValue(createHighRiskAssessment());
    });

    it('should block login when risk score exceeds 90 (Requirement 10.4)', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(403);
      expect(body.error.code).toBe('RISK_SCORE_TOO_HIGH');
      expect(body.error.message).toBe('Login blocked due to security concerns. Please contact support.');
    });

    it('should not leak risk details in error response', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      // Should not include risk score or factors in response
      expect(body.error.details).toBeUndefined();
      expect(body.risk_score).toBeUndefined();
      expect(body.risk_factors).toBeUndefined();
    });

    it('should log blocked login with full risk details', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'login_blocked_high_risk',
          details: expect.objectContaining({
            risk_score: 95,
            risk_level: 'critical',
            blocked_reason: 'risk_score_exceeded_threshold',
            threshold: 90,
            risk_factors: expect.arrayContaining([
              expect.objectContaining({
                type: RiskFactorType.TOR_DETECTED,
                severity: 'critical'
              })
            ])
          })
        })
      );
    });

    it('should block login before password verification', async () => {
      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      // Password verification should not be called for blocked logins
      // (Risk assessment happens before password check in the flow)
      // Note: In our implementation, risk assessment happens after user lookup
      // but before password verification for valid users
      expect(verifyPassword).not.toHaveBeenCalled();
    });
  });

  // ==========================================================================
  // Error Handling Tests
  // ==========================================================================

  describe('Risk Assessment Error Handling', () => {
    it('should fail open when risk assessment fails (graceful degradation)', async () => {
      mockRiskService.assessLoginRisk.mockRejectedValue(new Error('Bedrock unavailable'));

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      // Should allow login despite risk assessment failure
      expect(result.statusCode).toBe(200);
      expect(body.message).toBe('Login successful');
    });

    it('should log risk assessment error', async () => {
      mockRiskService.assessLoginRisk.mockRejectedValue(new Error('Bedrock unavailable'));

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'risk_assessment_error',
          details: expect.objectContaining({
            error: 'Bedrock unavailable',
            fail_open: true
          })
        })
      );
    });

    it('should handle geo-location lookup failure gracefully', async () => {
      (lookupIpLocation as jest.Mock).mockRejectedValue(new Error('Geo service unavailable'));
      mockRiskService.assessLoginRisk.mockResolvedValue(createLowRiskAssessment());

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);

      // Should continue with login despite geo-location failure
      expect(result.statusCode).toBe(200);
    });
  });

  // ==========================================================================
  // Audit Logging Tests (Requirement 10.10)
  // ==========================================================================

  describe('Audit Logging (Requirement 10.10)', () => {
    it('should log risk assessment for all login attempts', async () => {
      mockRiskService.assessLoginRisk.mockResolvedValue(createLowRiskAssessment());

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'risk_assessment',
          realm_id: 'test-realm',
          user_id: 'user_123',
          details: expect.objectContaining({
            risk_score: expect.any(Number),
            risk_level: expect.any(String),
            assessment_id: expect.any(String)
          })
        })
      );
    });

    it('should log risk factors in assessment', async () => {
      mockRiskService.assessLoginRisk.mockResolvedValue(createMediumRiskAssessment());

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      await handler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'risk_assessment',
          details: expect.objectContaining({
            risk_factors: expect.arrayContaining([
              expect.objectContaining({
                type: expect.any(String),
                severity: expect.any(String),
                score: expect.any(Number)
              })
            ])
          })
        })
      );
    });

    it('should include risk score in failed login log', async () => {
      mockRiskService.assessLoginRisk.mockResolvedValue(createLowRiskAssessment());
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'WrongPassword!'
      });

      await handler(event);

      // Risk assessment should still be logged even for failed logins
      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'risk_assessment'
        })
      );
    });
  });

  // ==========================================================================
  // Integration with Existing MFA
  // ==========================================================================

  describe('Integration with Existing MFA', () => {
    it('should require MFA when both user MFA and risk MFA are triggered', async () => {
      // User has MFA enabled
      (findUserByEmail as jest.Mock).mockResolvedValue({
        ...mockUser,
        mfa_enabled: true
      });

      // Risk score also requires MFA
      mockRiskService.assessLoginRisk.mockResolvedValue(createMediumRiskAssessment());

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.mfa_required).toBe(true);
    });

    it('should require MFA when realm policy requires it regardless of risk', async () => {
      (checkMfaEnforcement as jest.Mock).mockResolvedValue({
        mfaRequired: true,
        setupRequired: false,
        gracePeriodActive: false,
        allowedMethods: ['totp', 'webauthn'],
        webauthnRequired: false,
        reason: 'realm_policy'
      });

      // Low risk score
      mockRiskService.assessLoginRisk.mockResolvedValue(createLowRiskAssessment());

      const event = createMockEvent({
        realm_id: 'test-realm',
        email: 'test@example.com',
        password: 'ValidPassword123!'
      });

      const result = await handler(event);
      const body = JSON.parse(result.body);

      expect(result.statusCode).toBe(200);
      expect(body.mfa_required).toBe(true);
      // Should not have risk_triggered since it's realm policy
      expect(body.risk_triggered).toBeUndefined();
    });
  });
});
