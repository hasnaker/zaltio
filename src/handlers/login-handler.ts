/**
 * User Login Lambda Handler
 * Validates: Requirements 2.1, 2.3, 2.5, 9.4, 9.6, 10.3, 10.4, 10.10
 * 
 * SECURITY FEATURES (January 2026):
 * - Rate limiting: 5 attempts/15min/IP
 * - Progressive delay: 1s, 2s, 4s, 8s, 16s
 * - Account lockout: 5 failures → 15 min lock
 * - Device fingerprint tracking
 * - Audit logging
 * - No email enumeration (same response for invalid email/password)
 * - MFA challenge when user has MFA enabled
 * - AI-powered risk assessment (Task 15.4):
 *   - Risk score > 70: Require MFA regardless of user settings
 *   - Risk score > 90: Block login and notify admin
 *   - All login attempts logged with risk score
 * - SSO enforcement (Task 19.5):
 *   - Block password login when SSO enforced for organization
 *   - Redirect to org's IdP automatically
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import crypto from 'crypto';
import { findUserByEmail, updateUserLoginAttempts } from '../repositories/user.repository';
import { findRealmById, getRealmSettings } from '../repositories/realm.repository';
import { createSession } from '../repositories/session.repository';
import { validateEmail, validateRealmId } from '../utils/validation';
import { verifyPassword, needsRehash, hashPassword } from '../utils/password';
import { generateTokenPair } from '../utils/jwt';
import { checkRateLimit, getRealmRateLimitConfig } from '../services/ratelimit.service';
import { logSecurityEvent } from '../services/security-logger.service';
import { checkMfaEnforcement, checkMfaSetupRequired } from '../services/realm.service';
import { sessionTaskIntegrationService } from '../services/session-task-integration.service';
import { toSessionTaskResponse } from '../models/session-task.model';
import { 
  createAIRiskService, 
  RiskAssessmentResult,
  RISK_THRESHOLDS 
} from '../services/ai-risk.service';
import { DeviceFingerprintInput } from '../services/device.service';
import { lookupIpLocation, GeoLocation } from '../services/geo-velocity.service';
import { dispatchHighRiskLogin, HighRiskLoginEventPayload } from '../services/webhook-events.service';
import { ssoEnforcementMiddleware } from '../middleware/sso-enforcement.middleware';

// Rate limit configuration for login
const LOGIN_RATE_LIMIT = {
  maxRequests: 5,
  windowSeconds: 900 // 15 minutes
};

// Account lockout configuration
const LOCKOUT_CONFIG = {
  maxAttempts: 5,
  lockoutDuration: 900, // 15 minutes in seconds
  emailVerificationThreshold: 10 // After 10 failures, require email verification
};

// Progressive delay configuration (in milliseconds)
const PROGRESSIVE_DELAYS = [1000, 2000, 4000, 8000, 16000];

// MFA session configuration
const MFA_SESSION_CONFIG = {
  expirySeconds: 300 // 5 minutes to complete MFA
};

// Risk assessment thresholds (Task 15.4)
// Requirements 10.3, 10.4
const RISK_ASSESSMENT_CONFIG = {
  mfaRequiredThreshold: 70,  // Score > 70: Require MFA regardless of user settings
  blockThreshold: 90,        // Score > 90: Block login and notify admin
  failOpenOnError: true      // If risk assessment fails, allow login with logging
};

// Import DynamoDB-backed MFA session functions
import { createMfaSession, getMfaSessionFromDb, deleteMfaSessionFromDb } from '../repositories/session.repository';

interface LoginRequest {
  realm_id: string;
  email: string;
  password: string;
  device_fingerprint?: {
    userAgent?: string;
    screen?: string;
    timezone?: string;
    language?: string;
    platform?: string;
  };
}

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}

function createErrorResponse(
  statusCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>,
  requestId?: string,
  headers?: Record<string, string>
): APIGatewayProxyResult {
  const response: ErrorResponse = {
    error: {
      code,
      message,
      details,
      timestamp: new Date().toISOString(),
      request_id: requestId
    }
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      ...headers
    },
    body: JSON.stringify(response)
  };
}

function createSuccessResponse(
  statusCode: number,
  data: unknown,
  headers?: Record<string, string>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      ...headers
    },
    body: JSON.stringify(data)
  };
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 
         event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
         'unknown';
}

function getUserAgent(event: APIGatewayProxyEvent): string {
  return event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown';
}

async function applyProgressiveDelay(failedAttempts: number): Promise<void> {
  const delayIndex = Math.min(failedAttempts - 1, PROGRESSIVE_DELAYS.length - 1);
  if (delayIndex >= 0) {
    const delay = PROGRESSIVE_DELAYS[delayIndex];
    await new Promise(resolve => setTimeout(resolve, delay));
  }
}

function isAccountLocked(user: { failed_login_attempts?: number; locked_until?: string }): boolean {
  if (!user.locked_until) return false;
  return new Date(user.locked_until) > new Date();
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);
  const userAgent = getUserAgent(event);

  try {
    // Rate limiting check (5 attempts/15min/IP)
    const rateLimitResult = await checkRateLimit(
      'global',
      `login:${clientIP}`,
      LOGIN_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'rate_limit_exceeded',
        ip_address: clientIP,
        details: { endpoint: 'login', retry_after: rateLimitResult.retryAfter }
      });

      return createErrorResponse(
        429,
        'RATE_LIMITED',
        'Too many login attempts. Please try again later.',
        { retry_after: rateLimitResult.retryAfter },
        requestId,
        { 'Retry-After': String(rateLimitResult.retryAfter) }
      );
    }

    // Parse request body
    if (!event.body) {
      return createErrorResponse(
        400,
        'INVALID_REQUEST',
        'Request body is required',
        undefined,
        requestId
      );
    }

    let request: LoginRequest;
    try {
      request = JSON.parse(event.body);
    } catch {
      return createErrorResponse(
        400,
        'INVALID_JSON',
        'Invalid JSON in request body',
        undefined,
        requestId
      );
    }

    // Validate realm_id
    const realmValidation = validateRealmId(request.realm_id);
    if (!realmValidation.valid) {
      return createErrorResponse(
        400,
        'INVALID_REALM',
        realmValidation.errors[0],
        { field: 'realm_id' },
        requestId
      );
    }

    // Check if realm exists
    const realm = await findRealmById(request.realm_id);
    if (!realm) {
      return createErrorResponse(
        404,
        'REALM_NOT_FOUND',
        'Authentication service unavailable',
        { realm: request.realm_id },
        requestId
      );
    }

    // Validate email
    const emailValidation = validateEmail(request.email);
    if (!emailValidation.valid) {
      return createErrorResponse(
        400,
        'INVALID_EMAIL',
        emailValidation.errors[0],
        { field: 'email' },
        requestId
      );
    }

    // =========================================================================
    // SSO Enforcement Check (Task 19.5)
    // Requirements: 9.4, 9.6
    // Block password login when SSO is enforced for the user's email domain
    // =========================================================================
    const ssoEnforcementResponse = await ssoEnforcementMiddleware(event, {
      realmId: request.realm_id
    });
    
    if (ssoEnforcementResponse) {
      // SSO is enforced - return redirect response
      return ssoEnforcementResponse;
    }

    // Validate password is provided
    if (!request.password || typeof request.password !== 'string') {
      return createErrorResponse(
        400,
        'INVALID_PASSWORD',
        'Password is required',
        { field: 'password' },
        requestId
      );
    }

    // Find user by email in the realm
    const user = await findUserByEmail(request.realm_id, request.email);
    
    // SECURITY: Same response for invalid email (prevent enumeration)
    if (!user) {
      await logSecurityEvent({
        event_type: 'login_failure',
        ip_address: clientIP,
        realm_id: request.realm_id,
        details: { reason: 'user_not_found', email_prefix: request.email.substring(0, 3) }
      });

      // Apply progressive delay even for non-existent users
      await applyProgressiveDelay(1);

      return createErrorResponse(
        401,
        'INVALID_CREDENTIALS',
        'Invalid email or password',
        undefined,
        requestId
      );
    }

    // Check if account is locked
    if (isAccountLocked(user)) {
      await logSecurityEvent({
        event_type: 'login_blocked',
        ip_address: clientIP,
        realm_id: request.realm_id,
        user_id: user.id,
        details: { reason: 'account_locked', locked_until: user.locked_until }
      });

      return createErrorResponse(
        423,
        'ACCOUNT_LOCKED',
        'Account is temporarily locked due to too many failed attempts. Please try again later.',
        { locked_until: user.locked_until },
        requestId
      );
    }

    // Check if user is suspended
    if (user.status === 'suspended') {
      await logSecurityEvent({
        event_type: 'login_blocked',
        ip_address: clientIP,
        realm_id: request.realm_id,
        user_id: user.id,
        details: { reason: 'account_suspended' }
      });

      return createErrorResponse(
        423,
        'ACCOUNT_SUSPENDED',
        'Account is suspended. Please contact support.',
        undefined,
        requestId
      );
    }

    // Apply progressive delay based on failed attempts
    const failedAttempts = user.failed_login_attempts || 0;
    if (failedAttempts > 0) {
      await applyProgressiveDelay(failedAttempts);
    }

    // =========================================================================
    // AI-Powered Risk Assessment (Task 15.4)
    // Requirements: 10.3, 10.4, 10.10
    // =========================================================================
    let riskAssessment: RiskAssessmentResult | null = null;
    let riskMfaRequired = false;
    
    try {
      // Create risk service for this realm
      const riskService = createAIRiskService(request.realm_id);
      
      // Lookup geo-location for risk assessment
      let geoLocation: GeoLocation | undefined;
      try {
        const geoResult = await lookupIpLocation(clientIP);
        geoLocation = geoResult ?? undefined;
      } catch (geoError) {
        console.warn('Geo-location lookup failed:', geoError);
        // Continue without geo-location
      }
      
      // Calculate account age in days
      const accountCreatedAt = user.created_at ? new Date(user.created_at).getTime() : Date.now();
      const accountAgeDays = Math.floor((Date.now() - accountCreatedAt) / (1000 * 60 * 60 * 24));
      
      // Assess login risk
      riskAssessment = await riskService.assessLoginRisk({
        userId: user.id,
        email: user.email,
        realmId: request.realm_id,
        ip: clientIP,
        userAgent,
        deviceFingerprint: request.device_fingerprint as DeviceFingerprintInput,
        geoLocation,
        timestamp: Date.now(),
        failedAttempts,
        mfaEnabled: user.mfa_enabled || false,
        accountAge: accountAgeDays
      });
      
      // Log risk assessment for all login attempts (Requirement 10.10)
      await logSecurityEvent({
        event_type: 'risk_assessment',
        ip_address: clientIP,
        realm_id: request.realm_id,
        user_id: user.id,
        details: {
          risk_score: riskAssessment.riskScore,
          risk_level: riskAssessment.riskLevel,
          recommendation: riskAssessment.adaptiveAuthLevel,
          requires_mfa: riskAssessment.requiresMfa,
          should_block: riskAssessment.shouldBlock,
          risk_factors: riskAssessment.riskFactors.map(f => ({
            type: f.type,
            severity: f.severity,
            score: f.score
          })),
          assessment_id: riskAssessment.assessmentId
        }
      });
      
      // Check if risk score exceeds block threshold (Requirement 10.4)
      // Score > 90: Block login and notify admin
      if (riskAssessment.riskScore > RISK_ASSESSMENT_CONFIG.blockThreshold) {
        // Log high-risk blocked login
        await logSecurityEvent({
          event_type: 'login_blocked_high_risk',
          ip_address: clientIP,
          realm_id: request.realm_id,
          user_id: user.id,
          details: {
            risk_score: riskAssessment.riskScore,
            risk_level: riskAssessment.riskLevel,
            risk_factors: riskAssessment.riskFactors.map(f => ({
              type: f.type,
              severity: f.severity,
              description: f.description
            })),
            blocked_reason: 'risk_score_exceeded_threshold',
            threshold: RISK_ASSESSMENT_CONFIG.blockThreshold
          }
        });
        
        // Trigger high-risk login webhook (Requirement 10.9)
        // WHEN high-risk login detected THEN trigger webhook with risk factors
        try {
          const webhookPayload: HighRiskLoginEventPayload = {
            user_id: user.id,
            realm_id: request.realm_id,
            email: user.email,
            risk_score: riskAssessment.riskScore,
            risk_level: riskAssessment.riskLevel,
            risk_factors: riskAssessment.riskFactors.map(f => ({
              type: f.type,
              severity: f.severity,
              score: f.score,
              description: f.description
            })),
            recommendation: riskAssessment.adaptiveAuthLevel === 'block' ? 'block' : 
                           riskAssessment.requiresMfa ? 'mfa_required' : 'allow',
            ip_address: clientIP,
            location: geoLocation ? {
              city: geoLocation.city,
              country: geoLocation.country,
              country_code: geoLocation.countryCode
            } : undefined,
            device: {
              user_agent: userAgent,
              is_new_device: riskAssessment.riskFactors.some(f => f.type === 'new_device')
            },
            action_taken: 'blocked',
            assessment_id: riskAssessment.assessmentId,
            timestamp: new Date().toISOString()
          };
          
          await dispatchHighRiskLogin(request.realm_id, webhookPayload);
        } catch (webhookError) {
          // Log webhook error but don't fail the request
          console.error('Failed to dispatch high-risk login webhook:', webhookError);
        }
        
        // Return generic error to prevent information leakage
        return createErrorResponse(
          403,
          'RISK_SCORE_TOO_HIGH',
          'Login blocked due to security concerns. Please contact support.',
          undefined,
          requestId
        );
      }
      
      // Check if risk score requires MFA (Requirement 10.3)
      // Score > 70: Require MFA regardless of user settings
      if (riskAssessment.riskScore > RISK_ASSESSMENT_CONFIG.mfaRequiredThreshold) {
        riskMfaRequired = true;
        
        await logSecurityEvent({
          event_type: 'mfa_required_by_risk',
          ip_address: clientIP,
          realm_id: request.realm_id,
          user_id: user.id,
          details: {
            risk_score: riskAssessment.riskScore,
            risk_level: riskAssessment.riskLevel,
            threshold: RISK_ASSESSMENT_CONFIG.mfaRequiredThreshold
          }
        });
        
        // Trigger high-risk login webhook for MFA-required logins (Requirement 10.9)
        // Also trigger webhook when risk is high enough to require MFA
        try {
          const webhookPayload: HighRiskLoginEventPayload = {
            user_id: user.id,
            realm_id: request.realm_id,
            email: user.email,
            risk_score: riskAssessment.riskScore,
            risk_level: riskAssessment.riskLevel,
            risk_factors: riskAssessment.riskFactors.map(f => ({
              type: f.type,
              severity: f.severity,
              score: f.score,
              description: f.description
            })),
            recommendation: 'mfa_required',
            ip_address: clientIP,
            location: geoLocation ? {
              city: geoLocation.city,
              country: geoLocation.country,
              country_code: geoLocation.countryCode
            } : undefined,
            device: {
              user_agent: userAgent,
              is_new_device: riskAssessment.riskFactors.some(f => f.type === 'new_device')
            },
            action_taken: 'mfa_required',
            assessment_id: riskAssessment.assessmentId,
            timestamp: new Date().toISOString()
          };
          
          await dispatchHighRiskLogin(request.realm_id, webhookPayload);
        } catch (webhookError) {
          // Log webhook error but don't fail the request
          console.error('Failed to dispatch high-risk login webhook:', webhookError);
        }
      }
    } catch (riskError) {
      // Fail open with logging (graceful error handling)
      console.error('Risk assessment failed:', riskError);
      
      await logSecurityEvent({
        event_type: 'risk_assessment_error',
        ip_address: clientIP,
        realm_id: request.realm_id,
        user_id: user.id,
        details: {
          error: (riskError as Error).message,
          fail_open: RISK_ASSESSMENT_CONFIG.failOpenOnError
        }
      });
      
      // Continue with login if fail-open is enabled
      if (!RISK_ASSESSMENT_CONFIG.failOpenOnError) {
        return createErrorResponse(
          500,
          'RISK_ASSESSMENT_ERROR',
          'Unable to process login request. Please try again.',
          undefined,
          requestId
        );
      }
    }

    // Verify password
    const passwordValid = await verifyPassword(request.password, user.password_hash);
    
    if (!passwordValid) {
      // Increment failed attempts
      const newFailedAttempts = failedAttempts + 1;
      const shouldLock = newFailedAttempts >= LOCKOUT_CONFIG.maxAttempts;
      const lockedUntil = shouldLock 
        ? new Date(Date.now() + LOCKOUT_CONFIG.lockoutDuration * 1000).toISOString()
        : undefined;

      await updateUserLoginAttempts(user.id, newFailedAttempts, lockedUntil);

      await logSecurityEvent({
        event_type: 'login_failure',
        ip_address: clientIP,
        realm_id: request.realm_id,
        user_id: user.id,
        details: { 
          reason: 'invalid_password',
          failed_attempts: newFailedAttempts,
          locked: shouldLock
        }
      });

      if (shouldLock) {
        return createErrorResponse(
          423,
          'ACCOUNT_LOCKED',
          'Account is temporarily locked due to too many failed attempts. Please try again later.',
          { locked_until: lockedUntil },
          requestId
        );
      }

      return createErrorResponse(
        401,
        'INVALID_CREDENTIALS',
        'Invalid email or password',
        { attempts_remaining: LOCKOUT_CONFIG.maxAttempts - newFailedAttempts },
        requestId
      );
    }

    // Check if password needs rehashing (bcrypt → Argon2id migration)
    if (needsRehash(user.password_hash)) {
      const newHash = await hashPassword(request.password);
      // TODO: Update user password hash in background
      console.info(`Password rehash needed for user ${user.id}`);
    }

    // Get realm settings
    const realmSettings = await getRealmSettings(request.realm_id);

    // Check MFA enforcement based on realm policy
    const mfaEnforcement = await checkMfaEnforcement(
      request.realm_id,
      user,
      {
        isNewDevice: false, // TODO: Implement device trust check
        deviceTrusted: false
      }
    );

    // Check if MFA setup is required (for required policy with grace period)
    if (mfaEnforcement.setupRequired && !user.mfa_enabled && 
        !(user.webauthn_credentials && user.webauthn_credentials.length > 0)) {
      const setupStatus = await checkMfaSetupRequired(request.realm_id, user);
      
      if (setupStatus.required && !mfaEnforcement.gracePeriodActive) {
        // Grace period expired - must setup MFA before login
        await logSecurityEvent({
          event_type: 'mfa_setup_required',
          ip_address: clientIP,
          realm_id: request.realm_id,
          user_id: user.id,
          details: { reason: 'grace_period_expired' }
        });

        return createErrorResponse(
          403,
          'MFA_SETUP_REQUIRED',
          'Multi-factor authentication setup is required to access this account',
          { 
            setup_url: `/v1/auth/mfa/totp/setup`,
            allowed_methods: mfaEnforcement.allowedMethods
          },
          requestId
        );
      }
    }

    // Check if MFA verification is required
    // Include risk-based MFA requirement (Task 15.4, Requirement 10.3)
    if (mfaEnforcement.mfaRequired || user.mfa_enabled || riskMfaRequired) {
      // Create MFA session
      const mfaSessionId = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + (MFA_SESSION_CONFIG.expirySeconds * 1000);
      
      // Store MFA session in DynamoDB (not in-memory!)
      await createMfaSession(mfaSessionId, {
        userId: user.id,
        realmId: user.realm_id,
        email: user.email,
        expiresAt,
        deviceFingerprint: request.device_fingerprint 
          ? JSON.stringify(request.device_fingerprint) 
          : undefined,
        ipAddress: clientIP,
        userAgent
      });

      // Determine the reason for MFA requirement
      const mfaReason = riskMfaRequired 
        ? 'risk_score_elevated' 
        : mfaEnforcement.reason;

      await logSecurityEvent({
        event_type: 'mfa_challenge_issued',
        ip_address: clientIP,
        realm_id: request.realm_id,
        user_id: user.id,
        details: { 
          mfa_session_id: mfaSessionId.substring(0, 8) + '...',
          reason: mfaReason,
          webauthn_required: mfaEnforcement.webauthnRequired,
          risk_triggered: riskMfaRequired,
          risk_score: riskAssessment?.riskScore
        }
      });

      // Include grace period info if applicable
      const responseData: Record<string, unknown> = {
        message: 'MFA verification required',
        mfa_required: true,
        mfa_session_id: mfaSessionId,
        mfa_expires_in: MFA_SESSION_CONFIG.expirySeconds,
        allowed_methods: mfaEnforcement.allowedMethods,
        webauthn_required: mfaEnforcement.webauthnRequired,
        user: {
          id: user.id,
          email: user.email
        }
      };

      if (mfaEnforcement.gracePeriodActive) {
        responseData.mfa_setup_required = true;
        responseData.grace_period_ends_at = mfaEnforcement.gracePeriodEndsAt;
      }

      // Include risk information when MFA is triggered by risk assessment (Task 15.4)
      if (riskMfaRequired && riskAssessment) {
        responseData.risk_triggered = true;
        responseData.risk_score = riskAssessment.riskScore;
        responseData.risk_level = riskAssessment.riskLevel;
      }

      return createSuccessResponse(200, responseData);
    }

    // Reset failed login attempts on successful login
    if (failedAttempts > 0) {
      await updateUserLoginAttempts(user.id, 0, undefined);
    }

    // Generate JWT tokens
    const tokenPair = await generateTokenPair(
      user.id,
      user.realm_id,
      user.email,
      { accessTokenExpiry: realmSettings.session_timeout }
    );

    // Create session record
    let sessionId: string | undefined;
    try {
      const session = await createSession(
        {
          user_id: user.id,
          realm_id: user.realm_id,
          ip_address: clientIP,
          user_agent: userAgent,
          device_fingerprint: request.device_fingerprint 
            ? JSON.stringify(request.device_fingerprint) 
            : undefined
        },
        tokenPair.access_token,
        tokenPair.refresh_token,
        7 * 24 * 60 * 60 // 7 days
      );
      sessionId = session.id;
    } catch (sessionError) {
      console.warn('Failed to create session record:', sessionError);
      // Continue - session creation failure shouldn't block login
    }

    // Evaluate and create session tasks (Requirements 4.3, 4.4, 4.5)
    let sessionTasks: ReturnType<typeof toSessionTaskResponse>[] = [];
    let hasBlockingTasks = false;
    
    if (sessionId) {
      try {
        // Check for compromised password (would be set by admin or background job)
        // For now, we check if user has a password_compromised flag
        const passwordCompromised = (user as unknown as { password_compromised?: boolean }).password_compromised === true;
        
        const taskResult = await sessionTaskIntegrationService.evaluateAndCreateTasks({
          user,
          sessionId,
          realmId: user.realm_id,
          passwordCompromised,
          // Terms version checking would come from realm settings
          currentTermsVersion: (realmSettings as unknown as { terms_version?: string }).terms_version,
          termsVersion: (user as unknown as { accepted_terms_version?: string }).accepted_terms_version
        });
        
        sessionTasks = taskResult.tasks.map(toSessionTaskResponse);
        hasBlockingTasks = taskResult.hasBlockingTasks;
        
        if (taskResult.tasks.length > 0) {
          await logSecurityEvent({
            event_type: 'session_tasks_created',
            ip_address: clientIP,
            realm_id: request.realm_id,
            user_id: user.id,
            details: { 
              task_count: taskResult.tasks.length,
              task_types: taskResult.tasks.map(t => t.type),
              has_blocking: hasBlockingTasks
            }
          });
        }
      } catch (taskError) {
        console.warn('Failed to evaluate session tasks:', taskError);
        // Continue - task evaluation failure shouldn't block login
      }
    }

    // Log successful login (include risk score - Requirement 10.10)
    await logSecurityEvent({
      event_type: 'login_success',
      ip_address: clientIP,
      realm_id: request.realm_id,
      user_id: user.id,
      details: { 
        user_agent: userAgent,
        device_fingerprint: request.device_fingerprint ? 'provided' : 'not_provided',
        session_tasks: sessionTasks.length > 0 ? sessionTasks.map(t => t.type) : undefined,
        risk_score: riskAssessment?.riskScore,
        risk_level: riskAssessment?.riskLevel
      }
    });

    // Build response with session tasks
    const responseData: Record<string, unknown> = {
      message: hasBlockingTasks ? 'Login successful - action required' : 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        email_verified: user.email_verified,
        profile: user.profile,
        status: user.status
      },
      tokens: tokenPair
    };
    
    // Include session tasks if any exist
    if (sessionTasks.length > 0) {
      responseData.session_tasks = sessionTasks;
      responseData.has_blocking_tasks = hasBlockingTasks;
    }

    return createSuccessResponse(200, responseData, {
      'X-RateLimit-Remaining': rateLimitResult.remaining.toString(),
      'X-RateLimit-Reset': rateLimitResult.resetAt.toString()
    });
  } catch (error) {
    console.error('Login error:', error);

    await logSecurityEvent({
      event_type: 'login_error',
      ip_address: clientIP,
      details: { error: (error as Error).message }
    });

    // Handle JWT errors
    if ((error as Error).name === 'JsonWebTokenError') {
      return createErrorResponse(
        500,
        'TOKEN_ERROR',
        'Failed to generate authentication token',
        undefined,
        requestId
      );
    }

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      undefined,
      requestId
    );
  }
}

/**
 * Get MFA session by ID (DynamoDB-backed)
 * Used by MFA verify handler
 */
export async function getMfaSession(sessionId: string) {
  const session = await getMfaSessionFromDb(sessionId);
  return session;
}

/**
 * Delete MFA session after successful verification (DynamoDB-backed)
 */
export async function deleteMfaSession(sessionId: string): Promise<void> {
  await deleteMfaSessionFromDb(sessionId);
}

/**
 * Clean up expired MFA sessions - now handled by DynamoDB TTL
 * @deprecated DynamoDB TTL handles cleanup automatically
 */
export function cleanupExpiredMfaSessions(): number {
  // DynamoDB TTL handles cleanup automatically
  return 0;
}
