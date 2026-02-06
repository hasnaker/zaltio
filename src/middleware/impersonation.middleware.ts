/**
 * Impersonation Restrictions Middleware
 * Task 11.4: Impersonation restrictions middleware
 * 
 * Blocks certain actions during impersonation sessions:
 * - Password change
 * - Account deletion
 * - Email change
 * - MFA disable
 * - Session revocation
 * - API key management
 * - Billing changes
 * 
 * SECURITY: Returns 403 IMPERSONATION_RESTRICTED for blocked actions
 * AUDIT: All blocked actions are logged
 * 
 * Validates: Requirements 6.8 (Impersonation Restrictions)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../utils/jwt';
import { 
  ImpersonationService,
  RestrictedAction,
  DEFAULT_RESTRICTED_ACTIONS
} from '../services/impersonation.service';
import { logAuditEvent, AuditEventType, AuditResult } from '../services/audit.service';

// Service instance
const impersonationService = new ImpersonationService();

/**
 * Endpoint to restricted action mapping
 */
export const ENDPOINT_RESTRICTIONS: Record<string, {
  methods: string[];
  action: RestrictedAction;
  description: string;
}> = {
  '/me/password': {
    methods: ['PUT', 'PATCH', 'POST'],
    action: 'change_password',
    description: 'Password change'
  },
  '/me/email': {
    methods: ['PUT', 'PATCH'],
    action: 'change_email',
    description: 'Email change'
  },
  '/me/delete': {
    methods: ['DELETE', 'POST'],
    action: 'delete_account',
    description: 'Account deletion'
  },
  '/account/delete': {
    methods: ['DELETE', 'POST'],
    action: 'delete_account',
    description: 'Account deletion'
  },
  '/mfa/disable': {
    methods: ['POST', 'DELETE'],
    action: 'disable_mfa',
    description: 'MFA disable'
  },
  '/mfa/totp/disable': {
    methods: ['POST', 'DELETE'],
    action: 'disable_mfa',
    description: 'TOTP MFA disable'
  },
  '/mfa/webauthn/disable': {
    methods: ['POST', 'DELETE'],
    action: 'disable_mfa',
    description: 'WebAuthn disable'
  },
  '/sessions/revoke-all': {
    methods: ['POST', 'DELETE'],
    action: 'revoke_sessions',
    description: 'Revoke all sessions'
  },
  '/sessions/revoke': {
    methods: ['POST', 'DELETE'],
    action: 'revoke_sessions',
    description: 'Revoke session'
  },
  '/api-keys': {
    methods: ['POST', 'DELETE'],
    action: 'manage_api_keys',
    description: 'API key management'
  },
  '/billing/subscribe': {
    methods: ['POST'],
    action: 'billing_changes',
    description: 'Subscription change'
  },
  '/billing/cancel': {
    methods: ['POST'],
    action: 'billing_changes',
    description: 'Subscription cancellation'
  },
  '/billing/payment-method': {
    methods: ['POST', 'PUT', 'DELETE'],
    action: 'billing_changes',
    description: 'Payment method change'
  }
};

/**
 * Response helper
 */
const response = (statusCode: number, body: unknown): APIGatewayProxyResult => ({
  statusCode,
  headers: {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  },
  body: JSON.stringify(body)
});

/**
 * Check if endpoint matches a restricted pattern
 */
export function matchRestrictedEndpoint(
  path: string,
  method: string
): { matched: boolean; action?: RestrictedAction; description?: string } {
  // Normalize path
  const normalizedPath = path.toLowerCase().replace(/\/+$/, '');
  
  for (const [pattern, config] of Object.entries(ENDPOINT_RESTRICTIONS)) {
    // Check if path matches pattern (exact or starts with for wildcard)
    const normalizedPattern = pattern.toLowerCase();
    
    if (normalizedPath === normalizedPattern || 
        normalizedPath.startsWith(normalizedPattern + '/')) {
      // Check if method matches
      if (config.methods.includes(method.toUpperCase())) {
        return {
          matched: true,
          action: config.action,
          description: config.description
        };
      }
    }
  }
  
  return { matched: false };
}

/**
 * Extract impersonation session from request
 */
async function getImpersonationSession(event: APIGatewayProxyEvent): Promise<{
  isImpersonating: boolean;
  sessionId?: string;
  adminId?: string;
  targetUserId?: string;
  realmId?: string;
  restrictedActions?: RestrictedAction[];
}> {
  const authHeader = event.headers.Authorization || event.headers.authorization;
  
  if (!authHeader?.startsWith('Bearer ')) {
    return { isImpersonating: false };
  }

  const token = authHeader.substring(7);
  
  try {
    // First try to validate as impersonation token
    const session = await impersonationService.validateToken(token);
    
    if (session) {
      return {
        isImpersonating: true,
        sessionId: session.id,
        adminId: session.admin_id,
        targetUserId: session.target_user_id,
        realmId: session.realm_id,
        restrictedActions: session.restricted_actions
      };
    }
    
    // Try regular JWT with impersonation claims
    const payload = await verifyAccessToken(token);
    const extendedPayload = payload as unknown as Record<string, unknown>;
    
    if (extendedPayload.is_impersonation === true) {
      return {
        isImpersonating: true,
        sessionId: extendedPayload.impersonation_session_id as string,
        adminId: extendedPayload.admin_id as string,
        targetUserId: payload.sub,
        realmId: payload.realm_id,
        restrictedActions: extendedPayload.restricted_actions as RestrictedAction[]
      };
    }
    
    return { isImpersonating: false };
  } catch {
    return { isImpersonating: false };
  }
}

/**
 * Impersonation restrictions middleware
 * 
 * Checks if the current request is from an impersonation session
 * and blocks restricted actions.
 */
export async function impersonationRestrictionsMiddleware(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult | null> {
  const clientIp = event.requestContext.identity?.sourceIp || 'unknown';
  const path = event.path;
  const method = event.httpMethod;
  
  // Check if this endpoint has restrictions
  const restriction = matchRestrictedEndpoint(path, method);
  
  if (!restriction.matched) {
    // No restrictions for this endpoint
    return null;
  }
  
  // Check if this is an impersonation session
  const impersonation = await getImpersonationSession(event);
  
  if (!impersonation.isImpersonating) {
    // Not impersonating, allow the request
    return null;
  }
  
  // Check if the action is restricted for this session
  const restrictedActions = impersonation.restrictedActions || DEFAULT_RESTRICTED_ACTIONS;
  
  if (!restrictedActions.includes(restriction.action!)) {
    // Action not restricted for this session
    return null;
  }
  
  // Action is restricted - block and log
  await logAuditEvent({
    eventType: AuditEventType.ADMIN_ACTION,
    action: 'impersonation_action_blocked',
    userId: impersonation.adminId!,
    realmId: impersonation.realmId!,
    ipAddress: clientIp,
    result: AuditResult.FAILURE,
    details: {
      impersonation_session_id: impersonation.sessionId,
      target_user_id: impersonation.targetUserId,
      blocked_action: restriction.action,
      blocked_endpoint: path,
      blocked_method: method,
      description: restriction.description
    }
  });
  
  // Log to impersonation service
  if (impersonation.sessionId) {
    await impersonationService.logBlockedAction(impersonation.sessionId, restriction.action!);
  }
  
  return response(403, {
    error: {
      code: 'IMPERSONATION_RESTRICTED',
      message: `${restriction.description} is not allowed during impersonation`,
      restricted_action: restriction.action,
      impersonation_session_id: impersonation.sessionId
    }
  });
}

/**
 * Check if a specific action is restricted for the current session
 */
export async function isActionRestrictedForSession(
  event: APIGatewayProxyEvent,
  action: RestrictedAction
): Promise<boolean> {
  const impersonation = await getImpersonationSession(event);
  
  if (!impersonation.isImpersonating) {
    return false;
  }
  
  const restrictedActions = impersonation.restrictedActions || DEFAULT_RESTRICTED_ACTIONS;
  return restrictedActions.includes(action);
}

/**
 * Get impersonation context from request
 */
export async function getImpersonationContext(event: APIGatewayProxyEvent): Promise<{
  isImpersonating: boolean;
  sessionId?: string;
  adminId?: string;
  targetUserId?: string;
  restrictedActions?: RestrictedAction[];
} | null> {
  const impersonation = await getImpersonationSession(event);
  
  if (!impersonation.isImpersonating) {
    return null;
  }
  
  return {
    isImpersonating: true,
    sessionId: impersonation.sessionId,
    adminId: impersonation.adminId,
    targetUserId: impersonation.targetUserId,
    restrictedActions: impersonation.restrictedActions
  };
}

/**
 * Middleware wrapper for use in handlers
 */
export function withImpersonationRestrictions<T extends APIGatewayProxyEvent>(
  handler: (event: T) => Promise<APIGatewayProxyResult>
): (event: T) => Promise<APIGatewayProxyResult> {
  return async (event: T): Promise<APIGatewayProxyResult> => {
    // Check impersonation restrictions
    const restrictionResponse = await impersonationRestrictionsMiddleware(event);
    
    if (restrictionResponse) {
      return restrictionResponse;
    }
    
    // Continue to handler
    return handler(event);
  };
}
