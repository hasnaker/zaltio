/**
 * Session Handler - Lambda for session management
 * Validates: Requirements 13.1, 13.2, 13.3, 13.4
 * 
 * Endpoints:
 * - GET /sessions - List all active sessions for the authenticated user
 * - GET /sessions/{id} - Get session details
 * - DELETE /sessions/{id} - Revoke specific session
 * - DELETE /sessions - Revoke all sessions except current
 * 
 * SECURITY FEATURES:
 * - Rate limiting: 100 requests/min/user
 * - Audit logging for all session operations
 * - Session binding validation
 * - No information leakage (generic errors)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../utils/jwt';
import { JWTPayload } from '../models/session.model';
import {
  getUserSessions,
  findSessionById,
  deleteSession,
  updateSessionLastActivity
} from '../repositories/session.repository';
import { Session } from '../models/session.model';
import { checkRateLimit } from '../services/ratelimit.service';
import { logSecurityEvent } from '../services/security-logger.service';
import { dispatchSessionRevoked } from '../services/webhook-events.service';
import { 
  lookupIpLocation, 
  GeoLocation, 
  checkGeoVelocity, 
  VelocityCheckResult,
  getRealmVelocityConfig 
} from '../services/geo-velocity.service';

// Rate limit configuration for session management
const SESSION_RATE_LIMIT = {
  maxRequests: 100,
  windowSeconds: 60 // 1 minute
};

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    request_id?: string;
  };
}

/**
 * Session info returned to the client
 * Validates: Requirement 13.2 - Session info includes device, browser, IP, location, last_activity, is_current
 */
interface SessionInfo {
  id: string;
  device: string;
  browser: string;
  ip_address: string;
  location?: {
    city?: string;
    country?: string;
    country_code?: string;
  };
  last_activity: string;
  created_at: string;
  is_current: boolean;
  user_agent: string;
  impossible_travel?: ImpossibleTravelInfo;
}

/**
 * Impossible travel detection result
 * Validates: Requirement 13.5 - Detect impossible travel and alert user
 */
interface ImpossibleTravelInfo {
  detected: boolean;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  previous_location?: {
    city?: string;
    country?: string;
  };
  current_location?: {
    city?: string;
    country?: string;
  };
  distance_km?: number;
  time_elapsed_hours?: number;
  speed_kmh?: number;
  reason?: string;
}

/**
 * Impossible travel alert payload for admin notification
 */
interface ImpossibleTravelAlert {
  user_id: string;
  realm_id: string;
  session_id: string;
  previous_location: string;
  current_location: string;
  distance_km: number;
  time_elapsed_hours: number;
  speed_kmh: number;
  risk_level: string;
  detected_at: string;
  action_taken: 'alert_only' | 'session_revoked';
}

function createErrorResponse(
  statusCode: number,
  code: string,
  message: string,
  details?: Record<string, unknown>,
  requestId?: string
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
      'X-Frame-Options': 'DENY'
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

/**
 * Extract Bearer token from Authorization header
 */
function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null;
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }
  
  return parts[1];
}

/**
 * Parse device type from user agent
 * Enhanced detection for Desktop, Mobile, Tablet, and Unknown
 * Validates: Requirement 13.2 - Device type detection
 */
function parseDeviceType(userAgent: string): string {
  if (!userAgent) return 'Unknown';
  
  const ua = userAgent.toLowerCase();
  
  // Check for tablets first (before mobile, as some tablets include 'mobile')
  if (
    ua.includes('ipad') ||
    ua.includes('tablet') ||
    (ua.includes('android') && !ua.includes('mobile')) ||
    ua.includes('kindle') ||
    ua.includes('silk') ||
    ua.includes('playbook')
  ) {
    return 'Tablet';
  }
  
  // Check for mobile devices
  if (
    ua.includes('mobile') ||
    ua.includes('iphone') ||
    ua.includes('ipod') ||
    ua.includes('android') ||
    ua.includes('blackberry') ||
    ua.includes('windows phone') ||
    ua.includes('opera mini') ||
    ua.includes('opera mobi') ||
    ua.includes('iemobile') ||
    ua.includes('webos')
  ) {
    return 'Mobile';
  }
  
  // Check for desktop
  if (
    ua.includes('windows') ||
    ua.includes('macintosh') ||
    ua.includes('mac os') ||
    ua.includes('linux') ||
    ua.includes('cros') || // Chrome OS
    ua.includes('x11')
  ) {
    return 'Desktop';
  }
  
  return 'Unknown';
}

/**
 * Browser info with name and version
 */
interface BrowserInfo {
  name: string;
  version: string;
}

/**
 * Parse browser name and version from user agent
 * Enhanced detection with version extraction
 * Validates: Requirement 13.2 - Browser detection
 */
function parseBrowserInfo(userAgent: string): BrowserInfo {
  if (!userAgent) return { name: 'Unknown', version: '' };
  
  const ua = userAgent;
  
  // Order matters - check more specific patterns first
  
  // Edge (Chromium-based)
  const edgeMatch = ua.match(/Edg(?:e|A|iOS)?\/(\d+(?:\.\d+)*)/);
  if (edgeMatch) {
    return { name: 'Edge', version: edgeMatch[1] };
  }
  
  // Opera (OPR for desktop, Opera for mobile)
  const operaMatch = ua.match(/(?:OPR|Opera)\/(\d+(?:\.\d+)*)/);
  if (operaMatch) {
    return { name: 'Opera', version: operaMatch[1] };
  }
  
  // Samsung Browser
  const samsungMatch = ua.match(/SamsungBrowser\/(\d+(?:\.\d+)*)/);
  if (samsungMatch) {
    return { name: 'Samsung Browser', version: samsungMatch[1] };
  }
  
  // UC Browser
  const ucMatch = ua.match(/UCBrowser\/(\d+(?:\.\d+)*)/);
  if (ucMatch) {
    return { name: 'UC Browser', version: ucMatch[1] };
  }
  
  // Firefox
  const firefoxMatch = ua.match(/Firefox\/(\d+(?:\.\d+)*)/);
  if (firefoxMatch) {
    return { name: 'Firefox', version: firefoxMatch[1] };
  }
  
  // Chrome (must be after Edge, Opera, Samsung, UC)
  const chromeMatch = ua.match(/Chrome\/(\d+(?:\.\d+)*)/);
  if (chromeMatch && !ua.includes('Edg') && !ua.includes('OPR')) {
    return { name: 'Chrome', version: chromeMatch[1] };
  }
  
  // Safari (must be after Chrome)
  const safariMatch = ua.match(/Version\/(\d+(?:\.\d+)*).*Safari/);
  if (safariMatch && !ua.includes('Chrome') && !ua.includes('Chromium')) {
    return { name: 'Safari', version: safariMatch[1] };
  }
  
  // Internet Explorer
  const ieMatch = ua.match(/(?:MSIE |rv:)(\d+(?:\.\d+)*)/);
  if (ieMatch && (ua.includes('MSIE') || ua.includes('Trident'))) {
    return { name: 'Internet Explorer', version: ieMatch[1] };
  }
  
  // Brave (identifies as Chrome but has Brave in UA)
  if (ua.includes('Brave')) {
    const braveMatch = ua.match(/Chrome\/(\d+(?:\.\d+)*)/);
    return { name: 'Brave', version: braveMatch ? braveMatch[1] : '' };
  }
  
  return { name: 'Unknown', version: '' };
}

/**
 * Parse browser name from user agent (backward compatible)
 */
function parseBrowserName(userAgent: string): string {
  return parseBrowserInfo(userAgent).name;
}

/**
 * Enrich session with geolocation data
 * Validates: Requirement 13.2 - IP geolocation (city, country, country_code)
 */
async function enrichSessionWithGeoLocation(ipAddress: string): Promise<{
  city?: string;
  country?: string;
  country_code?: string;
} | undefined> {
  if (!ipAddress || ipAddress === 'unknown') {
    return undefined;
  }
  
  try {
    const geoLocation = await lookupIpLocation(ipAddress);
    if (geoLocation) {
      return {
        city: geoLocation.city,
        country: geoLocation.country,
        country_code: geoLocation.countryCode
      };
    }
  } catch (error) {
    // Log but don't fail - geolocation is optional enrichment
    console.warn('Failed to lookup IP geolocation:', error);
  }
  
  return undefined;
}

/**
 * Convert internal session to client-facing session info
 * Validates: Requirement 13.2 - Session info includes device, browser, IP, location, last_activity, is_current
 */
function toSessionInfo(
  session: Session, 
  currentSessionId: string,
  location?: { city?: string; country?: string; country_code?: string }
): SessionInfo {
  const userAgent = session.user_agent || 'Unknown';
  const browserInfo = parseBrowserInfo(userAgent);
  
  // Format browser with version if available
  const browserDisplay = browserInfo.version 
    ? `${browserInfo.name} ${browserInfo.version.split('.')[0]}` // Major version only
    : browserInfo.name;
  
  return {
    id: session.id,
    device: parseDeviceType(userAgent),
    browser: browserDisplay,
    ip_address: maskIpAddress(session.ip_address),
    location: location,
    last_activity: session.last_used_at || session.created_at,
    created_at: session.created_at,
    is_current: session.id === currentSessionId,
    user_agent: userAgent
  };
}

/**
 * Convert internal session to client-facing session info with async geolocation enrichment
 * Validates: Requirement 13.2 - Full session info enrichment
 */
async function toEnrichedSessionInfo(
  session: Session, 
  currentSessionId: string
): Promise<SessionInfo> {
  const location = await enrichSessionWithGeoLocation(session.ip_address);
  return toSessionInfo(session, currentSessionId, location);
}

/**
 * Check for impossible travel between sessions
 * Validates: Requirement 13.5 - Calculate geo-velocity and detect impossible travel
 * 
 * @param userId - User ID to check
 * @param realmId - Realm ID for configuration
 * @param currentIp - Current session IP address
 * @returns Impossible travel detection result
 */
async function checkImpossibleTravel(
  userId: string,
  realmId: string,
  currentIp: string
): Promise<ImpossibleTravelInfo | undefined> {
  if (!currentIp || currentIp === 'unknown') {
    return undefined;
  }

  try {
    // Get current location from IP
    const currentLocation = await lookupIpLocation(currentIp);
    if (!currentLocation) {
      return undefined;
    }

    // Get realm-specific velocity config
    const velocityConfig = getRealmVelocityConfig(realmId);

    // Check geo-velocity against previous logins
    const velocityResult = await checkGeoVelocity(
      userId,
      realmId,
      currentIp,
      currentLocation,
      velocityConfig
    );

    // Only return info if suspicious or impossible travel detected
    if (velocityResult.isSuspicious || velocityResult.isImpossibleTravel) {
      return {
        detected: velocityResult.isImpossibleTravel,
        risk_level: velocityResult.riskLevel,
        previous_location: velocityResult.previousLocation ? {
          city: velocityResult.previousLocation.city,
          country: velocityResult.previousLocation.country
        } : undefined,
        current_location: {
          city: currentLocation.city,
          country: currentLocation.country
        },
        distance_km: Math.round(velocityResult.distanceKm),
        time_elapsed_hours: parseFloat(velocityResult.timeElapsedHours.toFixed(2)),
        speed_kmh: Math.round(velocityResult.speedKmh),
        reason: velocityResult.reason
      };
    }

    return undefined;
  } catch (error) {
    console.warn('Failed to check impossible travel:', error);
    return undefined;
  }
}

/**
 * Alert admin on impossible travel detection
 * Validates: Requirement 13.5 - Alert on impossible travel
 * 
 * @param alert - Impossible travel alert details
 */
async function alertAdminOnImpossibleTravel(
  alert: ImpossibleTravelAlert
): Promise<void> {
  try {
    // Log security event for admin visibility
    await logSecurityEvent({
      event_type: 'impossible_travel_alert',
      ip_address: 'system',
      realm_id: alert.realm_id,
      user_id: alert.user_id,
      details: {
        session_id: alert.session_id,
        previous_location: alert.previous_location,
        current_location: alert.current_location,
        distance_km: alert.distance_km,
        time_elapsed_hours: alert.time_elapsed_hours,
        speed_kmh: alert.speed_kmh,
        risk_level: alert.risk_level,
        action_taken: alert.action_taken
      }
    });

    // TODO: In production, also send webhook notification to admin
    // await dispatchImpossibleTravelAlert(alert.realm_id, alert);
    
    console.log(`[IMPOSSIBLE_TRAVEL_ALERT] User ${alert.user_id} - ${alert.previous_location} → ${alert.current_location} (${alert.distance_km}km in ${alert.time_elapsed_hours}h)`);
  } catch (error) {
    console.error('Failed to alert admin on impossible travel:', error);
  }
}

/**
 * Optionally revoke session based on realm policy
 * Validates: Requirement 13.5 - Optionally revoke session
 * 
 * @param sessionId - Session to revoke
 * @param realmId - Realm ID for policy check
 * @param userId - User ID
 * @param velocityResult - Velocity check result
 * @returns Whether session was revoked
 */
async function maybeRevokeSessionOnImpossibleTravel(
  sessionId: string,
  realmId: string,
  userId: string,
  velocityResult: ImpossibleTravelInfo
): Promise<boolean> {
  // Get realm-specific velocity config to check if auto-revoke is enabled
  const velocityConfig = getRealmVelocityConfig(realmId);
  
  // Only revoke if:
  // 1. Impossible travel was detected (not just suspicious)
  // 2. Realm policy enables blocking on impossible travel
  // 3. Risk level is critical
  if (
    velocityResult.detected && 
    velocityConfig.blockOnImpossibleTravel &&
    velocityResult.risk_level === 'critical'
  ) {
    try {
      const deleted = await deleteSession(sessionId, realmId, userId);
      
      if (deleted) {
        // Log the automatic revocation
        await logSecurityEvent({
          event_type: 'session_auto_revoked_impossible_travel',
          ip_address: 'system',
          realm_id: realmId,
          user_id: userId,
          details: {
            session_id: sessionId,
            reason: velocityResult.reason,
            distance_km: velocityResult.distance_km,
            speed_kmh: velocityResult.speed_kmh
          }
        });

        // Trigger webhook for session revocation
        try {
          await dispatchSessionRevoked(realmId, {
            session_id: sessionId,
            user_id: userId,
            realm_id: realmId,
            reason: 'impossible_travel'
          });
        } catch (webhookError) {
          console.error('Failed to dispatch session.revoked webhook:', webhookError);
        }

        return true;
      }
    } catch (error) {
      console.error('Failed to revoke session on impossible travel:', error);
    }
  }

  return false;
}

/**
 * Mask IP address for privacy (show only first two octets for IPv4)
 */
function maskIpAddress(ip: string): string {
  if (!ip || ip === 'unknown') return 'unknown';
  
  // IPv4
  const ipv4Parts = ip.split('.');
  if (ipv4Parts.length === 4) {
    return `${ipv4Parts[0]}.${ipv4Parts[1]}.*.*`;
  }
  
  // IPv6 - mask last 4 groups
  const ipv6Parts = ip.split(':');
  if (ipv6Parts.length >= 4) {
    return `${ipv6Parts.slice(0, 4).join(':')}:****`;
  }
  
  return ip;
}

/**
 * Extract session ID from the current access token
 * The session ID is stored in the jti claim
 */
function extractCurrentSessionId(accessToken: string): string | null {
  try {
    // Decode the token without verification to get the jti
    const parts = accessToken.split('.');
    if (parts.length !== 3) return null;
    
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return payload.jti || null;
  } catch {
    return null;
  }
}

/**
 * Authenticate the request and return the JWT payload
 */
async function authenticateRequest(
  event: APIGatewayProxyEvent,
  requestId?: string
): Promise<{ payload: JWTPayload; accessToken: string } | APIGatewayProxyResult> {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;
  const accessToken = extractBearerToken(authHeader);

  if (!accessToken) {
    return createErrorResponse(
      401,
      'UNAUTHORIZED',
      'Authorization header with Bearer token is required',
      undefined,
      requestId
    );
  }

  try {
    const payload = await verifyAccessToken(accessToken);
    return { payload, accessToken };
  } catch (error) {
    const errorMessage = (error as Error).message;
    
    if (errorMessage.includes('expired')) {
      return createErrorResponse(
        401,
        'TOKEN_EXPIRED',
        'Access token has expired',
        undefined,
        requestId
      );
    }
    
    return createErrorResponse(
      401,
      'INVALID_TOKEN',
      'Invalid access token',
      undefined,
      requestId
    );
  }
}

/**
 * GET /sessions - List all active sessions for the authenticated user
 * Validates: Requirement 13.1, 13.2, 13.5
 * Enhanced with geolocation enrichment and impossible travel detection
 */
async function listSessions(
  event: APIGatewayProxyEvent,
  payload: JWTPayload,
  currentSessionId: string | null,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);
  
  try {
    // Get all sessions for the user
    const sessions = await getUserSessions(payload.realm_id, payload.sub);
    
    // Filter out revoked sessions
    const activeSessions = sessions.filter(s => !s.revoked);
    
    // Enrich sessions with geolocation data (parallel processing for performance)
    const enrichedSessions = await Promise.all(
      activeSessions.map(s => toEnrichedSessionInfo(s, currentSessionId || ''))
    );

    // Check for impossible travel on current session (Requirement 13.5)
    let impossibleTravelDetected = false;
    if (currentSessionId && clientIP && clientIP !== 'unknown') {
      const impossibleTravel = await checkImpossibleTravel(
        payload.sub,
        payload.realm_id,
        clientIP
      );

      if (impossibleTravel && (impossibleTravel.detected || impossibleTravel.risk_level === 'high')) {
        impossibleTravelDetected = true;

        // Find current session and add impossible travel info
        const currentSessionIndex = enrichedSessions.findIndex(s => s.id === currentSessionId);
        if (currentSessionIndex >= 0) {
          enrichedSessions[currentSessionIndex].impossible_travel = impossibleTravel;
        }

        // Alert admin on impossible travel detection
        await alertAdminOnImpossibleTravel({
          user_id: payload.sub,
          realm_id: payload.realm_id,
          session_id: currentSessionId,
          previous_location: impossibleTravel.previous_location 
            ? `${impossibleTravel.previous_location.city || 'Unknown'}, ${impossibleTravel.previous_location.country || 'Unknown'}`
            : 'Unknown',
          current_location: impossibleTravel.current_location
            ? `${impossibleTravel.current_location.city || 'Unknown'}, ${impossibleTravel.current_location.country || 'Unknown'}`
            : 'Unknown',
          distance_km: impossibleTravel.distance_km || 0,
          time_elapsed_hours: impossibleTravel.time_elapsed_hours || 0,
          speed_kmh: impossibleTravel.speed_kmh || 0,
          risk_level: impossibleTravel.risk_level,
          detected_at: new Date().toISOString(),
          action_taken: 'alert_only'
        });

        // Optionally revoke session based on realm policy
        if (impossibleTravel.detected) {
          const wasRevoked = await maybeRevokeSessionOnImpossibleTravel(
            currentSessionId,
            payload.realm_id,
            payload.sub,
            impossibleTravel
          );

          if (wasRevoked) {
            // Update the alert with revocation action
            await alertAdminOnImpossibleTravel({
              user_id: payload.sub,
              realm_id: payload.realm_id,
              session_id: currentSessionId,
              previous_location: impossibleTravel.previous_location 
                ? `${impossibleTravel.previous_location.city || 'Unknown'}, ${impossibleTravel.previous_location.country || 'Unknown'}`
                : 'Unknown',
              current_location: impossibleTravel.current_location
                ? `${impossibleTravel.current_location.city || 'Unknown'}, ${impossibleTravel.current_location.country || 'Unknown'}`
                : 'Unknown',
              distance_km: impossibleTravel.distance_km || 0,
              time_elapsed_hours: impossibleTravel.time_elapsed_hours || 0,
              speed_kmh: impossibleTravel.speed_kmh || 0,
              risk_level: impossibleTravel.risk_level,
              detected_at: new Date().toISOString(),
              action_taken: 'session_revoked'
            });

            // Return error indicating session was revoked
            return createErrorResponse(
              403,
              'SESSION_REVOKED_IMPOSSIBLE_TRAVEL',
              'Session revoked due to impossible travel detection',
              {
                reason: impossibleTravel.reason,
                previous_location: impossibleTravel.previous_location,
                current_location: impossibleTravel.current_location
              },
              requestId
            );
          }
        }
      }
    }
    
    // Update last activity for current session
    if (currentSessionId) {
      const currentSession = activeSessions.find(s => s.id === currentSessionId);
      if (currentSession) {
        try {
          await updateSessionLastActivity(currentSessionId, payload.realm_id, payload.sub);
        } catch (updateError) {
          // Don't fail the request if activity update fails
          console.warn('Failed to update session last activity:', updateError);
        }
      }
    }
    
    // Log the session list request
    await logSecurityEvent({
      event_type: 'sessions_listed',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { 
        session_count: enrichedSessions.length,
        impossible_travel_detected: impossibleTravelDetected
      }
    });
    
    return createSuccessResponse(200, {
      message: 'Sessions retrieved successfully',
      sessions: enrichedSessions,
      total: enrichedSessions.length,
      impossible_travel_detected: impossibleTravelDetected
    });
  } catch (error) {
    console.error('Error listing sessions:', error);
    
    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'Failed to retrieve sessions',
      undefined,
      requestId
    );
  }
}

/**
 * GET /sessions/{id} - Get session details
 * Validates: Requirement 13.2 - Full session info enrichment
 */
async function getSessionDetails(
  event: APIGatewayProxyEvent,
  payload: JWTPayload,
  sessionId: string,
  currentSessionId: string | null,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);
  
  try {
    // Find the session
    const session = await findSessionById(sessionId, payload.realm_id, payload.sub);
    
    if (!session) {
      return createErrorResponse(
        404,
        'SESSION_NOT_FOUND',
        'Session not found',
        undefined,
        requestId
      );
    }
    
    // Verify the session belongs to the authenticated user
    if (session.user_id !== payload.sub || session.realm_id !== payload.realm_id) {
      return createErrorResponse(
        403,
        'FORBIDDEN',
        'Cannot access session belonging to another user',
        undefined,
        requestId
      );
    }
    
    // Check if session is revoked
    if (session.revoked) {
      return createErrorResponse(
        404,
        'SESSION_NOT_FOUND',
        'Session not found',
        undefined,
        requestId
      );
    }
    
    // Enrich session with geolocation data
    const sessionInfo = await toEnrichedSessionInfo(session, currentSessionId || '');

    // Check for impossible travel on the session being viewed (Requirement 13.5)
    if (session.ip_address && session.ip_address !== 'unknown') {
      const impossibleTravel = await checkImpossibleTravel(
        payload.sub,
        payload.realm_id,
        session.ip_address
      );

      if (impossibleTravel && (impossibleTravel.detected || impossibleTravel.risk_level === 'high')) {
        sessionInfo.impossible_travel = impossibleTravel;

        // Alert admin if this is the current session
        if (sessionId === currentSessionId) {
          await alertAdminOnImpossibleTravel({
            user_id: payload.sub,
            realm_id: payload.realm_id,
            session_id: sessionId,
            previous_location: impossibleTravel.previous_location 
              ? `${impossibleTravel.previous_location.city || 'Unknown'}, ${impossibleTravel.previous_location.country || 'Unknown'}`
              : 'Unknown',
            current_location: impossibleTravel.current_location
              ? `${impossibleTravel.current_location.city || 'Unknown'}, ${impossibleTravel.current_location.country || 'Unknown'}`
              : 'Unknown',
            distance_km: impossibleTravel.distance_km || 0,
            time_elapsed_hours: impossibleTravel.time_elapsed_hours || 0,
            speed_kmh: impossibleTravel.speed_kmh || 0,
            risk_level: impossibleTravel.risk_level,
            detected_at: new Date().toISOString(),
            action_taken: 'alert_only'
          });
        }
      }
    }
    
    // Update last activity for this session if it's the current one
    if (sessionId === currentSessionId) {
      try {
        await updateSessionLastActivity(sessionId, payload.realm_id, payload.sub);
      } catch (updateError) {
        console.warn('Failed to update session last activity:', updateError);
      }
    }
    
    // Log the session detail request
    await logSecurityEvent({
      event_type: 'session_details_viewed',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { session_id: sessionId }
    });
    
    return createSuccessResponse(200, {
      message: 'Session retrieved successfully',
      session: sessionInfo
    });
  } catch (error) {
    console.error('Error getting session details:', error);
    
    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'Failed to retrieve session',
      undefined,
      requestId
    );
  }
}

/**
 * DELETE /sessions/{id} - Revoke specific session
 * Validates: Requirement 13.3
 */
async function revokeSession(
  event: APIGatewayProxyEvent,
  payload: JWTPayload,
  sessionId: string,
  currentSessionId: string | null,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);
  
  try {
    // Find the session first
    const session = await findSessionById(sessionId, payload.realm_id, payload.sub);
    
    if (!session) {
      return createErrorResponse(
        404,
        'SESSION_NOT_FOUND',
        'Session not found',
        undefined,
        requestId
      );
    }
    
    // Verify the session belongs to the authenticated user
    if (session.user_id !== payload.sub || session.realm_id !== payload.realm_id) {
      return createErrorResponse(
        403,
        'FORBIDDEN',
        'Cannot revoke session belonging to another user',
        undefined,
        requestId
      );
    }
    
    // Check if trying to revoke current session
    const isCurrentSession = sessionId === currentSessionId;
    
    // Delete the session
    const deleted = await deleteSession(sessionId, payload.realm_id, payload.sub);
    
    if (!deleted) {
      return createErrorResponse(
        500,
        'REVOKE_FAILED',
        'Failed to revoke session',
        undefined,
        requestId
      );
    }
    
    // Log the session revocation
    await logSecurityEvent({
      event_type: 'session_revoked',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { 
        session_id: sessionId,
        is_current_session: isCurrentSession
      }
    });
    
    // Trigger session.revoked webhook (Requirement 13.8)
    try {
      await dispatchSessionRevoked(payload.realm_id, {
        session_id: sessionId,
        user_id: payload.sub,
        realm_id: payload.realm_id,
        reason: 'logout'
      });
    } catch (webhookError) {
      console.error('Failed to dispatch session.revoked webhook:', webhookError);
      // Don't fail the request if webhook fails
    }
    
    return createSuccessResponse(200, {
      message: 'Session revoked successfully',
      session_id: sessionId,
      is_current_session: isCurrentSession
    });
  } catch (error) {
    console.error('Error revoking session:', error);
    
    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'Failed to revoke session',
      undefined,
      requestId
    );
  }
}

/**
 * DELETE /sessions - Revoke all sessions except current
 * Validates: Requirement 13.4
 */
async function revokeAllSessions(
  event: APIGatewayProxyEvent,
  payload: JWTPayload,
  currentSessionId: string | null,
  requestId?: string
): Promise<APIGatewayProxyResult> {
  const clientIP = getClientIP(event);
  
  try {
    // Get all sessions for the user
    const sessions = await getUserSessions(payload.realm_id, payload.sub);
    
    // Filter out the current session
    const sessionsToRevoke = sessions.filter(s => s.id !== currentSessionId && !s.revoked);
    
    if (sessionsToRevoke.length === 0) {
      return createSuccessResponse(200, {
        message: 'No other sessions to revoke',
        revoked_count: 0
      });
    }
    
    // Delete each session except current
    let revokedCount = 0;
    for (const session of sessionsToRevoke) {
      const deleted = await deleteSession(session.id, payload.realm_id, payload.sub);
      if (deleted) {
        revokedCount++;
        
        // Trigger session.revoked webhook for each session
        try {
          await dispatchSessionRevoked(payload.realm_id, {
            session_id: session.id,
            user_id: payload.sub,
            realm_id: payload.realm_id,
            reason: 'force_logout'
          });
        } catch (webhookError) {
          console.error('Failed to dispatch session.revoked webhook:', webhookError);
          // Don't fail the request if webhook fails
        }
      }
    }
    
    // Log the bulk session revocation
    await logSecurityEvent({
      event_type: 'sessions_revoked_all',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { 
        revoked_count: revokedCount,
        kept_current_session: currentSessionId ? true : false
      }
    });
    
    return createSuccessResponse(200, {
      message: `${revokedCount} session(s) revoked successfully`,
      revoked_count: revokedCount
    });
  } catch (error) {
    console.error('Error revoking all sessions:', error);
    
    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'Failed to revoke sessions',
      undefined,
      requestId
    );
  }
}

/**
 * Main handler for session management endpoints
 */
export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);
  const httpMethod = event.httpMethod;
  const pathParameters = event.pathParameters;
  
  try {
    // Authenticate the request
    const authResult = await authenticateRequest(event, requestId);
    
    // If authResult is an APIGatewayProxyResult, it's an error response
    if ('statusCode' in authResult) {
      return authResult;
    }
    
    const { payload, accessToken } = authResult;
    
    // Rate limiting check
    const rateLimitResult = await checkRateLimit(
      payload.realm_id,
      `sessions:${payload.sub}`,
      SESSION_RATE_LIMIT
    );

    if (!rateLimitResult.allowed) {
      await logSecurityEvent({
        event_type: 'rate_limit_exceeded',
        ip_address: clientIP,
        realm_id: payload.realm_id,
        user_id: payload.sub,
        details: { endpoint: 'sessions', retry_after: rateLimitResult.retryAfter }
      });

      return createErrorResponse(
        429,
        'RATE_LIMITED',
        'Too many requests. Please try again later.',
        { retry_after: rateLimitResult.retryAfter },
        requestId
      );
    }
    
    // Extract current session ID from the access token
    const currentSessionId = extractCurrentSessionId(accessToken);
    
    // Route based on HTTP method and path
    const sessionId = pathParameters?.id || pathParameters?.sessionId;
    
    if (httpMethod === 'GET') {
      if (sessionId) {
        // GET /sessions/{id} - Get session details
        return await getSessionDetails(event, payload, sessionId, currentSessionId, requestId);
      } else {
        // GET /sessions - List all sessions
        return await listSessions(event, payload, currentSessionId, requestId);
      }
    }
    
    if (httpMethod === 'DELETE') {
      if (sessionId) {
        // DELETE /sessions/{id} - Revoke specific session
        return await revokeSession(event, payload, sessionId, currentSessionId, requestId);
      } else {
        // DELETE /sessions - Revoke all sessions except current
        return await revokeAllSessions(event, payload, currentSessionId, requestId);
      }
    }
    
    // Method not allowed
    return createErrorResponse(
      405,
      'METHOD_NOT_ALLOWED',
      `Method ${httpMethod} not allowed`,
      undefined,
      requestId
    );
  } catch (error) {
    console.error('Session handler error:', error);

    await logSecurityEvent({
      event_type: 'session_handler_error',
      ip_address: clientIP,
      details: { error: (error as Error).message }
    });

    return createErrorResponse(
      500,
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      undefined,
      requestId
    );
  }
}
