/**
 * Device Management Lambda Handlers
 * Validates: Requirements 3.1, 3.2, 3.3 (Device Trust)
 * 
 * Endpoints:
 * - GET /v1/auth/devices - List user's devices
 * - DELETE /v1/auth/devices/:id - Remove a device
 * - POST /v1/auth/devices/trust - Trust current device
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { verifyAccessToken } from '../utils/jwt';
import { findUserById } from '../repositories/user.repository';
import { verifyPassword } from '../utils/password';
import { logSecurityEvent } from '../services/security-logger.service';
import { 
  StoredDevice, 
  generateDeviceName,
  DeviceFingerprintInput 
} from '../services/device.service';
import { getRememberDeviceDuration } from '../services/realm.service';

// In-memory device store (in production, use DynamoDB)
const deviceStore = new Map<string, StoredDevice[]>();

function createResponse(
  statusCode: number,
  body: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
    body: JSON.stringify(body)
  };
}

function extractBearerToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') return null;
  return parts[1];
}

function getClientIP(event: APIGatewayProxyEvent): string {
  return event.requestContext?.identity?.sourceIp || 'unknown';
}

/**
 * Get user's devices from store
 */
export function getUserDevices(userId: string): StoredDevice[] {
  return deviceStore.get(userId) || [];
}

/**
 * Save user's devices to store
 */
export function saveUserDevices(userId: string, devices: StoredDevice[]): void {
  deviceStore.set(userId, devices);
}

/**
 * Add a device for user
 */
export function addUserDevice(userId: string, device: StoredDevice): void {
  const devices = getUserDevices(userId);
  devices.push(device);
  saveUserDevices(userId, devices);
}

/**
 * GET /v1/auth/devices
 * List user's registered devices
 */
export async function listDevicesHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    const token = extractBearerToken(authHeader);
    
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const payload = await verifyAccessToken(token);
    
    // Get user's devices
    const devices = getUserDevices(payload.sub);

    // Get current device fingerprint from request (if available)
    const currentFingerprint = event.headers['X-Device-Fingerprint'];

    // Return safe device info
    const safeDevices = devices.map(d => ({
      id: d.id,
      name: d.name || generateDeviceName(d.components),
      trusted: d.trusted,
      trustExpiresAt: d.trustExpiresAt,
      firstSeenAt: d.firstSeenAt,
      lastSeenAt: d.lastSeenAt,
      lastIpAddress: d.lastIpAddress ? maskIpAddress(d.lastIpAddress) : undefined,
      loginCount: d.loginCount,
      isCurrent: currentFingerprint ? d.fingerprintHash === currentFingerprint : false
    }));

    return createResponse(200, {
      devices: safeDevices,
      count: safeDevices.length
    });

  } catch (error) {
    console.error('List devices error:', error);
    
    if ((error as Error).name === 'TokenExpiredError') {
      return createResponse(401, {
        error: { code: 'TOKEN_EXPIRED', message: 'Access token expired', request_id: requestId }
      });
    }

    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * DELETE /v1/auth/devices/:id
 * Remove a device (requires password)
 */
export async function deleteDeviceHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    const token = extractBearerToken(authHeader);
    
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const payload = await verifyAccessToken(token);

    // Get device ID from path
    const deviceId = event.pathParameters?.id;
    if (!deviceId) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Device ID required', request_id: requestId }
      });
    }

    // Get password from body
    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Password required to remove device', request_id: requestId }
      });
    }

    const { password } = JSON.parse(event.body);
    if (!password) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Password is required', request_id: requestId }
      });
    }

    // Get user and verify password
    const user = await findUserById(payload.realm_id, payload.sub);
    if (!user) {
      return createResponse(404, {
        error: { code: 'USER_NOT_FOUND', message: 'User not found', request_id: requestId }
      });
    }

    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid) {
      return createResponse(401, {
        error: { code: 'INVALID_PASSWORD', message: 'Invalid password', request_id: requestId }
      });
    }

    // Find and remove device
    const devices = getUserDevices(payload.sub);
    const deviceIndex = devices.findIndex(d => d.id === deviceId);

    if (deviceIndex === -1) {
      return createResponse(404, {
        error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found', request_id: requestId }
      });
    }

    const deletedDevice = devices[deviceIndex];
    const updatedDevices = devices.filter(d => d.id !== deviceId);
    saveUserDevices(payload.sub, updatedDevices);

    // TODO: Invalidate sessions for this device

    await logSecurityEvent({
      event_type: 'device_removed',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { 
        device_id: deviceId,
        device_name: deletedDevice.name
      }
    });

    return createResponse(200, {
      message: 'Device removed successfully'
    });

  } catch (error) {
    console.error('Delete device error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * POST /v1/auth/devices/trust
 * Trust the current device for MFA skip
 */
export async function trustDeviceHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    const token = extractBearerToken(authHeader);
    
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const payload = await verifyAccessToken(token);

    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { device_id, device_name } = JSON.parse(event.body);

    if (!device_id) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'device_id is required', request_id: requestId }
      });
    }

    // Find device
    const devices = getUserDevices(payload.sub);
    const deviceIndex = devices.findIndex(d => d.id === device_id);

    if (deviceIndex === -1) {
      return createResponse(404, {
        error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found', request_id: requestId }
      });
    }

    // Get trust duration from realm settings
    const trustDuration = await getRememberDeviceDuration(payload.realm_id);
    const trustExpiresAt = new Date(Date.now() + (trustDuration * 1000)).toISOString();

    // Update device trust
    devices[deviceIndex] = {
      ...devices[deviceIndex],
      trusted: true,
      trustExpiresAt,
      name: device_name || devices[deviceIndex].name
    };

    saveUserDevices(payload.sub, devices);

    await logSecurityEvent({
      event_type: 'device_trusted',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { 
        device_id,
        trust_expires_at: trustExpiresAt
      }
    });

    return createResponse(200, {
      message: 'Device trusted successfully',
      device: {
        id: devices[deviceIndex].id,
        name: devices[deviceIndex].name,
        trusted: true,
        trustExpiresAt
      }
    });

  } catch (error) {
    console.error('Trust device error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * POST /v1/auth/devices/untrust
 * Remove trust from a device
 */
export async function untrustDeviceHandler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId;
  const clientIP = getClientIP(event);

  try {
    // Verify access token
    const authHeader = event.headers.Authorization || event.headers.authorization;
    const token = extractBearerToken(authHeader);
    
    if (!token) {
      return createResponse(401, {
        error: { code: 'UNAUTHORIZED', message: 'Access token required', request_id: requestId }
      });
    }

    const payload = await verifyAccessToken(token);

    if (!event.body) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'Request body required', request_id: requestId }
      });
    }

    const { device_id } = JSON.parse(event.body);

    if (!device_id) {
      return createResponse(400, {
        error: { code: 'INVALID_REQUEST', message: 'device_id is required', request_id: requestId }
      });
    }

    // Find device
    const devices = getUserDevices(payload.sub);
    const deviceIndex = devices.findIndex(d => d.id === device_id);

    if (deviceIndex === -1) {
      return createResponse(404, {
        error: { code: 'DEVICE_NOT_FOUND', message: 'Device not found', request_id: requestId }
      });
    }

    // Remove trust
    devices[deviceIndex] = {
      ...devices[deviceIndex],
      trusted: false,
      trustExpiresAt: undefined
    };

    saveUserDevices(payload.sub, devices);

    await logSecurityEvent({
      event_type: 'device_untrusted',
      ip_address: clientIP,
      realm_id: payload.realm_id,
      user_id: payload.sub,
      details: { device_id }
    });

    return createResponse(200, {
      message: 'Device trust removed successfully'
    });

  } catch (error) {
    console.error('Untrust device error:', error);
    return createResponse(500, {
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', request_id: requestId }
    });
  }
}

/**
 * Mask IP address for privacy (show only first two octets)
 */
function maskIpAddress(ip: string): string {
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.*.*`;
  }
  return ip.substring(0, ip.length / 2) + '***';
}
