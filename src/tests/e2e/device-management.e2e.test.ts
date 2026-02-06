/**
 * Device Management Handler E2E Tests
 * 
 * Task 3.3: Device Management Handler
 * Validates: Requirements 3.3 (Device Management)
 * 
 * @e2e-test
 * @phase Phase 3
 */

import { APIGatewayProxyEvent } from 'aws-lambda';

// Mock dependencies
jest.mock('../../utils/jwt', () => ({
  verifyAccessToken: jest.fn()
}));

jest.mock('../../repositories/user.repository', () => ({
  findUserById: jest.fn()
}));

jest.mock('../../utils/password', () => ({
  verifyPassword: jest.fn().mockResolvedValue(true)
}));

jest.mock('../../services/security-logger.service', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

jest.mock('../../services/realm.service', () => ({
  getRememberDeviceDuration: jest.fn().mockResolvedValue(30 * 24 * 60 * 60) // 30 days
}));

// Import after mocks
import {
  listDevicesHandler,
  deleteDeviceHandler,
  trustDeviceHandler,
  untrustDeviceHandler,
  getUserDevices,
  saveUserDevices,
  addUserDevice
} from '../../handlers/device.handler';
import { verifyAccessToken } from '../../utils/jwt';
import { findUserById } from '../../repositories/user.repository';
import { verifyPassword } from '../../utils/password';
import { createDeviceRecord } from '../../services/device.service';

const mockPayload = {
  sub: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  type: 'access'
};

const mockUser = {
  id: 'user-123',
  realm_id: 'clinisyn-psychologists',
  email: 'dr.ayse@example.com',
  password_hash: '$argon2id$v=19$m=32768,t=5,p=2$hash',
  status: 'active'
};

const mockFingerprint = {
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
  screen: '2560x1600',
  timezone: 'Europe/Istanbul',
  language: 'tr-TR',
  platform: 'MacIntel'
};

function createMockEvent(
  body: object | null = null,
  accessToken: string = 'valid-access-token',
  pathParameters: Record<string, string> | null = null
): APIGatewayProxyEvent {
  return {
    body: body ? JSON.stringify(body) : null,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
      'User-Agent': 'Test-Agent/1.0'
    },
    httpMethod: 'GET',
    isBase64Encoded: false,
    path: '/v1/auth/devices',
    pathParameters,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '192.168.1.1' }
    } as any,
    resource: '/v1/auth/devices',
    multiValueHeaders: {}
  };
}

describe('Device Management Handler E2E Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (verifyAccessToken as jest.Mock).mockResolvedValue(mockPayload);
    (findUserById as jest.Mock).mockResolvedValue(mockUser);
    
    // Clear device store
    saveUserDevices('user-123', []);
  });

  describe('List Devices Handler', () => {
    it('should return empty list when no devices', async () => {
      const event = createMockEvent();

      const response = await listDevicesHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.devices).toEqual([]);
      expect(body.count).toBe(0);
    });

    it('should return list of devices', async () => {
      // Add a device
      const device = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint, '192.168.1.1');
      addUserDevice('user-123', device);

      const event = createMockEvent();

      const response = await listDevicesHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.devices).toHaveLength(1);
      expect(body.devices[0].id).toBe(device.id);
      expect(body.devices[0].name).toContain('Chrome');
    });

    it('should mask IP addresses for privacy', async () => {
      const device = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint, '192.168.1.100');
      addUserDevice('user-123', device);

      const event = createMockEvent();

      const response = await listDevicesHandler(event);
      const body = JSON.parse(response.body);

      expect(body.devices[0].lastIpAddress).toBe('192.168.*.*');
    });

    it('should not expose fingerprint hash', async () => {
      const device = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      addUserDevice('user-123', device);

      const event = createMockEvent();

      const response = await listDevicesHandler(event);
      const body = JSON.parse(response.body);

      expect(body.devices[0].fingerprintHash).toBeUndefined();
      expect(body.devices[0].components).toBeUndefined();
    });

    it('should reject without authorization', async () => {
      const event = {
        ...createMockEvent(),
        headers: { 'Content-Type': 'application/json' }
      };

      const response = await listDevicesHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('UNAUTHORIZED');
    });
  });

  describe('Delete Device Handler', () => {
    beforeEach(() => {
      const device = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      addUserDevice('user-123', { ...device, id: 'device-to-delete' });
    });

    it('should delete device with valid password', async () => {
      const event = createMockEvent(
        { password: 'ValidPassword123!' },
        'valid-token',
        { id: 'device-to-delete' }
      );

      const response = await deleteDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Device removed successfully');
      expect(getUserDevices('user-123')).toHaveLength(0);
    });

    it('should reject invalid password', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(false);

      const event = createMockEvent(
        { password: 'WrongPassword!' },
        'valid-token',
        { id: 'device-to-delete' }
      );

      const response = await deleteDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(401);
      expect(body.error.code).toBe('INVALID_PASSWORD');
    });

    it('should reject missing password', async () => {
      const event = createMockEvent(
        {},
        'valid-token',
        { id: 'device-to-delete' }
      );

      const response = await deleteDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject non-existent device', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(true);
      
      const event = createMockEvent(
        { password: 'ValidPassword123!' },
        'valid-token',
        { id: 'non-existent-device' }
      );

      const response = await deleteDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('DEVICE_NOT_FOUND');
    });
  });

  describe('Trust Device Handler', () => {
    beforeEach(() => {
      const device = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      addUserDevice('user-123', { ...device, id: 'device-to-trust', trusted: false });
    });

    it('should trust device successfully', async () => {
      const event = createMockEvent(
        { device_id: 'device-to-trust' },
        'valid-token'
      );

      const response = await trustDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Device trusted successfully');
      expect(body.device.trusted).toBe(true);
      expect(body.device.trustExpiresAt).toBeDefined();
    });

    it('should set trust expiration', async () => {
      const event = createMockEvent(
        { device_id: 'device-to-trust' },
        'valid-token'
      );

      const response = await trustDeviceHandler(event);
      const body = JSON.parse(response.body);

      const expiresAt = new Date(body.device.trustExpiresAt);
      const now = new Date();
      const daysDiff = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

      // Should be approximately 30 days
      expect(daysDiff).toBeGreaterThan(29);
      expect(daysDiff).toBeLessThan(31);
    });

    it('should allow custom device name', async () => {
      const event = createMockEvent(
        { device_id: 'device-to-trust', device_name: 'My Work MacBook' },
        'valid-token'
      );

      const response = await trustDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(body.device.name).toBe('My Work MacBook');
    });

    it('should reject missing device_id', async () => {
      const event = createMockEvent({}, 'valid-token');

      const response = await trustDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(400);
      expect(body.error.code).toBe('INVALID_REQUEST');
    });

    it('should reject non-existent device', async () => {
      const event = createMockEvent(
        { device_id: 'non-existent' },
        'valid-token'
      );

      const response = await trustDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('DEVICE_NOT_FOUND');
    });
  });

  describe('Untrust Device Handler', () => {
    beforeEach(() => {
      const device = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      addUserDevice('user-123', { 
        ...device, 
        id: 'trusted-device', 
        trusted: true,
        trustExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      });
    });

    it('should remove trust from device', async () => {
      const event = createMockEvent(
        { device_id: 'trusted-device' },
        'valid-token'
      );

      const response = await untrustDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(200);
      expect(body.message).toBe('Device trust removed successfully');

      const devices = getUserDevices('user-123');
      expect(devices[0].trusted).toBe(false);
      expect(devices[0].trustExpiresAt).toBeUndefined();
    });

    it('should reject non-existent device', async () => {
      const event = createMockEvent(
        { device_id: 'non-existent' },
        'valid-token'
      );

      const response = await untrustDeviceHandler(event);
      const body = JSON.parse(response.body);

      expect(response.statusCode).toBe(404);
      expect(body.error.code).toBe('DEVICE_NOT_FOUND');
    });
  });

  describe('Security Logging', () => {
    it('should log device removal', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');
      (verifyPassword as jest.Mock).mockResolvedValue(true);
      
      const device = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      saveUserDevices('user-123', [{ ...device, id: 'device-to-delete' }]);

      const event = createMockEvent(
        { password: 'ValidPassword123!' },
        'valid-token',
        { id: 'device-to-delete' }
      );

      await deleteDeviceHandler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'device_removed'
        })
      );
    });

    it('should log device trust', async () => {
      const { logSecurityEvent } = require('../../services/security-logger.service');
      
      const device = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      addUserDevice('user-123', { ...device, id: 'device-to-trust' });

      const event = createMockEvent(
        { device_id: 'device-to-trust' },
        'valid-token'
      );

      await trustDeviceHandler(event);

      expect(logSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'device_trusted'
        })
      );
    });
  });

  describe('Multiple Devices', () => {
    it('should handle multiple devices per user', async () => {
      // Add multiple devices
      const device1 = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      const device2 = createDeviceRecord('user-123', 'clinisyn-psychologists', {
        ...mockFingerprint,
        platform: 'iPhone'
      });
      
      addUserDevice('user-123', { ...device1, id: 'device-1' });
      addUserDevice('user-123', { ...device2, id: 'device-2' });

      const event = createMockEvent();

      const response = await listDevicesHandler(event);
      const body = JSON.parse(response.body);

      expect(body.devices).toHaveLength(2);
      expect(body.count).toBe(2);
    });

    it('should only delete specified device', async () => {
      (verifyPassword as jest.Mock).mockResolvedValue(true);
      
      const device1 = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      const device2 = createDeviceRecord('user-123', 'clinisyn-psychologists', mockFingerprint);
      
      // Use saveUserDevices to set clean state
      saveUserDevices('user-123', [
        { ...device1, id: 'device-1' },
        { ...device2, id: 'device-2' }
      ]);

      const event = createMockEvent(
        { password: 'ValidPassword123!' },
        'valid-token',
        { id: 'device-1' }
      );

      await deleteDeviceHandler(event);

      const devices = getUserDevices('user-123');
      expect(devices).toHaveLength(1);
      expect(devices[0].id).toBe('device-2');
    });
  });
});
