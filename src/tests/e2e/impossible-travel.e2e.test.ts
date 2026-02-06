/**
 * Impossible Travel E2E Tests
 * Task 6.8: Geographic Velocity Check
 * 
 * Tests:
 * - Impossible travel detection
 * - VPN/Proxy detection
 * - Healthcare realm blocking
 * - Alert generation
 * - Login history tracking
 */

import {
  checkGeoVelocity,
  recordLoginLocation,
  getLastLoginLocation,
  getUserLoginHistory,
  lookupIpLocation,
  getRealmVelocityConfig,
  calculateHaversineDistance,
  calculateSpeed,
  determineRiskLevel,
  isAnonymizedLocation,
  DEFAULT_VELOCITY_CONFIG,
  HEALTHCARE_VELOCITY_CONFIG,
  GeoLocation,
  VelocityCheckResult
} from '../../services/geo-velocity.service';
import * as crypto from 'crypto';

// Generate unique ID
function generateId(): string {
  return crypto.randomUUID();
}

// Mock DynamoDB
jest.mock('../../services/dynamodb.service', () => {
  const records = new Map<string, any>();
  
  return {
    dynamoDb: {
      send: jest.fn().mockImplementation((command: any) => {
        const commandName = command.constructor.name;
        
        if (commandName === 'PutCommand') {
          const key = `${command.input.Item.pk}#${command.input.Item.sk}`;
          records.set(key, command.input.Item);
          return Promise.resolve({});
        }
        
        if (commandName === 'QueryCommand') {
          const pk = command.input.ExpressionAttributeValues[':pk'];
          const skPrefix = command.input.ExpressionAttributeValues[':skPrefix'];
          
          const items: any[] = [];
          records.forEach((item, key) => {
            if (item.pk === pk && item.sk.startsWith(skPrefix.replace('LOGIN_LOCATION#', 'LOGIN_LOCATION#'))) {
              items.push(item);
            }
          });
          
          // Sort by timestamp descending
          items.sort((a, b) => b.timestamp - a.timestamp);
          
          const limit = command.input.Limit || items.length;
          return Promise.resolve({ Items: items.slice(0, limit) });
        }
        
        return Promise.resolve({});
      })
    },
    TableNames: {
      DOCUMENTS: 'zalt-documents'
    },
    __records: records
  };
});

// Mock security logger
jest.mock('../../services/security-logger.service', () => ({
  logSimpleSecurityEvent: jest.fn().mockResolvedValue(undefined)
}));

describe('Impossible Travel E2E Tests', () => {
  const testRealmId = 'clinisyn-psychologists';
  const testUserId = generateId();
  
  beforeEach(() => {
    jest.clearAllMocks();
    const { __records } = require('../../services/dynamodb.service');
    __records.clear();
  });

  describe('IP Geolocation Lookup', () => {
    it('should lookup Istanbul IP', async () => {
      const location = await lookupIpLocation('85.105.1.1');
      expect(location).not.toBeNull();
      expect(location?.city).toBe('Istanbul');
      expect(location?.countryCode).toBe('TR');
    });

    it('should lookup New York IP', async () => {
      const location = await lookupIpLocation('74.125.1.1');
      expect(location).not.toBeNull();
      expect(location?.city).toBe('New York');
      expect(location?.countryCode).toBe('US');
    });

    it('should detect VPN/Datacenter IP', async () => {
      const location = await lookupIpLocation('10.0.0.1');
      expect(location).not.toBeNull();
      expect(location?.isVpn).toBe(true);
      expect(location?.isDatacenter).toBe(true);
    });

    it('should detect Tor exit node', async () => {
      const location = await lookupIpLocation('185.220.101.1');
      expect(location).not.toBeNull();
      expect(location?.isTor).toBe(true);
    });

    it('should return null for unknown IP', async () => {
      const location = await lookupIpLocation('1.2.3.4');
      expect(location).toBeNull();
    });
  });

  describe('First Login (No Previous Location)', () => {
    it('should allow first login and record location', async () => {
      const userId = generateId();
      const location: GeoLocation = {
        latitude: 41.0082,
        longitude: 28.9784,
        city: 'Istanbul',
        country: 'Turkey',
        countryCode: 'TR'
      };

      const result = await checkGeoVelocity(
        userId,
        testRealmId,
        '85.105.1.1',
        location
      );

      expect(result.isImpossibleTravel).toBe(false);
      expect(result.isSuspicious).toBe(false);
      expect(result.riskLevel).toBe('low');
      expect(result.blocked).toBe(false);
    });

    it('should record first login location', async () => {
      const userId = generateId();
      const location: GeoLocation = {
        latitude: 41.0082,
        longitude: 28.9784,
        city: 'Istanbul',
        country: 'Turkey',
        countryCode: 'TR'
      };

      await checkGeoVelocity(userId, testRealmId, '85.105.1.1', location);

      const lastLogin = await getLastLoginLocation(userId, testRealmId);
      expect(lastLogin).not.toBeNull();
      expect(lastLogin?.location.city).toBe('Istanbul');
    });
  });

  describe('VPN/Proxy Detection', () => {
    it('should flag VPN login as suspicious', async () => {
      const userId = generateId();
      const location: GeoLocation = {
        latitude: 0,
        longitude: 0,
        isVpn: true,
        isDatacenter: true
      };

      const result = await checkGeoVelocity(
        userId,
        testRealmId,
        '10.0.0.1',
        location
      );

      expect(result.isSuspicious).toBe(true);
      expect(result.riskLevel).toBe('medium');
      expect(result.requiresMfa).toBe(true);
      expect(result.reason).toContain('VPN');
    });

    it('should flag Tor login as suspicious', async () => {
      const userId = generateId();
      const location: GeoLocation = {
        latitude: 52.5200,
        longitude: 13.4050,
        city: 'Berlin',
        country: 'Germany',
        isTor: true
      };

      const result = await checkGeoVelocity(
        userId,
        testRealmId,
        '185.220.101.1',
        location
      );

      expect(result.isSuspicious).toBe(true);
      expect(result.requiresMfa).toBe(true);
    });
  });

  describe('Same City Login', () => {
    it('should allow login from same city', async () => {
      const userId = generateId();
      const config = getRealmVelocityConfig(testRealmId);
      
      // First login from Istanbul
      const location1: GeoLocation = {
        latitude: 41.0082,
        longitude: 28.9784,
        city: 'Istanbul',
        country: 'Turkey',
        countryCode: 'TR'
      };
      await checkGeoVelocity(userId, testRealmId, '85.105.1.1', location1);

      // Second login from nearby in Istanbul (within tolerance)
      const location2: GeoLocation = {
        latitude: 41.0100,
        longitude: 28.9800,
        city: 'Istanbul',
        country: 'Turkey',
        countryCode: 'TR'
      };
      
      const result = await checkGeoVelocity(
        userId,
        testRealmId,
        '85.105.1.2',
        location2
      );

      expect(result.isImpossibleTravel).toBe(false);
      expect(result.isSuspicious).toBe(false);
      expect(result.riskLevel).toBe('low');
    });
  });

  describe('Normal Travel', () => {
    it('should allow Istanbul to Ankara in 5 hours', async () => {
      const userId = generateId();
      const { __records } = require('../../services/dynamodb.service');
      
      // Simulate login 5 hours ago from Istanbul
      const fiveHoursAgo = Math.floor(Date.now() / 1000) - (5 * 3600);
      __records.set(`USER#${testRealmId}#${userId}#LOGIN_LOCATION#${fiveHoursAgo}`, {
        pk: `USER#${testRealmId}#${userId}`,
        sk: `LOGIN_LOCATION#${fiveHoursAgo}`,
        event_type: 'login_location',
        user_id: userId,
        realm_id: testRealmId,
        ip_address: '85.105.1.1',
        location: {
          latitude: 41.0082,
          longitude: 28.9784,
          city: 'Istanbul',
          country: 'Turkey',
          countryCode: 'TR'
        },
        timestamp: fiveHoursAgo
      });

      // Login from Ankara now
      const ankaraLocation: GeoLocation = {
        latitude: 39.9334,
        longitude: 32.8597,
        city: 'Ankara',
        country: 'Turkey',
        countryCode: 'TR'
      };

      const result = await checkGeoVelocity(
        userId,
        testRealmId,
        '78.180.1.1',
        ankaraLocation
      );

      expect(result.isImpossibleTravel).toBe(false);
      expect(result.riskLevel).toBe('low');
      expect(result.distanceKm).toBeGreaterThan(300);
      expect(result.distanceKm).toBeLessThan(400);
    });
  });

  describe('Impossible Travel Detection', () => {
    it('should detect Istanbul to New York in 1 hour as impossible', async () => {
      const userId = generateId();
      const { __records } = require('../../services/dynamodb.service');
      
      // Simulate login 1 hour ago from Istanbul
      const oneHourAgo = Math.floor(Date.now() / 1000) - 3600;
      __records.set(`USER#${testRealmId}#${userId}#LOGIN_LOCATION#${oneHourAgo}`, {
        pk: `USER#${testRealmId}#${userId}`,
        sk: `LOGIN_LOCATION#${oneHourAgo}`,
        event_type: 'login_location',
        user_id: userId,
        realm_id: testRealmId,
        ip_address: '85.105.1.1',
        location: {
          latitude: 41.0082,
          longitude: 28.9784,
          city: 'Istanbul',
          country: 'Turkey',
          countryCode: 'TR'
        },
        timestamp: oneHourAgo
      });

      // Login from New York now
      const nyLocation: GeoLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'United States',
        countryCode: 'US'
      };

      const result = await checkGeoVelocity(
        userId,
        testRealmId,
        '74.125.1.1',
        nyLocation
      );

      expect(result.isImpossibleTravel).toBe(true);
      expect(result.riskLevel).toBe('critical');
      expect(result.speedKmh).toBeGreaterThan(7000);
      expect(result.reason).toContain('Impossible travel');
    });

    it('should block impossible travel for healthcare realms', async () => {
      const userId = generateId();
      const { __records } = require('../../services/dynamodb.service');
      
      // Simulate login 1 hour ago from Istanbul
      const oneHourAgo = Math.floor(Date.now() / 1000) - 3600;
      __records.set(`USER#${testRealmId}#${userId}#LOGIN_LOCATION#${oneHourAgo}`, {
        pk: `USER#${testRealmId}#${userId}`,
        sk: `LOGIN_LOCATION#${oneHourAgo}`,
        event_type: 'login_location',
        user_id: userId,
        realm_id: testRealmId,
        ip_address: '85.105.1.1',
        location: {
          latitude: 41.0082,
          longitude: 28.9784,
          city: 'Istanbul',
          country: 'Turkey',
          countryCode: 'TR'
        },
        timestamp: oneHourAgo
      });

      const nyLocation: GeoLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'United States',
        countryCode: 'US'
      };

      const result = await checkGeoVelocity(
        userId,
        testRealmId,
        '74.125.1.1',
        nyLocation,
        HEALTHCARE_VELOCITY_CONFIG
      );

      expect(result.blocked).toBe(true);
      expect(result.requiresVerification).toBe(true);
    });

    it('should log security event for impossible travel', async () => {
      const { logSimpleSecurityEvent } = require('../../services/security-logger.service');
      const userId = generateId();
      const { __records } = require('../../services/dynamodb.service');
      
      const oneHourAgo = Math.floor(Date.now() / 1000) - 3600;
      __records.set(`USER#${testRealmId}#${userId}#LOGIN_LOCATION#${oneHourAgo}`, {
        pk: `USER#${testRealmId}#${userId}`,
        sk: `LOGIN_LOCATION#${oneHourAgo}`,
        event_type: 'login_location',
        user_id: userId,
        realm_id: testRealmId,
        ip_address: '85.105.1.1',
        location: {
          latitude: 41.0082,
          longitude: 28.9784,
          city: 'Istanbul',
          country: 'Turkey',
          countryCode: 'TR'
        },
        timestamp: oneHourAgo
      });

      const nyLocation: GeoLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        city: 'New York',
        country: 'United States',
        countryCode: 'US'
      };

      await checkGeoVelocity(userId, testRealmId, '74.125.1.1', nyLocation);

      expect(logSimpleSecurityEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          event_type: 'impossible_travel_detected',
          user_id: userId,
          realm_id: testRealmId
        })
      );
    });
  });

  describe('Suspicious Travel Detection', () => {
    it('should flag London to Paris in 30 minutes as suspicious', async () => {
      const userId = generateId();
      const realmId = 'other-company'; // Non-healthcare
      const { __records } = require('../../services/dynamodb.service');
      
      // Simulate login 30 minutes ago from London
      const thirtyMinutesAgo = Math.floor(Date.now() / 1000) - 1800;
      __records.set(`USER#${realmId}#${userId}#LOGIN_LOCATION#${thirtyMinutesAgo}`, {
        pk: `USER#${realmId}#${userId}`,
        sk: `LOGIN_LOCATION#${thirtyMinutesAgo}`,
        event_type: 'login_location',
        user_id: userId,
        realm_id: realmId,
        ip_address: '51.140.1.1',
        location: {
          latitude: 51.5074,
          longitude: -0.1278,
          city: 'London',
          country: 'United Kingdom',
          countryCode: 'GB'
        },
        timestamp: thirtyMinutesAgo
      });

      // Login from Paris now
      const parisLocation: GeoLocation = {
        latitude: 48.8566,
        longitude: 2.3522,
        city: 'Paris',
        country: 'France',
        countryCode: 'FR'
      };

      const result = await checkGeoVelocity(
        userId,
        realmId,
        '82.66.1.1',
        parisLocation
      );

      expect(result.isSuspicious).toBe(true);
      expect(result.riskLevel).toBe('high');
      expect(result.requiresMfa).toBe(true);
      expect(result.reason).toContain('Suspicious');
    });
  });

  describe('Login History', () => {
    it('should track login history', async () => {
      const userId = generateId();
      const realmId = 'test-realm';
      const now = Math.floor(Date.now() / 1000);
      
      // Record multiple logins with different timestamps
      await recordLoginLocation({
        userId,
        realmId,
        ipAddress: '85.105.1.1',
        location: {
          latitude: 41.0082,
          longitude: 28.9784,
          city: 'Istanbul',
          country: 'Turkey',
          countryCode: 'TR'
        },
        timestamp: now - 7200
      });

      // Wait a bit to ensure different sk
      await new Promise(resolve => setTimeout(resolve, 10));

      await recordLoginLocation({
        userId,
        realmId,
        ipAddress: '78.180.1.1',
        location: {
          latitude: 39.9334,
          longitude: 32.8597,
          city: 'Ankara',
          country: 'Turkey',
          countryCode: 'TR'
        },
        timestamp: now
      });

      const history = await getUserLoginHistory(userId, realmId);
      expect(history.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Realm Configuration', () => {
    it('should use healthcare config for clinisyn realms', () => {
      const config = getRealmVelocityConfig('clinisyn-psychologists');
      expect(config.blockOnImpossibleTravel).toBe(true);
      expect(config.maxSpeedKmh).toBe(800);
    });

    it('should use default config for other realms', () => {
      const config = getRealmVelocityConfig('other-company');
      expect(config.blockOnImpossibleTravel).toBe(false);
      expect(config.maxSpeedKmh).toBe(1000);
    });
  });

  describe('Edge Cases', () => {
    it('should handle rapid successive logins from same location', async () => {
      const userId = generateId();
      const location: GeoLocation = {
        latitude: 41.0082,
        longitude: 28.9784,
        city: 'Istanbul',
        country: 'Turkey',
        countryCode: 'TR'
      };

      // First login
      await checkGeoVelocity(userId, testRealmId, '85.105.1.1', location);

      // Immediate second login (within minTimeBetweenChecks)
      const result = await checkGeoVelocity(
        userId,
        testRealmId,
        '85.105.1.1',
        location
      );

      expect(result.isImpossibleTravel).toBe(false);
      expect(result.riskLevel).toBe('low');
    });

    it('should handle missing previous location gracefully', async () => {
      const userId = generateId();
      const location: GeoLocation = {
        latitude: 41.0082,
        longitude: 28.9784,
        city: 'Istanbul',
        country: 'Turkey',
        countryCode: 'TR'
      };

      const result = await checkGeoVelocity(
        userId,
        'new-realm',
        '85.105.1.1',
        location
      );

      expect(result.isImpossibleTravel).toBe(false);
      expect(result.previousLocation).toBeUndefined();
    });
  });

  describe('Distance Calculations', () => {
    it('should calculate Istanbul to Ankara distance correctly', () => {
      const distance = calculateHaversineDistance(
        41.0082, 28.9784, // Istanbul
        39.9334, 32.8597  // Ankara
      );
      expect(distance).toBeGreaterThan(300);
      expect(distance).toBeLessThan(400);
    });

    it('should calculate Istanbul to New York distance correctly', () => {
      const distance = calculateHaversineDistance(
        41.0082, 28.9784,  // Istanbul
        40.7128, -74.0060  // New York
      );
      expect(distance).toBeGreaterThan(7500);
      expect(distance).toBeLessThan(8500);
    });
  });

  describe('Speed Calculations', () => {
    it('should calculate speed correctly', () => {
      // 350 km in 5 hours = 70 km/h
      const speed = calculateSpeed(350, 5 * 3600);
      expect(speed).toBeCloseTo(70, 0);
    });

    it('should handle impossible speeds', () => {
      // 8000 km in 1 hour = 8000 km/h
      const speed = calculateSpeed(8000, 3600);
      expect(speed).toBeCloseTo(8000, 0);
      expect(determineRiskLevel(speed, DEFAULT_VELOCITY_CONFIG)).toBe('critical');
    });
  });
});
