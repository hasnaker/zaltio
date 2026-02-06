/**
 * Geographic Velocity Check Service Tests
 * Task 6.8: Impossible Travel Detection
 * 
 * Tests:
 * - Haversine distance calculation
 * - Speed calculation
 * - Risk level determination
 * - VPN/Proxy detection
 * - Velocity check logic
 */

import * as fc from 'fast-check';
import {
  calculateHaversineDistance,
  calculateSpeed,
  determineRiskLevel,
  isAnonymizedLocation,
  isSameCountry,
  isSameCity,
  estimateTravelTime,
  getRealmVelocityConfig,
  DEFAULT_VELOCITY_CONFIG,
  HEALTHCARE_VELOCITY_CONFIG,
  GeoLocation,
  VelocityConfig
} from './geo-velocity.service';

describe('Geographic Velocity Service - Unit Tests', () => {
  describe('calculateHaversineDistance', () => {
    it('should return 0 for same location', () => {
      const distance = calculateHaversineDistance(41.0082, 28.9784, 41.0082, 28.9784);
      expect(distance).toBeCloseTo(0, 1);
    });

    it('should calculate Istanbul to Ankara correctly (~350km)', () => {
      // Istanbul: 41.0082, 28.9784
      // Ankara: 39.9334, 32.8597
      const distance = calculateHaversineDistance(41.0082, 28.9784, 39.9334, 32.8597);
      expect(distance).toBeGreaterThan(300);
      expect(distance).toBeLessThan(400);
    });

    it('should calculate Istanbul to New York correctly (~8000km)', () => {
      // Istanbul: 41.0082, 28.9784
      // New York: 40.7128, -74.0060
      const distance = calculateHaversineDistance(41.0082, 28.9784, 40.7128, -74.0060);
      expect(distance).toBeGreaterThan(7500);
      expect(distance).toBeLessThan(8500);
    });

    it('should calculate London to Sydney correctly (~17000km)', () => {
      // London: 51.5074, -0.1278
      // Sydney: -33.8688, 151.2093
      const distance = calculateHaversineDistance(51.5074, -0.1278, -33.8688, 151.2093);
      expect(distance).toBeGreaterThan(16000);
      expect(distance).toBeLessThan(18000);
    });

    it('should be symmetric (A to B = B to A)', () => {
      const d1 = calculateHaversineDistance(41.0082, 28.9784, 40.7128, -74.0060);
      const d2 = calculateHaversineDistance(40.7128, -74.0060, 41.0082, 28.9784);
      expect(d1).toBeCloseTo(d2, 5);
    });

    it('should handle equator crossing', () => {
      // Quito, Ecuador: -0.1807, -78.4678
      // Bogota, Colombia: 4.7110, -74.0721
      const distance = calculateHaversineDistance(-0.1807, -78.4678, 4.7110, -74.0721);
      expect(distance).toBeGreaterThan(500);
      expect(distance).toBeLessThan(800);
    });

    it('should handle international date line crossing', () => {
      // Tokyo: 35.6762, 139.6503
      // Los Angeles: 34.0522, -118.2437
      const distance = calculateHaversineDistance(35.6762, 139.6503, 34.0522, -118.2437);
      expect(distance).toBeGreaterThan(8500);
      expect(distance).toBeLessThan(9500);
    });
  });

  describe('calculateSpeed', () => {
    it('should calculate speed correctly', () => {
      // 100 km in 1 hour = 100 km/h
      expect(calculateSpeed(100, 3600)).toBeCloseTo(100, 1);
    });

    it('should handle short distances', () => {
      // 10 km in 30 minutes = 20 km/h
      expect(calculateSpeed(10, 1800)).toBeCloseTo(20, 1);
    });

    it('should handle long distances', () => {
      // 8000 km in 10 hours = 800 km/h
      expect(calculateSpeed(8000, 36000)).toBeCloseTo(800, 1);
    });

    it('should return Infinity for zero time', () => {
      expect(calculateSpeed(100, 0)).toBe(Infinity);
    });

    it('should return Infinity for negative time', () => {
      expect(calculateSpeed(100, -1)).toBe(Infinity);
    });

    it('should return 0 for zero distance', () => {
      expect(calculateSpeed(0, 3600)).toBe(0);
    });
  });

  describe('determineRiskLevel', () => {
    const config = DEFAULT_VELOCITY_CONFIG;

    it('should return low for slow speeds', () => {
      expect(determineRiskLevel(100, config)).toBe('low');
      expect(determineRiskLevel(200, config)).toBe('low');
    });

    it('should return medium for moderate speeds', () => {
      expect(determineRiskLevel(300, config)).toBe('medium');
      expect(determineRiskLevel(400, config)).toBe('medium');
    });

    it('should return high for suspicious speeds', () => {
      expect(determineRiskLevel(600, config)).toBe('high');
      expect(determineRiskLevel(800, config)).toBe('high');
    });

    it('should return critical for impossible speeds', () => {
      expect(determineRiskLevel(1100, config)).toBe('critical');
      expect(determineRiskLevel(2000, config)).toBe('critical');
    });

    it('should use healthcare config thresholds', () => {
      const healthcareConfig = HEALTHCARE_VELOCITY_CONFIG;
      // Healthcare has lower thresholds
      expect(determineRiskLevel(400, healthcareConfig)).toBe('high');
      expect(determineRiskLevel(900, healthcareConfig)).toBe('critical');
    });
  });

  describe('isAnonymizedLocation', () => {
    it('should detect VPN', () => {
      const location: GeoLocation = {
        latitude: 0,
        longitude: 0,
        isVpn: true
      };
      expect(isAnonymizedLocation(location)).toBe(true);
    });

    it('should detect Proxy', () => {
      const location: GeoLocation = {
        latitude: 0,
        longitude: 0,
        isProxy: true
      };
      expect(isAnonymizedLocation(location)).toBe(true);
    });

    it('should detect Tor', () => {
      const location: GeoLocation = {
        latitude: 0,
        longitude: 0,
        isTor: true
      };
      expect(isAnonymizedLocation(location)).toBe(true);
    });

    it('should detect Datacenter', () => {
      const location: GeoLocation = {
        latitude: 0,
        longitude: 0,
        isDatacenter: true
      };
      expect(isAnonymizedLocation(location)).toBe(true);
    });

    it('should return false for normal location', () => {
      const location: GeoLocation = {
        latitude: 41.0082,
        longitude: 28.9784,
        city: 'Istanbul',
        country: 'Turkey'
      };
      expect(isAnonymizedLocation(location)).toBe(false);
    });
  });

  describe('isSameCountry', () => {
    it('should return true for same country', () => {
      const loc1: GeoLocation = { latitude: 41.0082, longitude: 28.9784, countryCode: 'TR' };
      const loc2: GeoLocation = { latitude: 39.9334, longitude: 32.8597, countryCode: 'TR' };
      expect(isSameCountry(loc1, loc2)).toBe(true);
    });

    it('should return false for different countries', () => {
      const loc1: GeoLocation = { latitude: 41.0082, longitude: 28.9784, countryCode: 'TR' };
      const loc2: GeoLocation = { latitude: 40.7128, longitude: -74.0060, countryCode: 'US' };
      expect(isSameCountry(loc1, loc2)).toBe(false);
    });
  });

  describe('isSameCity', () => {
    it('should return true for same city', () => {
      const loc1: GeoLocation = { latitude: 41.0082, longitude: 28.9784, city: 'Istanbul', countryCode: 'TR' };
      const loc2: GeoLocation = { latitude: 41.0100, longitude: 28.9800, city: 'Istanbul', countryCode: 'TR' };
      expect(isSameCity(loc1, loc2)).toBe(true);
    });

    it('should return false for different cities', () => {
      const loc1: GeoLocation = { latitude: 41.0082, longitude: 28.9784, city: 'Istanbul', countryCode: 'TR' };
      const loc2: GeoLocation = { latitude: 39.9334, longitude: 32.8597, city: 'Ankara', countryCode: 'TR' };
      expect(isSameCity(loc1, loc2)).toBe(false);
    });

    it('should return false for same city name in different countries', () => {
      const loc1: GeoLocation = { latitude: 0, longitude: 0, city: 'Paris', countryCode: 'FR' };
      const loc2: GeoLocation = { latitude: 0, longitude: 0, city: 'Paris', countryCode: 'US' };
      expect(isSameCity(loc1, loc2)).toBe(false);
    });
  });

  describe('estimateTravelTime', () => {
    it('should return 0.5 hours for local travel', () => {
      expect(estimateTravelTime(50)).toBe(0.5);
    });

    it('should return 1 hour for short flights', () => {
      expect(estimateTravelTime(350)).toBe(1);
    });

    it('should return 3 hours for medium flights', () => {
      expect(estimateTravelTime(1500)).toBe(3);
    });

    it('should return 8 hours for long flights', () => {
      expect(estimateTravelTime(4000)).toBe(8);
    });

    it('should return 15 hours for very long flights', () => {
      expect(estimateTravelTime(10000)).toBe(15);
    });
  });

  describe('getRealmVelocityConfig', () => {
    it('should return healthcare config for clinisyn realms', () => {
      expect(getRealmVelocityConfig('clinisyn-psychologists')).toEqual(HEALTHCARE_VELOCITY_CONFIG);
      expect(getRealmVelocityConfig('clinisyn-students')).toEqual(HEALTHCARE_VELOCITY_CONFIG);
    });

    it('should return default config for other realms', () => {
      expect(getRealmVelocityConfig('other-company')).toEqual(DEFAULT_VELOCITY_CONFIG);
    });
  });

  describe('DEFAULT_VELOCITY_CONFIG', () => {
    it('should have reasonable max speed', () => {
      expect(DEFAULT_VELOCITY_CONFIG.maxSpeedKmh).toBe(1000);
    });

    it('should have suspicious speed below max', () => {
      expect(DEFAULT_VELOCITY_CONFIG.suspiciousSpeedKmh).toBeLessThan(DEFAULT_VELOCITY_CONFIG.maxSpeedKmh);
    });

    it('should not block by default', () => {
      expect(DEFAULT_VELOCITY_CONFIG.blockOnImpossibleTravel).toBe(false);
    });

    it('should require MFA on suspicious', () => {
      expect(DEFAULT_VELOCITY_CONFIG.requireMfaOnSuspicious).toBe(true);
    });
  });

  describe('HEALTHCARE_VELOCITY_CONFIG', () => {
    it('should have stricter max speed', () => {
      expect(HEALTHCARE_VELOCITY_CONFIG.maxSpeedKmh).toBeLessThan(DEFAULT_VELOCITY_CONFIG.maxSpeedKmh);
    });

    it('should block on impossible travel', () => {
      expect(HEALTHCARE_VELOCITY_CONFIG.blockOnImpossibleTravel).toBe(true);
    });

    it('should have smaller same-city tolerance', () => {
      expect(HEALTHCARE_VELOCITY_CONFIG.sameCityToleranceKm).toBeLessThan(DEFAULT_VELOCITY_CONFIG.sameCityToleranceKm);
    });
  });

  describe('Property-based tests', () => {
    describe('Haversine distance', () => {
      it('should always return non-negative distance', () => {
        fc.assert(
          fc.property(
            fc.float({ min: -90, max: 90, noNaN: true }),
            fc.float({ min: -180, max: 180, noNaN: true }),
            fc.float({ min: -90, max: 90, noNaN: true }),
            fc.float({ min: -180, max: 180, noNaN: true }),
            (lat1, lon1, lat2, lon2) => {
              const distance = calculateHaversineDistance(lat1, lon1, lat2, lon2);
              expect(distance).toBeGreaterThanOrEqual(0);
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });

      it('should be symmetric', () => {
        fc.assert(
          fc.property(
            fc.float({ min: -90, max: 90, noNaN: true }),
            fc.float({ min: -180, max: 180, noNaN: true }),
            fc.float({ min: -90, max: 90, noNaN: true }),
            fc.float({ min: -180, max: 180, noNaN: true }),
            (lat1, lon1, lat2, lon2) => {
              const d1 = calculateHaversineDistance(lat1, lon1, lat2, lon2);
              const d2 = calculateHaversineDistance(lat2, lon2, lat1, lon1);
              expect(Math.abs(d1 - d2)).toBeLessThan(0.001);
              return true;
            }
          ),
          { numRuns: 50 }
        );
      });

      it('should not exceed Earth circumference', () => {
        const maxDistance = 40075; // Earth circumference in km
        fc.assert(
          fc.property(
            fc.float({ min: -90, max: 90, noNaN: true }),
            fc.float({ min: -180, max: 180, noNaN: true }),
            fc.float({ min: -90, max: 90, noNaN: true }),
            fc.float({ min: -180, max: 180, noNaN: true }),
            (lat1, lon1, lat2, lon2) => {
              const distance = calculateHaversineDistance(lat1, lon1, lat2, lon2);
              expect(distance).toBeLessThanOrEqual(maxDistance / 2);
              return true;
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('Speed calculation', () => {
      it('should always return non-negative for positive inputs', () => {
        fc.assert(
          fc.property(
            fc.float({ min: 0, max: 20000, noNaN: true }),
            fc.float({ min: 1, max: 100000, noNaN: true }),
            (distance, time) => {
              const speed = calculateSpeed(distance, time);
              expect(speed).toBeGreaterThanOrEqual(0);
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('Risk level determination', () => {
      it('should always return valid risk level', () => {
        const validLevels = ['low', 'medium', 'high', 'critical'];
        fc.assert(
          fc.property(
            fc.float({ min: 0, max: 5000 }),
            (speed) => {
              const level = determineRiskLevel(speed, DEFAULT_VELOCITY_CONFIG);
              expect(validLevels).toContain(level);
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });

      it('should increase risk with speed', () => {
        const riskOrder = ['low', 'medium', 'high', 'critical'];
        fc.assert(
          fc.property(
            fc.float({ min: 0, max: 2000 }),
            fc.float({ min: 0, max: 2000 }),
            (speed1, speed2) => {
              const level1 = determineRiskLevel(speed1, DEFAULT_VELOCITY_CONFIG);
              const level2 = determineRiskLevel(speed2, DEFAULT_VELOCITY_CONFIG);
              
              if (speed1 < speed2) {
                expect(riskOrder.indexOf(level1)).toBeLessThanOrEqual(riskOrder.indexOf(level2));
              }
              return true;
            }
          ),
          { numRuns: 50 }
        );
      });
    });
  });

  describe('Real-world scenarios', () => {
    it('should detect Istanbul to New York in 1 hour as impossible', () => {
      // Distance: ~8000 km
      // Time: 1 hour
      // Speed: ~8000 km/h (impossible)
      const distance = calculateHaversineDistance(41.0082, 28.9784, 40.7128, -74.0060);
      const speed = calculateSpeed(distance, 3600);
      const risk = determineRiskLevel(speed, DEFAULT_VELOCITY_CONFIG);
      
      expect(speed).toBeGreaterThan(7000);
      expect(risk).toBe('critical');
    });

    it('should allow Istanbul to Ankara in 5 hours', () => {
      // Distance: ~350 km
      // Time: 5 hours
      // Speed: ~70 km/h (normal driving)
      const distance = calculateHaversineDistance(41.0082, 28.9784, 39.9334, 32.8597);
      const speed = calculateSpeed(distance, 18000);
      const risk = determineRiskLevel(speed, DEFAULT_VELOCITY_CONFIG);
      
      expect(speed).toBeLessThan(100);
      expect(risk).toBe('low');
    });

    it('should flag London to Paris in 30 minutes as suspicious', () => {
      // Distance: ~340 km
      // Time: 30 minutes
      // Speed: ~680 km/h (possible by plane, but suspicious)
      const distance = calculateHaversineDistance(51.5074, -0.1278, 48.8566, 2.3522);
      const speed = calculateSpeed(distance, 1800);
      const risk = determineRiskLevel(speed, DEFAULT_VELOCITY_CONFIG);
      
      expect(speed).toBeGreaterThan(500);
      expect(risk).toBe('high');
    });

    it('should allow same city movement', () => {
      // Two locations in Istanbul
      const distance = calculateHaversineDistance(41.0082, 28.9784, 41.0500, 29.0100);
      expect(distance).toBeLessThan(DEFAULT_VELOCITY_CONFIG.sameCityToleranceKm);
    });
  });
});
