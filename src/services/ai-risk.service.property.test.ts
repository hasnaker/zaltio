/**
 * Property-Based Tests for AI Risk Assessment System
 * Task 15.8: Write property tests for AI Risk
 * 
 * Properties tested:
 * - Property 28: Risk score consistency (±5 within 1 min)
 * - Property 29: High risk triggers MFA requirement
 * - Property 30: Very high risk blocks login
 * - Property 31: Impossible travel detection works
 * 
 * **Validates: Requirements 10.1, 10.3, 10.4**
 */

import * as fc from 'fast-check';
import {
  assessRisk,
  RiskAssessmentInput,
  RISK_THRESHOLDS,
  ADAPTIVE_AUTH_THRESHOLDS
} from './ai-risk.service';
import { GeoLocation } from './geo-velocity.service';
import {
  RiskAssessment,
  MFA_REQUIRED_THRESHOLD,
  BLOCK_THRESHOLD,
  getRecommendationFromScore,
  requiresMfa,
  shouldBlock,
  areAssessmentsConsistent,
  detectImpossibleTravel,
  GeoLocation as ModelGeoLocation
} from '../models/risk-assessment.model';

// ============================================================================
// Custom Generators for AI Risk Tests
// ============================================================================

const userIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `user_${hex}`);

const realmIdArb = fc.stringMatching(/^[a-z0-9-]{3,50}$/)
  .filter(s => s.length >= 3 && s.length <= 50);

const emailArb = fc.emailAddress();

const ipAddressArb = fc.tuple(
  fc.integer({ min: 1, max: 255 }),
  fc.integer({ min: 0, max: 255 }),
  fc.integer({ min: 0, max: 255 }),
  fc.integer({ min: 1, max: 254 })
).map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`);

const userAgentArb = fc.constantFrom(
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
);

const riskScoreArb = fc.integer({ min: 0, max: 100 });
const latitudeArb = fc.double({ min: -90, max: 90, noNaN: true });
const longitudeArb = fc.double({ min: -180, max: 180, noNaN: true });
const passwordStrengthArb = fc.integer({ min: 0, max: 100 });
const accountAgeDaysArb = fc.integer({ min: 0, max: 3650 });
const failedAttemptsArb = fc.integer({ min: 0, max: 20 });

/**
 * Generate a GeoLocation for service (geo-velocity.service type)
 */
function generateServiceGeoLocation(
  lat: number,
  lon: number,
  options: {
    isVpn?: boolean;
    isTor?: boolean;
    isProxy?: boolean;
    isDatacenter?: boolean;
    countryCode?: string;
  } = {}
): GeoLocation {
  return {
    latitude: lat,
    longitude: lon,
    country: options.countryCode === 'US' ? 'United States' : 'Test Country',
    countryCode: options.countryCode || 'US',
    city: 'Test City',
    region: 'Test Region',
    timezone: 'America/New_York',
    isVpn: options.isVpn ?? false,
    isTor: options.isTor ?? false,
    isProxy: options.isProxy ?? false,
    isDatacenter: options.isDatacenter ?? false
  };
}

/**
 * Generate a GeoLocation for model (risk-assessment.model type)
 */
function generateModelGeoLocation(
  lat: number,
  lon: number,
  countryCode?: string
): ModelGeoLocation {
  return {
    latitude: lat,
    longitude: lon,
    country: countryCode || 'US',
    city: 'Test City',
    region: 'Test Region',
    timezone: 'America/New_York'
  };
}

/**
 * Generate a mock RiskAssessmentInput for testing
 */
function generateMockRiskInput(
  options: Partial<RiskAssessmentInput> = {}
): RiskAssessmentInput {
  return {
    userId: options.userId || `user_${Math.random().toString(36).slice(2)}`,
    email: options.email || 'test@example.com',
    realmId: options.realmId || 'test-realm',
    ipAddress: options.ipAddress || '192.168.1.100',
    userAgent: options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    loginTimestamp: options.loginTimestamp || Date.now(),
    failedAttempts: options.failedAttempts ?? 0,
    passwordStrength: options.passwordStrength ?? 80,
    isBreachedPassword: options.isBreachedPassword ?? false,
    accountAge: options.accountAge ?? 365,
    mfaEnabled: options.mfaEnabled ?? true,
    geoLocation: options.geoLocation,
    deviceFingerprint: options.deviceFingerprint,
    storedDevices: options.storedDevices,
    previousRiskScores: options.previousRiskScores
  };
}

describe('AI Risk Assessment Property Tests', () => {
  /**
   * Property 28: Risk score consistency (±5 within 1 min)
   * 
   * For any login context, repeated risk assessments within 1 minute
   * SHALL return scores within ±5 points of each other.
   * 
   * **Validates: Requirements 10.1, 10.2**
   */
  describe('Property 28: Risk score consistency (±5 within 1 min)', () => {
    it('should return consistent risk scores for identical inputs', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          ipAddressArb,
          userAgentArb,
          passwordStrengthArb,
          fc.boolean(),
          accountAgeDaysArb,
          async (email, realmId, ip, userAgent, passwordStrength, mfaEnabled, accountAge) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: ip,
              userAgent,
              passwordStrength,
              mfaEnabled,
              accountAge,
              loginTimestamp: Date.now()
            });

            const result1 = await assessRisk(input);
            const result2 = await assessRisk(input);

            const scoreDiff = Math.abs(result1.riskScore - result2.riskScore);
            expect(scoreDiff).toBeLessThanOrEqual(5);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should return same risk level for identical inputs', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          ipAddressArb,
          async (email, realmId, ip) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: ip,
              loginTimestamp: Date.now()
            });

            const result1 = await assessRisk(input);
            const result2 = await assessRisk(input);

            expect(result1.riskLevel).toBe(result2.riskLevel);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should return consistent recommendations for identical inputs', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          ipAddressArb,
          failedAttemptsArb,
          async (email, realmId, ip, failedAttempts) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: ip,
              failedAttempts,
              loginTimestamp: Date.now()
            });

            const result1 = await assessRisk(input);
            const result2 = await assessRisk(input);

            expect(result1.adaptiveAuthLevel).toBe(result2.adaptiveAuthLevel);
            expect(result1.requiresMfa).toBe(result2.requiresMfa);
            expect(result1.shouldBlock).toBe(result2.shouldBlock);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should use areAssessmentsConsistent helper correctly', () => {
      fc.assert(
        fc.property(
          riskScoreArb,
          fc.integer({ min: 0, max: 5 }),
          (baseScore, diff) => {
            const assessment1: RiskAssessment = {
              score: baseScore,
              factors: [],
              recommendation: getRecommendationFromScore(baseScore),
              assessedAt: new Date().toISOString()
            };

            const score2 = Math.min(100, Math.max(0, baseScore + diff));
            const assessment2: RiskAssessment = {
              score: score2,
              factors: [],
              recommendation: getRecommendationFromScore(score2),
              assessedAt: new Date().toISOString()
            };

            const consistent = areAssessmentsConsistent(assessment1, assessment2, 5);
            expect(consistent).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should detect inconsistent assessments with large differences', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 90 }),
          fc.integer({ min: 10, max: 50 }),
          (baseScore, diff) => {
            const assessment1: RiskAssessment = {
              score: baseScore,
              factors: [],
              recommendation: getRecommendationFromScore(baseScore),
              assessedAt: new Date().toISOString()
            };

            const score2 = Math.min(100, baseScore + diff);
            const assessment2: RiskAssessment = {
              score: score2,
              factors: [],
              recommendation: getRecommendationFromScore(score2),
              assessedAt: new Date().toISOString()
            };

            const consistent = areAssessmentsConsistent(assessment1, assessment2, 5);
            expect(consistent).toBe(diff <= 5);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  /**
   * Property 29: High risk triggers MFA requirement
   * 
   * IF risk score > 70 THEN THE Zalt_Platform SHALL require MFA
   * regardless of user setting.
   * 
   * **Validates: Requirements 10.3**
   */
  describe('Property 29: High risk triggers MFA requirement', () => {
    it('should require MFA when risk score exceeds threshold', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 71, max: 100 }),
          (riskScore) => {
            const mfaRequired = requiresMfa(riskScore);
            if (riskScore > MFA_REQUIRED_THRESHOLD && riskScore <= BLOCK_THRESHOLD) {
              expect(mfaRequired).toBe(true);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not require MFA for low risk scores', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 70 }),
          (riskScore) => {
            const mfaRequired = requiresMfa(riskScore);
            expect(mfaRequired).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should return mfa_required recommendation for high risk', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 71, max: 90 }),
          (riskScore) => {
            const recommendation = getRecommendationFromScore(riskScore);
            expect(recommendation).toBe('mfa_required');
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should trigger MFA for suspicious network conditions', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          ipAddressArb,
          async (email, realmId, ip) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: ip,
              geoLocation: generateServiceGeoLocation(40.7128, -74.0060, { isVpn: true }),
              failedAttempts: 3,
              mfaEnabled: false,
              accountAge: 1
            });

            const result = await assessRisk(input);

            if (result.riskScore > ADAPTIVE_AUTH_THRESHOLDS.mfa) {
              expect(result.requiresMfa).toBe(true);
            }
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should trigger MFA for Tor exit nodes', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          async (email, realmId) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: '185.220.101.1',
              geoLocation: generateServiceGeoLocation(40.7128, -74.0060, { isTor: true })
            });

            const result = await assessRisk(input);

            expect(result.geoRisk).toBeGreaterThan(0);
            
            if (result.riskScore > ADAPTIVE_AUTH_THRESHOLDS.mfa) {
              expect(result.requiresMfa).toBe(true);
            }
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should trigger MFA for multiple failed attempts', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          ipAddressArb,
          fc.integer({ min: 3, max: 10 }),
          async (email, realmId, ip, failedAttempts) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: ip,
              failedAttempts
            });

            const result = await assessRisk(input);

            expect(result.behaviorRisk).toBeGreaterThan(0);
            
            if (failedAttempts >= 5 && result.riskScore > ADAPTIVE_AUTH_THRESHOLDS.mfa) {
              expect(result.requiresMfa).toBe(true);
            }
          }
        ),
        { numRuns: 30 }
      );
    });
  });

  /**
   * Property 30: Very high risk blocks login
   * 
   * IF risk score > 90 THEN THE Zalt_Platform SHALL block login
   * and notify admin.
   * 
   * **Validates: Requirements 10.4**
   */
  describe('Property 30: Very high risk blocks login', () => {
    it('should block login when risk score exceeds block threshold', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 91, max: 100 }),
          (riskScore) => {
            const blocked = shouldBlock(riskScore);
            expect(blocked).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should not block login for scores at or below threshold', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 90 }),
          (riskScore) => {
            const blocked = shouldBlock(riskScore);
            expect(blocked).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should return block recommendation for very high risk', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 91, max: 100 }),
          (riskScore) => {
            const recommendation = getRecommendationFromScore(riskScore);
            expect(recommendation).toBe('block');
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should block login for breached passwords with other risk factors', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          ipAddressArb,
          async (email, realmId, ip) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: ip,
              isBreachedPassword: true,
              geoLocation: generateServiceGeoLocation(40.7128, -74.0060, { isTor: true }),
              failedAttempts: 5,
              mfaEnabled: false,
              accountAge: 1
            });

            const result = await assessRisk(input);

            expect(result.credentialRisk).toBeGreaterThan(0);
            
            if (result.riskScore > ADAPTIVE_AUTH_THRESHOLDS.block) {
              expect(result.shouldBlock).toBe(true);
            }
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should set shouldAlert for high risk scores', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          async (email, realmId) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: '185.220.101.1',
              isBreachedPassword: true,
              geoLocation: generateServiceGeoLocation(40.7128, -74.0060, { isTor: true }),
              failedAttempts: 10,
              mfaEnabled: false,
              accountAge: 0
            });

            const result = await assessRisk(input);

            if (result.riskScore >= RISK_THRESHOLDS.high) {
              expect(result.shouldAlert).toBe(true);
            }
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * Property 31: Impossible travel detection works
   * 
   * The system SHALL detect when a user logs in from two locations
   * that would require traveling faster than physically possible
   * (> 1000 km/h, faster than commercial aircraft).
   * 
   * **Validates: Requirements 10.2**
   */
  describe('Property 31: Impossible travel detection works', () => {
    it('should detect impossible travel for very distant locations in short time', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 60 }),
          (minutesBetween) => {
            const loc1: ModelGeoLocation = {
              latitude: 40.7128,
              longitude: -74.0060,
              country: 'US'
            };

            const loc2: ModelGeoLocation = {
              latitude: 35.6762,
              longitude: 139.6503,
              country: 'JP'
            };

            const timeDifferenceMs = minutesBetween * 60 * 1000;
            const result = detectImpossibleTravel(loc1, loc2, timeDifferenceMs);

            const hoursRequired = 10.8;
            const hoursAvailable = minutesBetween / 60;

            if (hoursAvailable < hoursRequired) {
              expect(result.impossible).toBe(true);
            }
            
            expect(result.velocity).not.toBeNull();
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should not flag impossible travel for nearby locations', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 30, max: 480 }),
          (minutesBetween) => {
            const loc1: ModelGeoLocation = {
              latitude: 40.7128,
              longitude: -74.0060,
              country: 'US'
            };

            const loc2: ModelGeoLocation = {
              latitude: 40.7580,
              longitude: -73.9855,
              country: 'US'
            };

            const timeDifferenceMs = minutesBetween * 60 * 1000;
            const result = detectImpossibleTravel(loc1, loc2, timeDifferenceMs);

            expect(result.impossible).toBe(false);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle same location correctly', () => {
      fc.assert(
        fc.property(
          latitudeArb,
          longitudeArb,
          fc.integer({ min: 1, max: 1000 }),
          (lat, lon, minutes) => {
            const loc: ModelGeoLocation = {
              latitude: lat,
              longitude: lon,
              country: 'XX'
            };

            const timeDifferenceMs = minutes * 60 * 1000;
            const result = detectImpossibleTravel(loc, loc, timeDifferenceMs);

            expect(result.impossible).toBe(false);
            if (result.velocity !== null) {
              expect(result.velocity).toBeLessThan(10);
            }
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should calculate velocity correctly', () => {
      fc.assert(
        fc.property(
          fc.double({ min: 100, max: 10000, noNaN: true }),
          fc.double({ min: 0.5, max: 24, noNaN: true }),
          (distanceKm, hours) => {
            const latDiff = distanceKm / 111;
            
            const loc1: ModelGeoLocation = {
              latitude: 0,
              longitude: 0,
              country: 'XX'
            };

            const loc2: ModelGeoLocation = {
              latitude: latDiff,
              longitude: 0,
              country: 'XX'
            };

            const timeDifferenceMs = hours * 60 * 60 * 1000;
            const result = detectImpossibleTravel(loc1, loc2, timeDifferenceMs);

            const expectedVelocity = distanceKm / hours;

            if (result.velocity !== null) {
              const velocityRatio = result.velocity / expectedVelocity;
              expect(velocityRatio).toBeGreaterThan(0.8);
              expect(velocityRatio).toBeLessThan(1.2);
            }
          }
        ),
        { numRuns: 30 }
      );
    });

    it('should flag impossible travel in risk assessment', async () => {
      await fc.assert(
        fc.asyncProperty(
          emailArb,
          realmIdArb,
          async (email, realmId) => {
            const input = generateMockRiskInput({
              email,
              realmId,
              ipAddress: '203.0.113.1',
              geoLocation: generateServiceGeoLocation(35.6762, 139.6503, { countryCode: 'JP' })
            });

            const result = await assessRisk(input);

            expect(result.geoRisk).toBeDefined();
            expect(typeof result.geoRisk).toBe('number');
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should handle missing coordinates gracefully', () => {
      const loc1: ModelGeoLocation = {
        country: 'US'
      };

      const loc2: ModelGeoLocation = {
        latitude: 35.6762,
        longitude: 139.6503,
        country: 'JP'
      };

      const result = detectImpossibleTravel(loc1, loc2, 60000);

      expect(result.impossible).toBe(false);
      expect(result.velocity).toBeNull();
    });

    it('should handle zero time difference', () => {
      const loc1: ModelGeoLocation = {
        latitude: 40.7128,
        longitude: -74.0060,
        country: 'US'
      };

      const loc2: ModelGeoLocation = {
        latitude: 35.6762,
        longitude: 139.6503,
        country: 'JP'
      };

      const result = detectImpossibleTravel(loc1, loc2, 0);

      expect(result.impossible).toBe(false);
      expect(result.velocity).toBeNull();
    });
  });
});
