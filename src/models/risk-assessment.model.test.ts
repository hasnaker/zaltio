/**
 * RiskAssessment Model Tests
 * 
 * Tests for AI-powered risk assessment model validation and helper functions.
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 * 
 * Validates: Requirements 10.1, 10.2
 */

import {
  // Types
  RiskFactorType,
  RiskRecommendation,
  RiskFactor,
  RiskAssessment,
  RiskAssessmentContext,
  GeoLocation,
  RiskRequestType,
  
  // Constants
  MIN_RISK_SCORE,
  MAX_RISK_SCORE,
  MFA_REQUIRED_THRESHOLD,
  BLOCK_THRESHOLD,
  RISK_FACTOR_TYPES,
  RISK_RECOMMENDATIONS,
  RISK_REQUEST_TYPES,
  DEFAULT_FACTOR_WEIGHTS,
  
  // Validation functions
  isValidRiskScore,
  isValidRiskFactorType,
  isValidRiskRecommendation,
  isValidRiskRequestType,
  isValidRiskFactor,
  isValidRiskAssessment,
  isValidRiskAssessmentContext,
  isValidIPAddress,
  isValidGeoLocation,
  
  // Helper functions
  getRiskLevel,
  getRiskLevelDescription,
  getRecommendationFromScore,
  requiresMfa,
  shouldBlock,
  calculateWeightedScore,
  createRiskAssessment,
  createRiskFactor,
  toRiskAssessmentResponse,
  getFactorDescription,
  getHighestRiskFactor,
  getHighRiskFactors,
  calculateGeoDistance,
  detectImpossibleTravel,
  maskIPAddress,
  areAssessmentsConsistent,
  mergeRiskFactors,
  sortFactorsByScore,
  createLowRiskAssessment,
  createHighRiskAssessment
} from './risk-assessment.model';


describe('RiskAssessment Model', () => {
  // ============================================================================
  // Constants Tests
  // ============================================================================
  
  describe('Constants', () => {
    it('should have valid score range', () => {
      expect(MIN_RISK_SCORE).toBe(0);
      expect(MAX_RISK_SCORE).toBe(100);
    });
    
    it('should have valid thresholds', () => {
      expect(MFA_REQUIRED_THRESHOLD).toBe(70);
      expect(BLOCK_THRESHOLD).toBe(90);
      expect(MFA_REQUIRED_THRESHOLD).toBeLessThan(BLOCK_THRESHOLD);
    });
    
    it('should have all risk factor types defined', () => {
      expect(RISK_FACTOR_TYPES).toContain('ip_reputation');
      expect(RISK_FACTOR_TYPES).toContain('geo_velocity');
      expect(RISK_FACTOR_TYPES).toContain('device_trust');
      expect(RISK_FACTOR_TYPES).toContain('behavior_anomaly');
      expect(RISK_FACTOR_TYPES).toContain('credential_stuffing');
      expect(RISK_FACTOR_TYPES).toContain('brute_force');
      expect(RISK_FACTOR_TYPES).toContain('tor_exit_node');
      expect(RISK_FACTOR_TYPES).toContain('vpn_proxy');
      expect(RISK_FACTOR_TYPES).toContain('bot_detection');
      expect(RISK_FACTOR_TYPES).toContain('time_anomaly');
      expect(RISK_FACTOR_TYPES.length).toBe(10);
    });
    
    it('should have all recommendations defined', () => {
      expect(RISK_RECOMMENDATIONS).toContain('allow');
      expect(RISK_RECOMMENDATIONS).toContain('mfa_required');
      expect(RISK_RECOMMENDATIONS).toContain('block');
      expect(RISK_RECOMMENDATIONS.length).toBe(3);
    });
    
    it('should have all request types defined', () => {
      expect(RISK_REQUEST_TYPES).toContain('login');
      expect(RISK_REQUEST_TYPES).toContain('registration');
      expect(RISK_REQUEST_TYPES).toContain('password_reset');
      expect(RISK_REQUEST_TYPES).toContain('mfa_setup');
      expect(RISK_REQUEST_TYPES).toContain('api_key_creation');
      expect(RISK_REQUEST_TYPES).toContain('sensitive_operation');
    });
    
    it('should have default weights for all factor types', () => {
      for (const type of RISK_FACTOR_TYPES) {
        expect(DEFAULT_FACTOR_WEIGHTS[type]).toBeDefined();
        expect(DEFAULT_FACTOR_WEIGHTS[type]).toBeGreaterThan(0);
        expect(DEFAULT_FACTOR_WEIGHTS[type]).toBeLessThanOrEqual(1);
      }
    });
  });


  // ============================================================================
  // Validation Function Tests
  // ============================================================================
  
  describe('isValidRiskScore', () => {
    it('should accept valid scores', () => {
      expect(isValidRiskScore(0)).toBe(true);
      expect(isValidRiskScore(50)).toBe(true);
      expect(isValidRiskScore(100)).toBe(true);
      expect(isValidRiskScore(70)).toBe(true);
      expect(isValidRiskScore(90)).toBe(true);
    });
    
    it('should reject scores below minimum', () => {
      expect(isValidRiskScore(-1)).toBe(false);
      expect(isValidRiskScore(-100)).toBe(false);
    });
    
    it('should reject scores above maximum', () => {
      expect(isValidRiskScore(101)).toBe(false);
      expect(isValidRiskScore(200)).toBe(false);
    });
    
    it('should reject non-numeric values', () => {
      expect(isValidRiskScore(NaN)).toBe(false);
      expect(isValidRiskScore('50' as unknown as number)).toBe(false);
      expect(isValidRiskScore(null as unknown as number)).toBe(false);
      expect(isValidRiskScore(undefined as unknown as number)).toBe(false);
    });
  });
  
  describe('isValidRiskFactorType', () => {
    it('should accept valid factor types', () => {
      expect(isValidRiskFactorType('ip_reputation')).toBe(true);
      expect(isValidRiskFactorType('geo_velocity')).toBe(true);
      expect(isValidRiskFactorType('device_trust')).toBe(true);
      expect(isValidRiskFactorType('behavior_anomaly')).toBe(true);
    });
    
    it('should reject invalid factor types', () => {
      expect(isValidRiskFactorType('invalid_type')).toBe(false);
      expect(isValidRiskFactorType('')).toBe(false);
      expect(isValidRiskFactorType('IP_REPUTATION')).toBe(false); // Case sensitive
    });
  });
  
  describe('isValidRiskRecommendation', () => {
    it('should accept valid recommendations', () => {
      expect(isValidRiskRecommendation('allow')).toBe(true);
      expect(isValidRiskRecommendation('mfa_required')).toBe(true);
      expect(isValidRiskRecommendation('block')).toBe(true);
    });
    
    it('should reject invalid recommendations', () => {
      expect(isValidRiskRecommendation('deny')).toBe(false);
      expect(isValidRiskRecommendation('ALLOW')).toBe(false);
      expect(isValidRiskRecommendation('')).toBe(false);
    });
  });
  
  describe('isValidRiskRequestType', () => {
    it('should accept valid request types', () => {
      expect(isValidRiskRequestType('login')).toBe(true);
      expect(isValidRiskRequestType('registration')).toBe(true);
      expect(isValidRiskRequestType('password_reset')).toBe(true);
    });
    
    it('should reject invalid request types', () => {
      expect(isValidRiskRequestType('logout')).toBe(false);
      expect(isValidRiskRequestType('')).toBe(false);
    });
  });


  describe('isValidRiskFactor', () => {
    it('should accept valid risk factors', () => {
      const validFactor: RiskFactor = {
        type: 'ip_reputation',
        score: 75,
        details: 'IP address has poor reputation'
      };
      expect(isValidRiskFactor(validFactor)).toBe(true);
    });
    
    it('should accept risk factors with optional weight', () => {
      const factorWithWeight: RiskFactor = {
        type: 'geo_velocity',
        score: 85,
        details: 'Impossible travel detected',
        weight: 0.25
      };
      expect(isValidRiskFactor(factorWithWeight)).toBe(true);
    });
    
    it('should accept risk factors with metadata', () => {
      const factorWithMetadata: RiskFactor = {
        type: 'device_trust',
        score: 30,
        details: 'New device detected',
        metadata: { deviceId: 'device_123', firstSeen: '2026-01-25' }
      };
      expect(isValidRiskFactor(factorWithMetadata)).toBe(true);
    });
    
    it('should reject factors with invalid type', () => {
      const invalidFactor = {
        type: 'invalid_type',
        score: 50,
        details: 'Some details'
      };
      expect(isValidRiskFactor(invalidFactor)).toBe(false);
    });
    
    it('should reject factors with invalid score', () => {
      const invalidFactor = {
        type: 'ip_reputation',
        score: 150,
        details: 'Some details'
      };
      expect(isValidRiskFactor(invalidFactor)).toBe(false);
    });
    
    it('should reject factors with empty details', () => {
      const invalidFactor = {
        type: 'ip_reputation',
        score: 50,
        details: ''
      };
      expect(isValidRiskFactor(invalidFactor)).toBe(false);
    });
    
    it('should reject factors with invalid weight', () => {
      const invalidFactor = {
        type: 'ip_reputation',
        score: 50,
        details: 'Some details',
        weight: 1.5 // Weight must be 0-1
      };
      expect(isValidRiskFactor(invalidFactor)).toBe(false);
    });
    
    it('should reject non-object values', () => {
      expect(isValidRiskFactor(null)).toBe(false);
      expect(isValidRiskFactor(undefined)).toBe(false);
      expect(isValidRiskFactor('string')).toBe(false);
      expect(isValidRiskFactor(123)).toBe(false);
    });
  });


  describe('isValidRiskAssessment', () => {
    it('should accept valid risk assessments', () => {
      const validAssessment: RiskAssessment = {
        score: 65,
        factors: [
          { type: 'ip_reputation', score: 70, details: 'Suspicious IP' },
          { type: 'device_trust', score: 60, details: 'Unknown device' }
        ],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      expect(isValidRiskAssessment(validAssessment)).toBe(true);
    });
    
    it('should accept assessments with empty factors array', () => {
      const assessment: RiskAssessment = {
        score: 0,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      expect(isValidRiskAssessment(assessment)).toBe(true);
    });
    
    it('should accept assessments with optional fields', () => {
      const assessment: RiskAssessment = {
        score: 85,
        factors: [{ type: 'geo_velocity', score: 90, details: 'Impossible travel' }],
        recommendation: 'mfa_required',
        assessedAt: new Date().toISOString(),
        userId: 'user_123',
        sessionId: 'session_456',
        requestId: 'req_789'
      };
      expect(isValidRiskAssessment(assessment)).toBe(true);
    });
    
    it('should reject assessments with invalid score', () => {
      const invalidAssessment = {
        score: 150,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      expect(isValidRiskAssessment(invalidAssessment)).toBe(false);
    });
    
    it('should reject assessments with invalid recommendation', () => {
      const invalidAssessment = {
        score: 50,
        factors: [],
        recommendation: 'invalid',
        assessedAt: new Date().toISOString()
      };
      expect(isValidRiskAssessment(invalidAssessment)).toBe(false);
    });
    
    it('should reject assessments with invalid factors', () => {
      const invalidAssessment = {
        score: 50,
        factors: [{ type: 'invalid_type', score: 50, details: 'test' }],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      expect(isValidRiskAssessment(invalidAssessment)).toBe(false);
    });
    
    it('should reject assessments with invalid timestamp', () => {
      const invalidAssessment = {
        score: 50,
        factors: [],
        recommendation: 'allow',
        assessedAt: 'invalid-date'
      };
      expect(isValidRiskAssessment(invalidAssessment)).toBe(false);
    });
  });


  describe('isValidRiskAssessmentContext', () => {
    it('should accept valid context', () => {
      const validContext: RiskAssessmentContext = {
        ip: '192.168.1.1',
        requestType: 'login'
      };
      expect(isValidRiskAssessmentContext(validContext)).toBe(true);
    });
    
    it('should accept context with all optional fields', () => {
      const fullContext: RiskAssessmentContext = {
        userId: 'user_123',
        email: 'test@example.com',
        ip: '10.0.0.1',
        userAgent: 'Mozilla/5.0',
        deviceFingerprint: 'fp_abc123',
        geoLocation: { country: 'US', city: 'New York' },
        timestamp: new Date().toISOString(),
        requestType: 'login',
        previousAttempts: 2
      };
      expect(isValidRiskAssessmentContext(fullContext)).toBe(true);
    });
    
    it('should reject context without IP', () => {
      const invalidContext = {
        requestType: 'login'
      };
      expect(isValidRiskAssessmentContext(invalidContext)).toBe(false);
    });
    
    it('should reject context with empty IP', () => {
      const invalidContext = {
        ip: '',
        requestType: 'login'
      };
      expect(isValidRiskAssessmentContext(invalidContext)).toBe(false);
    });
    
    it('should reject context without request type', () => {
      const invalidContext = {
        ip: '192.168.1.1'
      };
      expect(isValidRiskAssessmentContext(invalidContext)).toBe(false);
    });
    
    it('should reject context with invalid request type', () => {
      const invalidContext = {
        ip: '192.168.1.1',
        requestType: 'invalid_type'
      };
      expect(isValidRiskAssessmentContext(invalidContext)).toBe(false);
    });
  });
  
  describe('isValidIPAddress', () => {
    it('should accept valid IPv4 addresses', () => {
      expect(isValidIPAddress('192.168.1.1')).toBe(true);
      expect(isValidIPAddress('10.0.0.1')).toBe(true);
      expect(isValidIPAddress('255.255.255.255')).toBe(true);
      expect(isValidIPAddress('0.0.0.0')).toBe(true);
    });
    
    it('should reject invalid IPv4 addresses', () => {
      expect(isValidIPAddress('256.1.1.1')).toBe(false);
      expect(isValidIPAddress('192.168.1')).toBe(false);
      expect(isValidIPAddress('192.168.1.1.1')).toBe(false);
    });
    
    it('should accept valid IPv6 addresses', () => {
      expect(isValidIPAddress('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
      expect(isValidIPAddress('::')).toBe(true);
    });
    
    it('should reject non-string values', () => {
      expect(isValidIPAddress(null as unknown as string)).toBe(false);
      expect(isValidIPAddress(123 as unknown as string)).toBe(false);
    });
  });
  
  describe('isValidGeoLocation', () => {
    it('should accept valid geo-locations', () => {
      expect(isValidGeoLocation({ country: 'US' })).toBe(true);
      expect(isValidGeoLocation({ country: 'TR', city: 'Istanbul' })).toBe(true);
      expect(isValidGeoLocation({ latitude: 41.0082, longitude: 28.9784 })).toBe(true);
    });
    
    it('should accept empty geo-location', () => {
      expect(isValidGeoLocation({})).toBe(true);
    });
    
    it('should reject invalid country codes', () => {
      expect(isValidGeoLocation({ country: 'USA' })).toBe(false); // Must be 2 chars
      expect(isValidGeoLocation({ country: 'U' })).toBe(false);
    });
    
    it('should reject invalid coordinates', () => {
      expect(isValidGeoLocation({ latitude: 100 })).toBe(false); // Max 90
      expect(isValidGeoLocation({ longitude: 200 })).toBe(false); // Max 180
    });
  });


  // ============================================================================
  // Helper Function Tests
  // ============================================================================
  
  describe('getRiskLevel', () => {
    it('should return low for scores 0-30', () => {
      expect(getRiskLevel(0)).toBe('low');
      expect(getRiskLevel(15)).toBe('low');
      expect(getRiskLevel(30)).toBe('low');
    });
    
    it('should return medium for scores 31-60', () => {
      expect(getRiskLevel(31)).toBe('medium');
      expect(getRiskLevel(45)).toBe('medium');
      expect(getRiskLevel(60)).toBe('medium');
    });
    
    it('should return high for scores 61-85', () => {
      expect(getRiskLevel(61)).toBe('high');
      expect(getRiskLevel(75)).toBe('high');
      expect(getRiskLevel(85)).toBe('high');
    });
    
    it('should return critical for scores 86-100', () => {
      expect(getRiskLevel(86)).toBe('critical');
      expect(getRiskLevel(95)).toBe('critical');
      expect(getRiskLevel(100)).toBe('critical');
    });
  });
  
  describe('getRiskLevelDescription', () => {
    it('should return appropriate descriptions', () => {
      expect(getRiskLevelDescription(20)).toContain('Low risk');
      expect(getRiskLevelDescription(50)).toContain('Medium risk');
      expect(getRiskLevelDescription(75)).toContain('High risk');
      expect(getRiskLevelDescription(95)).toContain('Critical risk');
    });
  });
  
  describe('getRecommendationFromScore', () => {
    it('should return allow for scores 0-70', () => {
      expect(getRecommendationFromScore(0)).toBe('allow');
      expect(getRecommendationFromScore(50)).toBe('allow');
      expect(getRecommendationFromScore(70)).toBe('allow');
    });
    
    it('should return mfa_required for scores 71-90', () => {
      expect(getRecommendationFromScore(71)).toBe('mfa_required');
      expect(getRecommendationFromScore(80)).toBe('mfa_required');
      expect(getRecommendationFromScore(90)).toBe('mfa_required');
    });
    
    it('should return block for scores 91-100', () => {
      expect(getRecommendationFromScore(91)).toBe('block');
      expect(getRecommendationFromScore(95)).toBe('block');
      expect(getRecommendationFromScore(100)).toBe('block');
    });
  });
  
  describe('requiresMfa', () => {
    it('should return false for low scores', () => {
      expect(requiresMfa(50)).toBe(false);
      expect(requiresMfa(70)).toBe(false);
    });
    
    it('should return true for medium-high scores', () => {
      expect(requiresMfa(71)).toBe(true);
      expect(requiresMfa(80)).toBe(true);
      expect(requiresMfa(90)).toBe(true);
    });
    
    it('should return false for very high scores (blocked)', () => {
      expect(requiresMfa(91)).toBe(false);
      expect(requiresMfa(100)).toBe(false);
    });
  });
  
  describe('shouldBlock', () => {
    it('should return false for scores <= 90', () => {
      expect(shouldBlock(50)).toBe(false);
      expect(shouldBlock(70)).toBe(false);
      expect(shouldBlock(90)).toBe(false);
    });
    
    it('should return true for scores > 90', () => {
      expect(shouldBlock(91)).toBe(true);
      expect(shouldBlock(95)).toBe(true);
      expect(shouldBlock(100)).toBe(true);
    });
  });


  describe('calculateWeightedScore', () => {
    it('should return 0 for empty factors', () => {
      expect(calculateWeightedScore([])).toBe(0);
    });
    
    it('should calculate weighted average correctly', () => {
      const factors: RiskFactor[] = [
        { type: 'ip_reputation', score: 80, details: 'Bad IP', weight: 0.5 },
        { type: 'device_trust', score: 40, details: 'Unknown device', weight: 0.5 }
      ];
      // (80 * 0.5 + 40 * 0.5) / (0.5 + 0.5) = 60
      expect(calculateWeightedScore(factors)).toBe(60);
    });
    
    it('should use default weights when not specified', () => {
      const factors: RiskFactor[] = [
        { type: 'ip_reputation', score: 100, details: 'Very bad IP' }
      ];
      const score = calculateWeightedScore(factors);
      expect(score).toBeGreaterThan(0);
      expect(score).toBeLessThanOrEqual(100);
    });
    
    it('should clamp scores to valid range', () => {
      const factors: RiskFactor[] = [
        { type: 'ip_reputation', score: 100, details: 'Bad', weight: 1 },
        { type: 'geo_velocity', score: 100, details: 'Bad', weight: 1 }
      ];
      const score = calculateWeightedScore(factors);
      expect(score).toBeLessThanOrEqual(100);
    });
  });
  
  describe('createRiskFactor', () => {
    it('should create a valid risk factor', () => {
      const factor = createRiskFactor('ip_reputation', 75, 'Suspicious IP address');
      
      expect(factor.type).toBe('ip_reputation');
      expect(factor.score).toBe(75);
      expect(factor.details).toBe('Suspicious IP address');
      expect(isValidRiskFactor(factor)).toBe(true);
    });
    
    it('should clamp score to valid range', () => {
      const factorHigh = createRiskFactor('ip_reputation', 150, 'Test');
      expect(factorHigh.score).toBe(100);
      
      const factorLow = createRiskFactor('ip_reputation', -10, 'Test');
      expect(factorLow.score).toBe(0);
    });
    
    it('should include optional weight and metadata', () => {
      const factor = createRiskFactor('device_trust', 50, 'New device', {
        weight: 0.3,
        metadata: { deviceId: 'dev_123' }
      });
      
      expect(factor.weight).toBe(0.3);
      expect(factor.metadata).toEqual({ deviceId: 'dev_123' });
    });
  });
  
  describe('createRiskAssessment', () => {
    it('should create a valid risk assessment', () => {
      const factors: RiskFactor[] = [
        createRiskFactor('ip_reputation', 60, 'Moderate risk IP'),
        createRiskFactor('device_trust', 40, 'Known device')
      ];
      
      const assessment = createRiskAssessment(factors);
      
      expect(isValidRiskAssessment(assessment)).toBe(true);
      expect(assessment.factors).toHaveLength(2);
      expect(assessment.assessedAt).toBeDefined();
      expect(new Date(assessment.assessedAt).getTime()).not.toBeNaN();
    });
    
    it('should calculate correct recommendation based on score', () => {
      const lowRiskFactors = [createRiskFactor('device_trust', 20, 'Trusted')];
      const lowAssessment = createRiskAssessment(lowRiskFactors);
      expect(lowAssessment.recommendation).toBe('allow');
      
      const highRiskFactors = [createRiskFactor('ip_reputation', 85, 'Bad IP', { weight: 1 })];
      const highAssessment = createRiskAssessment(highRiskFactors);
      expect(highAssessment.recommendation).toBe('mfa_required');
      
      const criticalFactors = [createRiskFactor('behavior_anomaly', 95, 'Attack', { weight: 1 })];
      const criticalAssessment = createRiskAssessment(criticalFactors);
      expect(criticalAssessment.recommendation).toBe('block');
    });
    
    it('should include optional metadata', () => {
      const factors = [createRiskFactor('ip_reputation', 50, 'Test')];
      const assessment = createRiskAssessment(factors, {
        userId: 'user_123',
        sessionId: 'session_456',
        requestId: 'req_789'
      });
      
      expect(assessment.userId).toBe('user_123');
      expect(assessment.sessionId).toBe('session_456');
      expect(assessment.requestId).toBe('req_789');
    });
  });


  describe('toRiskAssessmentResponse', () => {
    it('should convert assessment to API response format', () => {
      const assessment: RiskAssessment = {
        score: 75,
        factors: [
          { type: 'ip_reputation', score: 80, details: 'Bad IP from threat intel' },
          { type: 'device_trust', score: 70, details: 'Unknown device fingerprint' }
        ],
        recommendation: 'mfa_required',
        assessedAt: '2026-01-25T10:00:00Z',
        userId: 'user_123',
        metadata: { ip: '192.168.1.1' }
      };
      
      const response = toRiskAssessmentResponse(assessment);
      
      expect(response.score).toBe(75);
      expect(response.recommendation).toBe('mfa_required');
      expect(response.assessedAt).toBe('2026-01-25T10:00:00Z');
      expect(response.requiresMfa).toBe(true);
      expect(response.blocked).toBe(false);
      expect(response.factors).toHaveLength(2);
      // Should not include sensitive details
      expect(response.factors[0].description).toBe('IP address reputation check');
      expect(response.factors[0]).not.toHaveProperty('details');
    });
    
    it('should set blocked flag correctly', () => {
      const blockedAssessment: RiskAssessment = {
        score: 95,
        factors: [{ type: 'behavior_anomaly', score: 95, details: 'Attack detected' }],
        recommendation: 'block',
        assessedAt: new Date().toISOString()
      };
      
      const response = toRiskAssessmentResponse(blockedAssessment);
      expect(response.blocked).toBe(true);
      expect(response.requiresMfa).toBe(false);
    });
  });
  
  describe('getFactorDescription', () => {
    it('should return descriptions for all factor types', () => {
      for (const type of RISK_FACTOR_TYPES) {
        const description = getFactorDescription(type);
        expect(description).toBeDefined();
        expect(description.length).toBeGreaterThan(0);
        expect(description).not.toBe('Unknown risk factor');
      }
    });
  });
  
  describe('getHighestRiskFactor', () => {
    it('should return the factor with highest score', () => {
      const assessment: RiskAssessment = {
        score: 70,
        factors: [
          { type: 'ip_reputation', score: 60, details: 'Moderate' },
          { type: 'geo_velocity', score: 90, details: 'Impossible travel' },
          { type: 'device_trust', score: 40, details: 'Unknown' }
        ],
        recommendation: 'mfa_required',
        assessedAt: new Date().toISOString()
      };
      
      const highest = getHighestRiskFactor(assessment);
      expect(highest?.type).toBe('geo_velocity');
      expect(highest?.score).toBe(90);
    });
    
    it('should return undefined for empty factors', () => {
      const assessment: RiskAssessment = {
        score: 0,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      
      expect(getHighestRiskFactor(assessment)).toBeUndefined();
    });
  });
  
  describe('getHighRiskFactors', () => {
    it('should return factors above threshold', () => {
      const assessment: RiskAssessment = {
        score: 70,
        factors: [
          { type: 'ip_reputation', score: 80, details: 'Bad' },
          { type: 'geo_velocity', score: 90, details: 'Very bad' },
          { type: 'device_trust', score: 40, details: 'OK' }
        ],
        recommendation: 'mfa_required',
        assessedAt: new Date().toISOString()
      };
      
      const highRisk = getHighRiskFactors(assessment, 70);
      expect(highRisk).toHaveLength(2);
      expect(highRisk.map(f => f.type)).toContain('ip_reputation');
      expect(highRisk.map(f => f.type)).toContain('geo_velocity');
    });
    
    it('should use default threshold of 70', () => {
      const assessment: RiskAssessment = {
        score: 60,
        factors: [
          { type: 'ip_reputation', score: 75, details: 'Above default' },
          { type: 'device_trust', score: 65, details: 'Below default' }
        ],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      
      const highRisk = getHighRiskFactors(assessment);
      expect(highRisk).toHaveLength(1);
      expect(highRisk[0].type).toBe('ip_reputation');
    });
  });


  describe('calculateGeoDistance', () => {
    it('should calculate distance between two locations', () => {
      // Istanbul to London (approximately 2500 km)
      const istanbul: GeoLocation = { latitude: 41.0082, longitude: 28.9784 };
      const london: GeoLocation = { latitude: 51.5074, longitude: -0.1278 };
      
      const distance = calculateGeoDistance(istanbul, london);
      expect(distance).not.toBeNull();
      expect(distance).toBeGreaterThan(2400);
      expect(distance).toBeLessThan(2600);
    });
    
    it('should return 0 for same location', () => {
      const location: GeoLocation = { latitude: 40.7128, longitude: -74.0060 };
      const distance = calculateGeoDistance(location, location);
      expect(distance).toBe(0);
    });
    
    it('should return null if coordinates are missing', () => {
      const incomplete: GeoLocation = { country: 'US' };
      const complete: GeoLocation = { latitude: 40.7128, longitude: -74.0060 };
      
      expect(calculateGeoDistance(incomplete, complete)).toBeNull();
      expect(calculateGeoDistance(complete, incomplete)).toBeNull();
    });
  });
  
  describe('detectImpossibleTravel', () => {
    it('should detect impossible travel', () => {
      // Istanbul to New York in 1 hour (impossible - ~8000 km)
      const istanbul: GeoLocation = { latitude: 41.0082, longitude: 28.9784 };
      const newYork: GeoLocation = { latitude: 40.7128, longitude: -74.0060 };
      const oneHourMs = 60 * 60 * 1000;
      
      const result = detectImpossibleTravel(istanbul, newYork, oneHourMs);
      expect(result.impossible).toBe(true);
      expect(result.velocity).toBeGreaterThan(1000);
    });
    
    it('should allow possible travel', () => {
      // Istanbul to Ankara in 4 hours (possible - ~350 km)
      const istanbul: GeoLocation = { latitude: 41.0082, longitude: 28.9784 };
      const ankara: GeoLocation = { latitude: 39.9334, longitude: 32.8597 };
      const fourHoursMs = 4 * 60 * 60 * 1000;
      
      const result = detectImpossibleTravel(istanbul, ankara, fourHoursMs);
      expect(result.impossible).toBe(false);
      expect(result.velocity).toBeLessThan(1000);
    });
    
    it('should handle missing coordinates', () => {
      const incomplete: GeoLocation = { country: 'US' };
      const complete: GeoLocation = { latitude: 40.7128, longitude: -74.0060 };
      
      const result = detectImpossibleTravel(incomplete, complete, 3600000);
      expect(result.impossible).toBe(false);
      expect(result.velocity).toBeNull();
    });
    
    it('should handle zero time difference', () => {
      const loc1: GeoLocation = { latitude: 41.0082, longitude: 28.9784 };
      const loc2: GeoLocation = { latitude: 40.7128, longitude: -74.0060 };
      
      const result = detectImpossibleTravel(loc1, loc2, 0);
      expect(result.impossible).toBe(false);
      expect(result.velocity).toBeNull();
    });
  });
  
  describe('maskIPAddress', () => {
    it('should mask IPv4 addresses', () => {
      expect(maskIPAddress('192.168.1.100')).toBe('192.168.*.*');
      expect(maskIPAddress('10.0.0.1')).toBe('10.0.*.*');
    });
    
    it('should mask IPv6 addresses', () => {
      const masked = maskIPAddress('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      expect(masked).toContain('2001');
      expect(masked).toContain('****');
    });
    
    it('should handle empty or invalid input', () => {
      expect(maskIPAddress('')).toBe('unknown');
      expect(maskIPAddress(null as unknown as string)).toBe('unknown');
    });
  });


  describe('areAssessmentsConsistent', () => {
    it('should return true for assessments within tolerance', () => {
      const assessment1: RiskAssessment = {
        score: 50,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      const assessment2: RiskAssessment = {
        score: 53,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      
      expect(areAssessmentsConsistent(assessment1, assessment2)).toBe(true);
      expect(areAssessmentsConsistent(assessment1, assessment2, 5)).toBe(true);
    });
    
    it('should return false for assessments outside tolerance', () => {
      const assessment1: RiskAssessment = {
        score: 50,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      const assessment2: RiskAssessment = {
        score: 60,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      
      expect(areAssessmentsConsistent(assessment1, assessment2, 5)).toBe(false);
    });
    
    it('should use default tolerance of 5', () => {
      const assessment1: RiskAssessment = {
        score: 50,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      const assessment2: RiskAssessment = {
        score: 55,
        factors: [],
        recommendation: 'allow',
        assessedAt: new Date().toISOString()
      };
      
      expect(areAssessmentsConsistent(assessment1, assessment2)).toBe(true);
    });
  });
  
  describe('mergeRiskFactors', () => {
    it('should keep highest score for duplicate types', () => {
      const factors: RiskFactor[] = [
        { type: 'ip_reputation', score: 60, details: 'First check' },
        { type: 'ip_reputation', score: 80, details: 'Second check' },
        { type: 'device_trust', score: 50, details: 'Device check' }
      ];
      
      const merged = mergeRiskFactors(factors);
      expect(merged).toHaveLength(2);
      
      const ipFactor = merged.find(f => f.type === 'ip_reputation');
      expect(ipFactor?.score).toBe(80);
    });
    
    it('should preserve all unique types', () => {
      const factors: RiskFactor[] = [
        { type: 'ip_reputation', score: 60, details: 'IP' },
        { type: 'device_trust', score: 50, details: 'Device' },
        { type: 'geo_velocity', score: 70, details: 'Geo' }
      ];
      
      const merged = mergeRiskFactors(factors);
      expect(merged).toHaveLength(3);
    });
  });
  
  describe('sortFactorsByScore', () => {
    it('should sort factors by score descending', () => {
      const factors: RiskFactor[] = [
        { type: 'ip_reputation', score: 50, details: 'Medium' },
        { type: 'geo_velocity', score: 90, details: 'High' },
        { type: 'device_trust', score: 30, details: 'Low' }
      ];
      
      const sorted = sortFactorsByScore(factors);
      expect(sorted[0].score).toBe(90);
      expect(sorted[1].score).toBe(50);
      expect(sorted[2].score).toBe(30);
    });
    
    it('should not modify original array', () => {
      const factors: RiskFactor[] = [
        { type: 'ip_reputation', score: 50, details: 'First' },
        { type: 'geo_velocity', score: 90, details: 'Second' }
      ];
      
      const sorted = sortFactorsByScore(factors);
      expect(factors[0].score).toBe(50); // Original unchanged
      expect(sorted[0].score).toBe(90);
    });
  });
  
  describe('createLowRiskAssessment', () => {
    it('should create a low-risk assessment', () => {
      const assessment = createLowRiskAssessment();
      
      expect(assessment.score).toBeLessThanOrEqual(30);
      expect(assessment.recommendation).toBe('allow');
      expect(assessment.factors).toHaveLength(1);
      expect(assessment.factors[0].type).toBe('device_trust');
    });
    
    it('should include optional metadata', () => {
      const assessment = createLowRiskAssessment({
        userId: 'user_123',
        sessionId: 'session_456'
      });
      
      expect(assessment.userId).toBe('user_123');
      expect(assessment.sessionId).toBe('session_456');
    });
  });
  
  describe('createHighRiskAssessment', () => {
    it('should create a high-risk assessment from factors', () => {
      const factors = [
        createRiskFactor('ip_reputation', 85, 'Bad IP'),
        createRiskFactor('geo_velocity', 90, 'Impossible travel')
      ];
      
      const assessment = createHighRiskAssessment(factors);
      
      expect(assessment.factors).toHaveLength(2);
      expect(assessment.score).toBeGreaterThan(70);
    });
    
    it('should create default high-risk factor if none provided', () => {
      const assessment = createHighRiskAssessment([]);
      
      expect(assessment.factors).toHaveLength(1);
      expect(assessment.factors[0].type).toBe('behavior_anomaly');
      expect(assessment.factors[0].score).toBe(85);
    });
  });
});
