/**
 * CloudWatch Monitoring Service Tests
 * Task 7.3: CloudWatch Integration
 * 
 * Tests:
 * - Metric creation
 * - Latency tracking
 * - Buffering and batching
 * - Helper functions
 */

import * as fc from 'fast-check';
import {
  MetricName,
  METRIC_NAMESPACE,
  DEFAULT_MONITORING_CONFIG,
  MonitoringConfig,
  MetricDataPoint,
  LatencyStats,
  createMetricDatum,
  createLatencyMetricDatum,
  bufferMetric,
  getBufferSize,
  clearBuffer,
  calculateLatencyStats,
  LatencyTimer,
  realmDimension,
  endpointDimension,
  errorTypeDimension,
  calculateSuccessRate,
  calculateErrorRate,
  MonitoringHelpers,
  DASHBOARD_METRICS,
  ALARM_THRESHOLDS
} from './monitoring.service';
import { StandardUnit } from '@aws-sdk/client-cloudwatch';

// Mock CloudWatch client
jest.mock('@aws-sdk/client-cloudwatch', () => ({
  CloudWatchClient: jest.fn().mockImplementation(() => ({
    send: jest.fn().mockResolvedValue({})
  })),
  PutMetricDataCommand: jest.fn(),
  StandardUnit: {
    Count: 'Count',
    Milliseconds: 'Milliseconds',
    Percent: 'Percent',
    Bytes: 'Bytes',
    None: 'None'
  }
}));

describe('CloudWatch Monitoring Service - Unit Tests', () => {
  beforeEach(() => {
    clearBuffer();
  });

  describe('METRIC_NAMESPACE', () => {
    it('should be Zalt/Auth', () => {
      expect(METRIC_NAMESPACE).toBe('Zalt/Auth');
    });
  });

  describe('MetricName enum', () => {
    it('should have authentication metrics', () => {
      expect(MetricName.LOGIN_SUCCESS).toBe('LoginSuccess');
      expect(MetricName.LOGIN_FAILURE).toBe('LoginFailure');
      expect(MetricName.LOGIN_LATENCY).toBe('LoginLatency');
      expect(MetricName.LOGOUT).toBe('Logout');
      expect(MetricName.REGISTER).toBe('Register');
    });

    it('should have token metrics', () => {
      expect(MetricName.TOKEN_REFRESH).toBe('TokenRefresh');
      expect(MetricName.TOKEN_REFRESH_LATENCY).toBe('TokenRefreshLatency');
      expect(MetricName.TOKEN_VALIDATION).toBe('TokenValidation');
    });

    it('should have MFA metrics', () => {
      expect(MetricName.MFA_SETUP).toBe('MFASetup');
      expect(MetricName.MFA_VERIFY_SUCCESS).toBe('MFAVerifySuccess');
      expect(MetricName.MFA_VERIFY_FAILURE).toBe('MFAVerifyFailure');
      expect(MetricName.WEBAUTHN_REGISTER).toBe('WebAuthnRegister');
    });

    it('should have security metrics', () => {
      expect(MetricName.RATE_LIMIT_HIT).toBe('RateLimitHit');
      expect(MetricName.ACCOUNT_LOCKOUT).toBe('AccountLockout');
      expect(MetricName.CREDENTIAL_STUFFING).toBe('CredentialStuffing');
      expect(MetricName.IMPOSSIBLE_TRAVEL).toBe('ImpossibleTravel');
    });

    it('should have error metrics', () => {
      expect(MetricName.ERROR_COUNT).toBe('ErrorCount');
      expect(MetricName.ERROR_4XX).toBe('Error4xx');
      expect(MetricName.ERROR_5XX).toBe('Error5xx');
    });

    it('should have session metrics', () => {
      expect(MetricName.SESSION_CREATED).toBe('SessionCreated');
      expect(MetricName.SESSION_EXPIRED).toBe('SessionExpired');
      expect(MetricName.SESSION_TIMEOUT).toBe('SessionTimeout');
    });

    it('should have device metrics', () => {
      expect(MetricName.NEW_DEVICE).toBe('NewDevice');
      expect(MetricName.TRUSTED_DEVICE).toBe('TrustedDevice');
      expect(MetricName.DEVICE_REVOKED).toBe('DeviceRevoked');
    });
  });

  describe('DEFAULT_MONITORING_CONFIG', () => {
    it('should be enabled', () => {
      expect(DEFAULT_MONITORING_CONFIG.enabled).toBe(true);
    });

    it('should have correct namespace', () => {
      expect(DEFAULT_MONITORING_CONFIG.namespace).toBe(METRIC_NAMESPACE);
    });

    it('should have default dimensions', () => {
      expect(DEFAULT_MONITORING_CONFIG.defaultDimensions).toBeDefined();
      expect(DEFAULT_MONITORING_CONFIG.defaultDimensions.length).toBeGreaterThan(0);
    });

    it('should have batch size of 20', () => {
      expect(DEFAULT_MONITORING_CONFIG.batchSize).toBe(20);
    });

    it('should have 1 minute flush interval', () => {
      expect(DEFAULT_MONITORING_CONFIG.flushIntervalMs).toBe(60000);
    });
  });

  describe('createMetricDatum', () => {
    it('should create metric datum with required fields', () => {
      const dataPoint: MetricDataPoint = {
        name: MetricName.LOGIN_SUCCESS,
        value: 1
      };

      const datum = createMetricDatum(dataPoint);

      expect(datum.MetricName).toBe(MetricName.LOGIN_SUCCESS);
      expect(datum.Value).toBe(1);
      expect(datum.Unit).toBe(StandardUnit.Count);
      expect(datum.Timestamp).toBeDefined();
    });

    it('should include default dimensions', () => {
      const dataPoint: MetricDataPoint = {
        name: MetricName.LOGIN_SUCCESS,
        value: 1
      };

      const datum = createMetricDatum(dataPoint);

      expect(datum.Dimensions).toBeDefined();
      expect(datum.Dimensions?.length).toBeGreaterThan(0);
    });

    it('should merge custom dimensions', () => {
      const dataPoint: MetricDataPoint = {
        name: MetricName.LOGIN_SUCCESS,
        value: 1,
        dimensions: [{ Name: 'RealmId', Value: 'test-realm' }]
      };

      const datum = createMetricDatum(dataPoint);

      expect(datum.Dimensions?.find(d => d.Name === 'RealmId')).toBeDefined();
    });

    it('should use custom unit if provided', () => {
      const dataPoint: MetricDataPoint = {
        name: MetricName.LOGIN_LATENCY,
        value: 100,
        unit: StandardUnit.Milliseconds
      };

      const datum = createMetricDatum(dataPoint);

      expect(datum.Unit).toBe(StandardUnit.Milliseconds);
    });

    it('should use custom timestamp if provided', () => {
      const timestamp = new Date('2026-01-15T10:00:00Z');
      const dataPoint: MetricDataPoint = {
        name: MetricName.LOGIN_SUCCESS,
        value: 1,
        timestamp
      };

      const datum = createMetricDatum(dataPoint);

      expect(datum.Timestamp).toEqual(timestamp);
    });
  });

  describe('createLatencyMetricDatum', () => {
    it('should create latency metric with statistics', () => {
      const stats: LatencyStats = {
        min: 10,
        max: 500,
        sum: 1000,
        count: 10
      };

      const datum = createLatencyMetricDatum(MetricName.LOGIN_LATENCY, stats);

      expect(datum.MetricName).toBe(MetricName.LOGIN_LATENCY);
      expect(datum.StatisticValues?.Minimum).toBe(10);
      expect(datum.StatisticValues?.Maximum).toBe(500);
      expect(datum.StatisticValues?.Sum).toBe(1000);
      expect(datum.StatisticValues?.SampleCount).toBe(10);
      expect(datum.Unit).toBe(StandardUnit.Milliseconds);
    });

    it('should include dimensions', () => {
      const stats: LatencyStats = { min: 10, max: 100, sum: 500, count: 5 };
      const dimensions = [{ Name: 'RealmId', Value: 'test-realm' }];

      const datum = createLatencyMetricDatum(MetricName.LOGIN_LATENCY, stats, dimensions);

      expect(datum.Dimensions?.find(d => d.Name === 'RealmId')).toBeDefined();
    });
  });

  describe('bufferMetric', () => {
    it('should add metric to buffer', () => {
      bufferMetric({
        name: MetricName.LOGIN_SUCCESS,
        value: 1
      });

      expect(getBufferSize()).toBe(1);
    });

    it('should not buffer when disabled', () => {
      const config: MonitoringConfig = {
        ...DEFAULT_MONITORING_CONFIG,
        enabled: false
      };

      bufferMetric({
        name: MetricName.LOGIN_SUCCESS,
        value: 1
      }, config);

      expect(getBufferSize()).toBe(0);
    });

    it('should accumulate multiple metrics', () => {
      bufferMetric({ name: MetricName.LOGIN_SUCCESS, value: 1 });
      bufferMetric({ name: MetricName.LOGIN_FAILURE, value: 1 });
      bufferMetric({ name: MetricName.LOGOUT, value: 1 });

      expect(getBufferSize()).toBe(3);
    });
  });

  describe('clearBuffer', () => {
    it('should clear all buffered metrics', () => {
      bufferMetric({ name: MetricName.LOGIN_SUCCESS, value: 1 });
      bufferMetric({ name: MetricName.LOGIN_FAILURE, value: 1 });

      clearBuffer();

      expect(getBufferSize()).toBe(0);
    });
  });

  describe('calculateLatencyStats', () => {
    it('should calculate stats for samples', () => {
      const samples = [10, 20, 30, 40, 50];
      const stats = calculateLatencyStats(samples);

      expect(stats.min).toBe(10);
      expect(stats.max).toBe(50);
      expect(stats.sum).toBe(150);
      expect(stats.count).toBe(5);
    });

    it('should calculate percentiles', () => {
      const samples = Array.from({ length: 100 }, (_, i) => i + 1);
      const stats = calculateLatencyStats(samples);

      // p50 is at index 50 (value 51), p95 at index 95 (value 96), p99 at index 99 (value 100)
      expect(stats.p50).toBe(51);
      expect(stats.p95).toBe(96);
      expect(stats.p99).toBe(100);
    });

    it('should handle empty array', () => {
      const stats = calculateLatencyStats([]);

      expect(stats.min).toBe(0);
      expect(stats.max).toBe(0);
      expect(stats.sum).toBe(0);
      expect(stats.count).toBe(0);
    });

    it('should handle single sample', () => {
      const stats = calculateLatencyStats([100]);

      expect(stats.min).toBe(100);
      expect(stats.max).toBe(100);
      expect(stats.sum).toBe(100);
      expect(stats.count).toBe(1);
    });
  });

  describe('LatencyTimer', () => {
    it('should measure elapsed time', async () => {
      const timer = new LatencyTimer();
      
      // Wait a bit - use 15ms to account for timing variations
      await new Promise(resolve => setTimeout(resolve, 15));
      
      const duration = timer.stop();
      
      // Allow 5ms tolerance for system scheduling variations
      expect(duration).toBeGreaterThanOrEqual(10);
    });

    it('should return same duration after stop', async () => {
      const timer = new LatencyTimer();
      await new Promise(resolve => setTimeout(resolve, 5));
      
      const duration1 = timer.stop();
      await new Promise(resolve => setTimeout(resolve, 10));
      const duration2 = timer.getDuration();
      
      expect(duration1).toBe(duration2);
    });

    it('should return current duration before stop', () => {
      const timer = new LatencyTimer();
      const duration = timer.getDuration();
      
      expect(duration).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Dimension helpers', () => {
    it('should create realm dimension', () => {
      const dim = realmDimension('clinisyn-psychologists');
      
      expect(dim.Name).toBe('RealmId');
      expect(dim.Value).toBe('clinisyn-psychologists');
    });

    it('should create endpoint dimension', () => {
      const dim = endpointDimension('/v1/auth/login');
      
      expect(dim.Name).toBe('Endpoint');
      expect(dim.Value).toBe('/v1/auth/login');
    });

    it('should create error type dimension', () => {
      const dim = errorTypeDimension('INVALID_CREDENTIALS');
      
      expect(dim.Name).toBe('ErrorType');
      expect(dim.Value).toBe('INVALID_CREDENTIALS');
    });
  });

  describe('calculateSuccessRate', () => {
    it('should calculate 100% for all success', () => {
      expect(calculateSuccessRate(100, 0)).toBe(100);
    });

    it('should calculate 0% for all failure', () => {
      expect(calculateSuccessRate(0, 100)).toBe(0);
    });

    it('should calculate 50% for equal success/failure', () => {
      expect(calculateSuccessRate(50, 50)).toBe(50);
    });

    it('should return 100% for zero total', () => {
      expect(calculateSuccessRate(0, 0)).toBe(100);
    });

    it('should calculate correct percentage', () => {
      expect(calculateSuccessRate(75, 25)).toBe(75);
    });
  });

  describe('calculateErrorRate', () => {
    it('should calculate 0% for no errors', () => {
      expect(calculateErrorRate(0, 100)).toBe(0);
    });

    it('should calculate 100% for all errors', () => {
      expect(calculateErrorRate(100, 100)).toBe(100);
    });

    it('should calculate 5% error rate', () => {
      expect(calculateErrorRate(5, 100)).toBe(5);
    });

    it('should return 0% for zero total', () => {
      expect(calculateErrorRate(0, 0)).toBe(0);
    });
  });

  describe('MonitoringHelpers', () => {
    beforeEach(() => {
      clearBuffer();
    });

    describe('Authentication helpers', () => {
      it('should buffer login success', () => {
        MonitoringHelpers.loginSuccess('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer login success with latency', () => {
        MonitoringHelpers.loginSuccess('test-realm', 100);
        expect(getBufferSize()).toBe(2);  // count + latency
      });

      it('should buffer login failure', () => {
        MonitoringHelpers.loginFailure('test-realm', 'INVALID_CREDENTIALS');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer logout', () => {
        MonitoringHelpers.logout('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer register', () => {
        MonitoringHelpers.register('test-realm');
        expect(getBufferSize()).toBe(1);
      });
    });

    describe('Token helpers', () => {
      it('should buffer token refresh', () => {
        MonitoringHelpers.tokenRefresh('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer token refresh with latency', () => {
        MonitoringHelpers.tokenRefresh('test-realm', 50);
        expect(getBufferSize()).toBe(2);
      });

      it('should buffer token validation', () => {
        MonitoringHelpers.tokenValidation('test-realm', 10);
        expect(getBufferSize()).toBe(2);
      });
    });

    describe('MFA helpers', () => {
      it('should buffer MFA setup', () => {
        MonitoringHelpers.mfaSetup('test-realm', 'totp');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer MFA verify success', () => {
        MonitoringHelpers.mfaVerifySuccess('test-realm', 200);
        expect(getBufferSize()).toBe(2);
      });

      it('should buffer MFA verify failure', () => {
        MonitoringHelpers.mfaVerifyFailure('test-realm');
        expect(getBufferSize()).toBe(1);
      });
    });

    describe('Security helpers', () => {
      it('should buffer rate limit hit', () => {
        MonitoringHelpers.rateLimitHit('test-realm', '/v1/auth/login');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer account lockout', () => {
        MonitoringHelpers.accountLockout('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer credential stuffing', () => {
        MonitoringHelpers.credentialStuffing('test-realm', 100);
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer impossible travel', () => {
        MonitoringHelpers.impossibleTravel('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer suspicious activity', () => {
        MonitoringHelpers.suspiciousActivity('test-realm', 'unusual_pattern');
        expect(getBufferSize()).toBe(1);
      });
    });

    describe('Error helpers', () => {
      it('should buffer 4xx error', () => {
        MonitoringHelpers.error('test-realm', 400, 'BAD_REQUEST');
        expect(getBufferSize()).toBe(2);  // ERROR_COUNT + ERROR_4XX
      });

      it('should buffer 5xx error', () => {
        MonitoringHelpers.error('test-realm', 500, 'INTERNAL_ERROR');
        expect(getBufferSize()).toBe(2);  // ERROR_COUNT + ERROR_5XX
      });

      it('should buffer generic error', () => {
        MonitoringHelpers.error('test-realm', 200);  // Not an error status
        expect(getBufferSize()).toBe(1);  // Only ERROR_COUNT
      });
    });

    describe('Session helpers', () => {
      it('should buffer session created', () => {
        MonitoringHelpers.sessionCreated('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer session expired', () => {
        MonitoringHelpers.sessionExpired('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer session timeout', () => {
        MonitoringHelpers.sessionTimeout('test-realm', 'idle');
        expect(getBufferSize()).toBe(1);
      });
    });

    describe('Device helpers', () => {
      it('should buffer new device', () => {
        MonitoringHelpers.newDevice('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer trusted device', () => {
        MonitoringHelpers.trustedDevice('test-realm');
        expect(getBufferSize()).toBe(1);
      });

      it('should buffer device revoked', () => {
        MonitoringHelpers.deviceRevoked('test-realm');
        expect(getBufferSize()).toBe(1);
      });
    });
  });

  describe('DASHBOARD_METRICS', () => {
    it('should have login success rate metric', () => {
      expect(DASHBOARD_METRICS.loginSuccessRate).toBeDefined();
      expect(DASHBOARD_METRICS.loginSuccessRate.namespace).toBe(METRIC_NAMESPACE);
    });

    it('should have login latency p95 metric', () => {
      expect(DASHBOARD_METRICS.loginLatencyP95).toBeDefined();
      expect(DASHBOARD_METRICS.loginLatencyP95.statistic).toBe('p95');
    });

    it('should have MFA success rate metric', () => {
      expect(DASHBOARD_METRICS.mfaSuccessRate).toBeDefined();
    });

    it('should have token refresh latency metric', () => {
      expect(DASHBOARD_METRICS.tokenRefreshLatency).toBeDefined();
    });

    it('should have error rate metric', () => {
      expect(DASHBOARD_METRICS.errorRate).toBeDefined();
    });

    it('should have security events metric', () => {
      expect(DASHBOARD_METRICS.securityEvents).toBeDefined();
    });
  });

  describe('ALARM_THRESHOLDS', () => {
    it('should have login latency threshold', () => {
      expect(ALARM_THRESHOLDS.loginLatencyP95).toBe(500);
    });

    it('should have error rate threshold', () => {
      expect(ALARM_THRESHOLDS.errorRate).toBe(5);
    });

    it('should have login failure spike threshold', () => {
      expect(ALARM_THRESHOLDS.loginFailureSpike).toBe(50);
    });

    it('should have account lockout spike threshold', () => {
      expect(ALARM_THRESHOLDS.accountLockoutSpike).toBe(10);
    });

    it('should have credential stuffing threshold', () => {
      expect(ALARM_THRESHOLDS.credentialStuffingThreshold).toBe(100);
    });
  });

  describe('Property-based tests', () => {
    it('should always create valid metric datum', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...Object.values(MetricName)),
          fc.integer({ min: 0, max: 10000 }),
          (name, value) => {
            const datum = createMetricDatum({ name, value });
            return (
              datum.MetricName === name &&
              datum.Value === value &&
              datum.Timestamp !== undefined
            );
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should calculate valid latency stats', () => {
      fc.assert(
        fc.property(
          fc.array(fc.integer({ min: 1, max: 10000 }), { minLength: 1, maxLength: 100 }),
          (samples) => {
            const stats = calculateLatencyStats(samples);
            return (
              stats.min <= stats.max &&
              stats.count === samples.length &&
              stats.sum === samples.reduce((a, b) => a + b, 0)
            );
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should calculate valid success rate', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 1000 }),
          fc.integer({ min: 0, max: 1000 }),
          (success, failure) => {
            const rate = calculateSuccessRate(success, failure);
            return rate >= 0 && rate <= 100;
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
