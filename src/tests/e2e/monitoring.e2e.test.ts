/**
 * CloudWatch Monitoring Service E2E Tests
 * Task 7.3: CloudWatch Integration
 * 
 * Tests:
 * - Metric creation and buffering
 * - Latency tracking
 * - Dashboard metrics
 * - Alarm thresholds
 */

// Mock CloudWatch client - must be before imports
const mockSend = jest.fn().mockResolvedValue({});
jest.mock('@aws-sdk/client-cloudwatch', () => ({
  CloudWatchClient: jest.fn().mockImplementation(() => ({
    send: (...args: unknown[]) => mockSend(...args)
  })),
  PutMetricDataCommand: jest.fn().mockImplementation((params) => params),
  StandardUnit: {
    Count: 'Count',
    Milliseconds: 'Milliseconds',
    Percent: 'Percent',
    Bytes: 'Bytes',
    None: 'None'
  }
}));

import {
  MetricName,
  METRIC_NAMESPACE,
  DEFAULT_MONITORING_CONFIG,
  MonitoringConfig,
  createMetricDatum,
  createLatencyMetricDatum,
  putMetric,
  putMetrics,
  bufferMetric,
  flushMetricBuffer,
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
} from '../../services/monitoring.service';
import { StandardUnit } from '@aws-sdk/client-cloudwatch';

describe('CloudWatch Monitoring Service - E2E Tests', () => {
  beforeEach(() => {
    clearBuffer();
    mockSend.mockClear();
  });

  describe('Authentication Metrics', () => {
    it('should track login success with latency', () => {
      MonitoringHelpers.loginSuccess('clinisyn-psychologists', 150);

      expect(getBufferSize()).toBe(2);
    });

    it('should track login failure with error type', () => {
      MonitoringHelpers.loginFailure('clinisyn-psychologists', 'INVALID_CREDENTIALS');

      expect(getBufferSize()).toBe(1);
    });

    it('should track multiple login attempts', () => {
      MonitoringHelpers.loginSuccess('clinisyn-psychologists', 100);
      MonitoringHelpers.loginSuccess('clinisyn-psychologists', 120);
      MonitoringHelpers.loginFailure('clinisyn-psychologists', 'INVALID_PASSWORD');
      MonitoringHelpers.loginSuccess('clinisyn-psychologists', 90);

      expect(getBufferSize()).toBe(7);  // 3 success + 3 latency + 1 failure
    });

    it('should track logout', () => {
      MonitoringHelpers.logout('clinisyn-psychologists');

      expect(getBufferSize()).toBe(1);
    });

    it('should track registration', () => {
      MonitoringHelpers.register('clinisyn-psychologists');

      expect(getBufferSize()).toBe(1);
    });
  });

  describe('Token Metrics', () => {
    it('should track token refresh with latency', () => {
      MonitoringHelpers.tokenRefresh('clinisyn-psychologists', 50);

      expect(getBufferSize()).toBe(2);
    });

    it('should track token validation', () => {
      MonitoringHelpers.tokenValidation('clinisyn-psychologists', 10);

      expect(getBufferSize()).toBe(2);
    });
  });

  describe('MFA Metrics', () => {
    it('should track TOTP MFA setup', () => {
      MonitoringHelpers.mfaSetup('clinisyn-psychologists', 'totp');

      expect(getBufferSize()).toBe(1);
    });

    it('should track WebAuthn MFA setup', () => {
      MonitoringHelpers.mfaSetup('clinisyn-psychologists', 'webauthn');

      expect(getBufferSize()).toBe(1);
    });

    it('should track MFA verify success with latency', () => {
      MonitoringHelpers.mfaVerifySuccess('clinisyn-psychologists', 200);

      expect(getBufferSize()).toBe(2);
    });

    it('should track MFA verify failure', () => {
      MonitoringHelpers.mfaVerifyFailure('clinisyn-psychologists');

      expect(getBufferSize()).toBe(1);
    });
  });

  describe('Security Metrics', () => {
    it('should track rate limit hits', () => {
      MonitoringHelpers.rateLimitHit('clinisyn-psychologists', '/v1/auth/login');

      expect(getBufferSize()).toBe(1);
    });

    it('should track account lockouts', () => {
      MonitoringHelpers.accountLockout('clinisyn-psychologists');

      expect(getBufferSize()).toBe(1);
    });

    it('should track credential stuffing attacks', () => {
      MonitoringHelpers.credentialStuffing('clinisyn-psychologists', 150);

      expect(getBufferSize()).toBe(1);
    });

    it('should track impossible travel', () => {
      MonitoringHelpers.impossibleTravel('clinisyn-psychologists');

      expect(getBufferSize()).toBe(1);
    });

    it('should track suspicious activity', () => {
      MonitoringHelpers.suspiciousActivity('clinisyn-psychologists', 'unusual_login_pattern');

      expect(getBufferSize()).toBe(1);
    });
  });

  describe('Error Metrics', () => {
    it('should track 4xx errors', () => {
      MonitoringHelpers.error('clinisyn-psychologists', 400, 'BAD_REQUEST');
      MonitoringHelpers.error('clinisyn-psychologists', 401, 'UNAUTHORIZED');
      MonitoringHelpers.error('clinisyn-psychologists', 403, 'FORBIDDEN');
      MonitoringHelpers.error('clinisyn-psychologists', 404, 'NOT_FOUND');

      expect(getBufferSize()).toBe(8);  // 4 ERROR_COUNT + 4 ERROR_4XX
    });

    it('should track 5xx errors', () => {
      MonitoringHelpers.error('clinisyn-psychologists', 500, 'INTERNAL_ERROR');
      MonitoringHelpers.error('clinisyn-psychologists', 502, 'BAD_GATEWAY');
      MonitoringHelpers.error('clinisyn-psychologists', 503, 'SERVICE_UNAVAILABLE');

      expect(getBufferSize()).toBe(6);  // 3 ERROR_COUNT + 3 ERROR_5XX
    });
  });

  describe('Session Metrics', () => {
    it('should track session lifecycle', () => {
      MonitoringHelpers.sessionCreated('clinisyn-psychologists');
      MonitoringHelpers.sessionExpired('clinisyn-psychologists');

      expect(getBufferSize()).toBe(2);
    });

    it('should track session timeouts', () => {
      MonitoringHelpers.sessionTimeout('clinisyn-psychologists', 'idle');
      MonitoringHelpers.sessionTimeout('clinisyn-psychologists', 'absolute');

      expect(getBufferSize()).toBe(2);
    });
  });

  describe('Device Metrics', () => {
    it('should track device events', () => {
      MonitoringHelpers.newDevice('clinisyn-psychologists');
      MonitoringHelpers.trustedDevice('clinisyn-psychologists');
      MonitoringHelpers.deviceRevoked('clinisyn-psychologists');

      expect(getBufferSize()).toBe(3);
    });
  });

  describe('Latency Tracking', () => {
    it('should calculate latency statistics', () => {
      const samples = [100, 150, 200, 250, 300, 350, 400, 450, 500, 550];
      const stats = calculateLatencyStats(samples);

      expect(stats.min).toBe(100);
      expect(stats.max).toBe(550);
      expect(stats.count).toBe(10);
      expect(stats.sum).toBe(3250);
    });

    it('should calculate percentiles correctly', () => {
      const samples = Array.from({ length: 1000 }, (_, i) => i + 1);
      const stats = calculateLatencyStats(samples);

      expect(stats.p50).toBe(501);
      expect(stats.p95).toBe(951);
      expect(stats.p99).toBe(991);
    });

    it('should use LatencyTimer for measurement', async () => {
      const timer = new LatencyTimer();
      await new Promise(resolve => setTimeout(resolve, 20));
      const duration = timer.stop();

      expect(duration).toBeGreaterThanOrEqual(20);
      expect(duration).toBeLessThan(100);
    });
  });

  describe('Metric Buffering', () => {
    it('should buffer metrics for batch sending', () => {
      for (let i = 0; i < 10; i++) {
        MonitoringHelpers.loginSuccess('test-realm');
      }

      expect(getBufferSize()).toBe(10);
    });

    it('should clear buffer', () => {
      MonitoringHelpers.loginSuccess('test-realm');
      MonitoringHelpers.loginFailure('test-realm');

      clearBuffer();

      expect(getBufferSize()).toBe(0);
    });

    it('should flush buffer to CloudWatch', async () => {
      MonitoringHelpers.loginSuccess('test-realm');
      MonitoringHelpers.loginFailure('test-realm');

      await flushMetricBuffer();

      expect(getBufferSize()).toBe(0);
    });
  });

  describe('Metric Creation', () => {
    it('should create metric datum with dimensions', () => {
      const datum = createMetricDatum({
        name: MetricName.LOGIN_SUCCESS,
        value: 1,
        dimensions: [
          realmDimension('clinisyn-psychologists'),
          endpointDimension('/v1/auth/login')
        ]
      });

      expect(datum.MetricName).toBe(MetricName.LOGIN_SUCCESS);
      expect(datum.Value).toBe(1);
      expect(datum.Dimensions?.find(d => d.Name === 'RealmId')).toBeDefined();
      expect(datum.Dimensions?.find(d => d.Name === 'Endpoint')).toBeDefined();
    });

    it('should create latency metric with statistics', () => {
      const stats = calculateLatencyStats([100, 200, 300, 400, 500]);
      const datum = createLatencyMetricDatum(
        MetricName.LOGIN_LATENCY,
        stats,
        [realmDimension('clinisyn-psychologists')]
      );

      expect(datum.MetricName).toBe(MetricName.LOGIN_LATENCY);
      expect(datum.StatisticValues?.Minimum).toBe(100);
      expect(datum.StatisticValues?.Maximum).toBe(500);
      expect(datum.StatisticValues?.SampleCount).toBe(5);
      expect(datum.Unit).toBe(StandardUnit.Milliseconds);
    });
  });

  describe('putMetric', () => {
    it('should send metric to CloudWatch', async () => {
      await putMetric({
        name: MetricName.LOGIN_SUCCESS,
        value: 1,
        dimensions: [realmDimension('test-realm')]
      });

      expect(mockSend).toHaveBeenCalled();
    });

    it('should not send when disabled', async () => {
      const config: MonitoringConfig = {
        ...DEFAULT_MONITORING_CONFIG,
        enabled: false
      };

      await putMetric({
        name: MetricName.LOGIN_SUCCESS,
        value: 1
      }, config);

      expect(mockSend).not.toHaveBeenCalled();
    });
  });

  describe('putMetrics', () => {
    it('should send multiple metrics', async () => {
      await putMetrics([
        { name: MetricName.LOGIN_SUCCESS, value: 1 },
        { name: MetricName.LOGIN_FAILURE, value: 1 },
        { name: MetricName.LOGOUT, value: 1 }
      ]);

      expect(mockSend).toHaveBeenCalled();
    });

    it('should batch metrics when exceeding limit', async () => {
      const metrics = Array.from({ length: 25 }, (_, i) => ({
        name: MetricName.LOGIN_SUCCESS,
        value: i + 1
      }));

      await putMetrics(metrics);

      // Should be called twice (20 + 5)
      expect(mockSend).toHaveBeenCalledTimes(2);
    });

    it('should not send empty array', async () => {
      await putMetrics([]);

      expect(mockSend).not.toHaveBeenCalled();
    });
  });

  describe('Success/Error Rate Calculations', () => {
    it('should calculate login success rate', () => {
      const successCount = 95;
      const failureCount = 5;
      const rate = calculateSuccessRate(successCount, failureCount);

      expect(rate).toBe(95);
    });

    it('should calculate error rate', () => {
      const errorCount = 10;
      const totalCount = 200;
      const rate = calculateErrorRate(errorCount, totalCount);

      expect(rate).toBe(5);
    });

    it('should handle edge cases', () => {
      expect(calculateSuccessRate(0, 0)).toBe(100);
      expect(calculateErrorRate(0, 0)).toBe(0);
      expect(calculateSuccessRate(100, 0)).toBe(100);
      expect(calculateErrorRate(100, 100)).toBe(100);
    });
  });

  describe('Dashboard Metrics', () => {
    it('should have all required dashboard metrics', () => {
      expect(DASHBOARD_METRICS.loginSuccessRate).toBeDefined();
      expect(DASHBOARD_METRICS.loginLatencyP95).toBeDefined();
      expect(DASHBOARD_METRICS.mfaSuccessRate).toBeDefined();
      expect(DASHBOARD_METRICS.tokenRefreshLatency).toBeDefined();
      expect(DASHBOARD_METRICS.errorRate).toBeDefined();
      expect(DASHBOARD_METRICS.securityEvents).toBeDefined();
    });

    it('should use correct namespace', () => {
      Object.values(DASHBOARD_METRICS).forEach(metric => {
        expect(metric.namespace).toBe(METRIC_NAMESPACE);
      });
    });

    it('should have 5 minute period', () => {
      Object.values(DASHBOARD_METRICS).forEach(metric => {
        expect(metric.period).toBe(300);
      });
    });
  });

  describe('Alarm Thresholds', () => {
    it('should have login latency threshold of 500ms', () => {
      expect(ALARM_THRESHOLDS.loginLatencyP95).toBe(500);
    });

    it('should have error rate threshold of 5%', () => {
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

  describe('Dimension Helpers', () => {
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

  describe('Real-world Scenarios', () => {
    it('should track complete login flow', () => {
      // User attempts login
      MonitoringHelpers.loginSuccess('clinisyn-psychologists', 150);
      
      // Session created
      MonitoringHelpers.sessionCreated('clinisyn-psychologists');
      
      // New device detected
      MonitoringHelpers.newDevice('clinisyn-psychologists');
      
      // MFA required
      MonitoringHelpers.mfaVerifySuccess('clinisyn-psychologists', 200);

      expect(getBufferSize()).toBe(6);
    });

    it('should track failed login with lockout', () => {
      // Multiple failed attempts
      for (let i = 0; i < 5; i++) {
        MonitoringHelpers.loginFailure('clinisyn-psychologists', 'INVALID_PASSWORD');
      }
      
      // Account locked
      MonitoringHelpers.accountLockout('clinisyn-psychologists');

      expect(getBufferSize()).toBe(6);
    });

    it('should track security incident', () => {
      // Credential stuffing detected
      MonitoringHelpers.credentialStuffing('clinisyn-psychologists', 150);
      
      // Rate limit hit
      MonitoringHelpers.rateLimitHit('clinisyn-psychologists', '/v1/auth/login');
      
      // Suspicious activity
      MonitoringHelpers.suspiciousActivity('clinisyn-psychologists', 'credential_stuffing');

      expect(getBufferSize()).toBe(3);
    });

    it('should track impossible travel scenario', () => {
      // Login from Istanbul
      MonitoringHelpers.loginSuccess('clinisyn-psychologists', 100);
      
      // 1 hour later, login from New York - impossible travel
      MonitoringHelpers.impossibleTravel('clinisyn-psychologists');
      
      // Account locked
      MonitoringHelpers.accountLockout('clinisyn-psychologists');

      expect(getBufferSize()).toBe(4);
    });
  });

  describe('Multi-realm Metrics', () => {
    it('should track metrics for different realms', () => {
      MonitoringHelpers.loginSuccess('clinisyn-psychologists', 100);
      MonitoringHelpers.loginSuccess('clinisyn-students', 120);
      MonitoringHelpers.loginSuccess('standard-app', 80);

      expect(getBufferSize()).toBe(6);  // 3 success + 3 latency
    });
  });
});
