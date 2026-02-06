/**
 * CloudWatch Monitoring Service for Zalt.io Auth Platform
 * Task 7.3: CloudWatch Integration
 * 
 * OBSERVABILITY:
 * - Custom metrics for authentication events
 * - Latency tracking (p50, p95, p99)
 * - Error rate monitoring
 * - Dashboard-ready metrics
 * - Alarm integration
 */

import { 
  CloudWatchClient, 
  PutMetricDataCommand,
  MetricDatum,
  StandardUnit,
  Dimension
} from '@aws-sdk/client-cloudwatch';
import { AWS_CONFIG } from '../config/aws.config';

/**
 * CloudWatch client
 */
const cloudWatchClient = new CloudWatchClient({ region: AWS_CONFIG.region });

/**
 * Metric namespace
 */
export const METRIC_NAMESPACE = 'Zalt/Auth';

/**
 * Metric names
 */
export enum MetricName {
  // Authentication metrics
  LOGIN_SUCCESS = 'LoginSuccess',
  LOGIN_FAILURE = 'LoginFailure',
  LOGIN_LATENCY = 'LoginLatency',
  LOGOUT = 'Logout',
  REGISTER = 'Register',
  
  // Token metrics
  TOKEN_REFRESH = 'TokenRefresh',
  TOKEN_REFRESH_LATENCY = 'TokenRefreshLatency',
  TOKEN_VALIDATION = 'TokenValidation',
  TOKEN_VALIDATION_LATENCY = 'TokenValidationLatency',
  
  // MFA metrics
  MFA_SETUP = 'MFASetup',
  MFA_VERIFY_SUCCESS = 'MFAVerifySuccess',
  MFA_VERIFY_FAILURE = 'MFAVerifyFailure',
  MFA_VERIFY_LATENCY = 'MFAVerifyLatency',
  WEBAUTHN_REGISTER = 'WebAuthnRegister',
  WEBAUTHN_AUTH = 'WebAuthnAuth',
  
  // Security metrics
  RATE_LIMIT_HIT = 'RateLimitHit',
  ACCOUNT_LOCKOUT = 'AccountLockout',
  CREDENTIAL_STUFFING = 'CredentialStuffing',
  IMPOSSIBLE_TRAVEL = 'ImpossibleTravel',
  SUSPICIOUS_ACTIVITY = 'SuspiciousActivity',
  
  // Error metrics
  ERROR_COUNT = 'ErrorCount',
  ERROR_4XX = 'Error4xx',
  ERROR_5XX = 'Error5xx',
  
  // Session metrics
  ACTIVE_SESSIONS = 'ActiveSessions',
  SESSION_CREATED = 'SessionCreated',
  SESSION_EXPIRED = 'SessionExpired',
  SESSION_TIMEOUT = 'SessionTimeout',
  
  // Device metrics
  NEW_DEVICE = 'NewDevice',
  TRUSTED_DEVICE = 'TrustedDevice',
  DEVICE_REVOKED = 'DeviceRevoked'
}

/**
 * Metric unit mapping
 */
const METRIC_UNITS: Record<MetricName, StandardUnit> = {
  [MetricName.LOGIN_SUCCESS]: StandardUnit.Count,
  [MetricName.LOGIN_FAILURE]: StandardUnit.Count,
  [MetricName.LOGIN_LATENCY]: StandardUnit.Milliseconds,
  [MetricName.LOGOUT]: StandardUnit.Count,
  [MetricName.REGISTER]: StandardUnit.Count,
  [MetricName.TOKEN_REFRESH]: StandardUnit.Count,
  [MetricName.TOKEN_REFRESH_LATENCY]: StandardUnit.Milliseconds,
  [MetricName.TOKEN_VALIDATION]: StandardUnit.Count,
  [MetricName.TOKEN_VALIDATION_LATENCY]: StandardUnit.Milliseconds,
  [MetricName.MFA_SETUP]: StandardUnit.Count,
  [MetricName.MFA_VERIFY_SUCCESS]: StandardUnit.Count,
  [MetricName.MFA_VERIFY_FAILURE]: StandardUnit.Count,
  [MetricName.MFA_VERIFY_LATENCY]: StandardUnit.Milliseconds,
  [MetricName.WEBAUTHN_REGISTER]: StandardUnit.Count,
  [MetricName.WEBAUTHN_AUTH]: StandardUnit.Count,
  [MetricName.RATE_LIMIT_HIT]: StandardUnit.Count,
  [MetricName.ACCOUNT_LOCKOUT]: StandardUnit.Count,
  [MetricName.CREDENTIAL_STUFFING]: StandardUnit.Count,
  [MetricName.IMPOSSIBLE_TRAVEL]: StandardUnit.Count,
  [MetricName.SUSPICIOUS_ACTIVITY]: StandardUnit.Count,
  [MetricName.ERROR_COUNT]: StandardUnit.Count,
  [MetricName.ERROR_4XX]: StandardUnit.Count,
  [MetricName.ERROR_5XX]: StandardUnit.Count,
  [MetricName.ACTIVE_SESSIONS]: StandardUnit.Count,
  [MetricName.SESSION_CREATED]: StandardUnit.Count,
  [MetricName.SESSION_EXPIRED]: StandardUnit.Count,
  [MetricName.SESSION_TIMEOUT]: StandardUnit.Count,
  [MetricName.NEW_DEVICE]: StandardUnit.Count,
  [MetricName.TRUSTED_DEVICE]: StandardUnit.Count,
  [MetricName.DEVICE_REVOKED]: StandardUnit.Count
};

/**
 * Monitoring configuration
 */
export interface MonitoringConfig {
  enabled: boolean;
  namespace: string;
  defaultDimensions: Dimension[];
  batchSize: number;
  flushIntervalMs: number;
}

/**
 * Default monitoring configuration
 */
export const DEFAULT_MONITORING_CONFIG: MonitoringConfig = {
  enabled: true,
  namespace: METRIC_NAMESPACE,
  defaultDimensions: [
    { Name: 'Environment', Value: process.env.STAGE || 'dev' }
  ],
  batchSize: 20,
  flushIntervalMs: 60000  // 1 minute
};

/**
 * Metric data point
 */
export interface MetricDataPoint {
  name: MetricName;
  value: number;
  unit?: StandardUnit;
  dimensions?: Dimension[];
  timestamp?: Date;
}

/**
 * Latency statistics
 */
export interface LatencyStats {
  min: number;
  max: number;
  sum: number;
  count: number;
  p50?: number;
  p95?: number;
  p99?: number;
}

/**
 * Metric buffer for batching
 */
const metricBuffer: MetricDatum[] = [];
let flushTimer: NodeJS.Timeout | null = null;

/**
 * Create metric datum
 */
export function createMetricDatum(
  dataPoint: MetricDataPoint,
  config: MonitoringConfig = DEFAULT_MONITORING_CONFIG
): MetricDatum {
  const dimensions = [
    ...config.defaultDimensions,
    ...(dataPoint.dimensions || [])
  ];

  return {
    MetricName: dataPoint.name,
    Value: dataPoint.value,
    Unit: dataPoint.unit || METRIC_UNITS[dataPoint.name] || StandardUnit.Count,
    Timestamp: dataPoint.timestamp || new Date(),
    Dimensions: dimensions
  };
}

/**
 * Create latency metric datum with statistics
 */
export function createLatencyMetricDatum(
  name: MetricName,
  stats: LatencyStats,
  dimensions?: Dimension[],
  config: MonitoringConfig = DEFAULT_MONITORING_CONFIG
): MetricDatum {
  const allDimensions = [
    ...config.defaultDimensions,
    ...(dimensions || [])
  ];

  return {
    MetricName: name,
    StatisticValues: {
      Minimum: stats.min,
      Maximum: stats.max,
      Sum: stats.sum,
      SampleCount: stats.count
    },
    Unit: StandardUnit.Milliseconds,
    Timestamp: new Date(),
    Dimensions: allDimensions
  };
}

/**
 * Put metric to CloudWatch
 */
export async function putMetric(
  dataPoint: MetricDataPoint,
  config: MonitoringConfig = DEFAULT_MONITORING_CONFIG
): Promise<void> {
  if (!config.enabled) {
    return;
  }

  const datum = createMetricDatum(dataPoint, config);
  
  const command = new PutMetricDataCommand({
    Namespace: config.namespace,
    MetricData: [datum]
  });

  try {
    await cloudWatchClient.send(command);
  } catch (error) {
    console.error('Failed to put metric:', error);
  }
}

/**
 * Put multiple metrics to CloudWatch
 */
export async function putMetrics(
  dataPoints: MetricDataPoint[],
  config: MonitoringConfig = DEFAULT_MONITORING_CONFIG
): Promise<void> {
  if (!config.enabled || dataPoints.length === 0) {
    return;
  }

  const metricData = dataPoints.map(dp => createMetricDatum(dp, config));

  // CloudWatch allows max 20 metrics per request
  const batches: MetricDatum[][] = [];
  for (let i = 0; i < metricData.length; i += config.batchSize) {
    batches.push(metricData.slice(i, i + config.batchSize));
  }

  for (const batch of batches) {
    const command = new PutMetricDataCommand({
      Namespace: config.namespace,
      MetricData: batch
    });

    try {
      await cloudWatchClient.send(command);
    } catch (error) {
      console.error('Failed to put metrics batch:', error);
    }
  }
}

/**
 * Buffer metric for batch sending
 */
export function bufferMetric(
  dataPoint: MetricDataPoint,
  config: MonitoringConfig = DEFAULT_MONITORING_CONFIG
): void {
  if (!config.enabled) {
    return;
  }

  const datum = createMetricDatum(dataPoint, config);
  metricBuffer.push(datum);

  // Start flush timer if not running
  if (!flushTimer) {
    flushTimer = setTimeout(() => flushMetricBuffer(config), config.flushIntervalMs);
  }

  // Flush if buffer is full
  if (metricBuffer.length >= config.batchSize) {
    flushMetricBuffer(config);
  }
}

/**
 * Flush metric buffer to CloudWatch
 */
export async function flushMetricBuffer(
  config: MonitoringConfig = DEFAULT_MONITORING_CONFIG
): Promise<void> {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }

  if (metricBuffer.length === 0) {
    return;
  }

  const metricsToSend = metricBuffer.splice(0, metricBuffer.length);

  // Send in batches
  const batches: MetricDatum[][] = [];
  for (let i = 0; i < metricsToSend.length; i += config.batchSize) {
    batches.push(metricsToSend.slice(i, i + config.batchSize));
  }

  for (const batch of batches) {
    const command = new PutMetricDataCommand({
      Namespace: config.namespace,
      MetricData: batch
    });

    try {
      await cloudWatchClient.send(command);
    } catch (error) {
      console.error('Failed to flush metrics:', error);
    }
  }
}

/**
 * Get current buffer size (for testing)
 */
export function getBufferSize(): number {
  return metricBuffer.length;
}

/**
 * Clear buffer (for testing)
 */
export function clearBuffer(): void {
  metricBuffer.length = 0;
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
}

/**
 * Calculate latency statistics from samples
 */
export function calculateLatencyStats(samples: number[]): LatencyStats {
  if (samples.length === 0) {
    return { min: 0, max: 0, sum: 0, count: 0 };
  }

  const sorted = [...samples].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, val) => acc + val, 0);

  return {
    min: sorted[0],
    max: sorted[sorted.length - 1],
    sum,
    count: sorted.length,
    p50: sorted[Math.floor(sorted.length * 0.5)],
    p95: sorted[Math.floor(sorted.length * 0.95)],
    p99: sorted[Math.floor(sorted.length * 0.99)]
  };
}

/**
 * Timer for measuring latency
 */
export class LatencyTimer {
  private startTime: number;
  private endTime?: number;

  constructor() {
    this.startTime = Date.now();
  }

  stop(): number {
    this.endTime = Date.now();
    return this.getDuration();
  }

  getDuration(): number {
    const end = this.endTime || Date.now();
    return end - this.startTime;
  }
}

/**
 * Create realm dimension
 */
export function realmDimension(realmId: string): Dimension {
  return { Name: 'RealmId', Value: realmId };
}

/**
 * Create endpoint dimension
 */
export function endpointDimension(endpoint: string): Dimension {
  return { Name: 'Endpoint', Value: endpoint };
}

/**
 * Create error type dimension
 */
export function errorTypeDimension(errorType: string): Dimension {
  return { Name: 'ErrorType', Value: errorType };
}

/**
 * Monitoring helper functions
 */
export const MonitoringHelpers = {
  // Authentication metrics
  loginSuccess: (realmId: string, latencyMs?: number) => {
    bufferMetric({
      name: MetricName.LOGIN_SUCCESS,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
    if (latencyMs !== undefined) {
      bufferMetric({
        name: MetricName.LOGIN_LATENCY,
        value: latencyMs,
        dimensions: [realmDimension(realmId)]
      });
    }
  },

  loginFailure: (realmId: string, errorType?: string) => {
    const dimensions = [realmDimension(realmId)];
    if (errorType) {
      dimensions.push(errorTypeDimension(errorType));
    }
    bufferMetric({
      name: MetricName.LOGIN_FAILURE,
      value: 1,
      dimensions
    });
  },

  logout: (realmId: string) => {
    bufferMetric({
      name: MetricName.LOGOUT,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  register: (realmId: string) => {
    bufferMetric({
      name: MetricName.REGISTER,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  // Token metrics
  tokenRefresh: (realmId: string, latencyMs?: number) => {
    bufferMetric({
      name: MetricName.TOKEN_REFRESH,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
    if (latencyMs !== undefined) {
      bufferMetric({
        name: MetricName.TOKEN_REFRESH_LATENCY,
        value: latencyMs,
        dimensions: [realmDimension(realmId)]
      });
    }
  },

  tokenValidation: (realmId: string, latencyMs?: number) => {
    bufferMetric({
      name: MetricName.TOKEN_VALIDATION,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
    if (latencyMs !== undefined) {
      bufferMetric({
        name: MetricName.TOKEN_VALIDATION_LATENCY,
        value: latencyMs,
        dimensions: [realmDimension(realmId)]
      });
    }
  },

  // MFA metrics
  mfaSetup: (realmId: string, mfaType: 'totp' | 'webauthn') => {
    bufferMetric({
      name: MetricName.MFA_SETUP,
      value: 1,
      dimensions: [
        realmDimension(realmId),
        { Name: 'MFAType', Value: mfaType }
      ]
    });
  },

  mfaVerifySuccess: (realmId: string, latencyMs?: number) => {
    bufferMetric({
      name: MetricName.MFA_VERIFY_SUCCESS,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
    if (latencyMs !== undefined) {
      bufferMetric({
        name: MetricName.MFA_VERIFY_LATENCY,
        value: latencyMs,
        dimensions: [realmDimension(realmId)]
      });
    }
  },

  mfaVerifyFailure: (realmId: string) => {
    bufferMetric({
      name: MetricName.MFA_VERIFY_FAILURE,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  // Security metrics
  rateLimitHit: (realmId: string, endpoint: string) => {
    bufferMetric({
      name: MetricName.RATE_LIMIT_HIT,
      value: 1,
      dimensions: [realmDimension(realmId), endpointDimension(endpoint)]
    });
  },

  accountLockout: (realmId: string) => {
    bufferMetric({
      name: MetricName.ACCOUNT_LOCKOUT,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  credentialStuffing: (realmId: string, blockedCount: number) => {
    bufferMetric({
      name: MetricName.CREDENTIAL_STUFFING,
      value: blockedCount,
      dimensions: [realmDimension(realmId)]
    });
  },

  impossibleTravel: (realmId: string) => {
    bufferMetric({
      name: MetricName.IMPOSSIBLE_TRAVEL,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  suspiciousActivity: (realmId: string, activityType: string) => {
    bufferMetric({
      name: MetricName.SUSPICIOUS_ACTIVITY,
      value: 1,
      dimensions: [
        realmDimension(realmId),
        { Name: 'ActivityType', Value: activityType }
      ]
    });
  },

  // Error metrics
  error: (realmId: string, statusCode: number, errorType?: string) => {
    const dimensions = [realmDimension(realmId)];
    if (errorType) {
      dimensions.push(errorTypeDimension(errorType));
    }

    bufferMetric({
      name: MetricName.ERROR_COUNT,
      value: 1,
      dimensions
    });

    if (statusCode >= 400 && statusCode < 500) {
      bufferMetric({
        name: MetricName.ERROR_4XX,
        value: 1,
        dimensions
      });
    } else if (statusCode >= 500) {
      bufferMetric({
        name: MetricName.ERROR_5XX,
        value: 1,
        dimensions
      });
    }
  },

  // Session metrics
  sessionCreated: (realmId: string) => {
    bufferMetric({
      name: MetricName.SESSION_CREATED,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  sessionExpired: (realmId: string) => {
    bufferMetric({
      name: MetricName.SESSION_EXPIRED,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  sessionTimeout: (realmId: string, timeoutType: 'idle' | 'absolute') => {
    bufferMetric({
      name: MetricName.SESSION_TIMEOUT,
      value: 1,
      dimensions: [
        realmDimension(realmId),
        { Name: 'TimeoutType', Value: timeoutType }
      ]
    });
  },

  // Device metrics
  newDevice: (realmId: string) => {
    bufferMetric({
      name: MetricName.NEW_DEVICE,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  trustedDevice: (realmId: string) => {
    bufferMetric({
      name: MetricName.TRUSTED_DEVICE,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  },

  deviceRevoked: (realmId: string) => {
    bufferMetric({
      name: MetricName.DEVICE_REVOKED,
      value: 1,
      dimensions: [realmDimension(realmId)]
    });
  }
};

/**
 * Calculate success rate from counts
 */
export function calculateSuccessRate(successCount: number, failureCount: number): number {
  const total = successCount + failureCount;
  if (total === 0) return 100;
  return (successCount / total) * 100;
}

/**
 * Calculate error rate from counts
 */
export function calculateErrorRate(errorCount: number, totalCount: number): number {
  if (totalCount === 0) return 0;
  return (errorCount / totalCount) * 100;
}

/**
 * Dashboard metric definitions (for CloudFormation/CDK)
 */
export const DASHBOARD_METRICS = {
  loginSuccessRate: {
    namespace: METRIC_NAMESPACE,
    metricName: MetricName.LOGIN_SUCCESS,
    statistic: 'Sum',
    period: 300  // 5 minutes
  },
  loginLatencyP95: {
    namespace: METRIC_NAMESPACE,
    metricName: MetricName.LOGIN_LATENCY,
    statistic: 'p95',
    period: 300
  },
  mfaSuccessRate: {
    namespace: METRIC_NAMESPACE,
    metricName: MetricName.MFA_VERIFY_SUCCESS,
    statistic: 'Sum',
    period: 300
  },
  tokenRefreshLatency: {
    namespace: METRIC_NAMESPACE,
    metricName: MetricName.TOKEN_REFRESH_LATENCY,
    statistic: 'p95',
    period: 300
  },
  errorRate: {
    namespace: METRIC_NAMESPACE,
    metricName: MetricName.ERROR_COUNT,
    statistic: 'Sum',
    period: 300
  },
  securityEvents: {
    namespace: METRIC_NAMESPACE,
    metricName: MetricName.SUSPICIOUS_ACTIVITY,
    statistic: 'Sum',
    period: 300
  }
};

/**
 * Alarm thresholds
 */
export const ALARM_THRESHOLDS = {
  loginLatencyP95: 500,  // 500ms
  errorRate: 5,  // 5%
  loginFailureSpike: 50,  // 50 failures in 5 minutes
  accountLockoutSpike: 10,  // 10 lockouts in 5 minutes
  credentialStuffingThreshold: 100  // 100 blocked attempts
};
