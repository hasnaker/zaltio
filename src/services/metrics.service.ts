/**
 * CloudWatch Metrics Service for HSD Auth Platform
 * Validates: Requirements 7.4, 7.6
 * 
 * Publishes custom metrics to CloudWatch for monitoring and alerting
 */

import {
  CloudWatchClient,
  PutMetricDataCommand,
  MetricDatum,
  StandardUnit
} from '@aws-sdk/client-cloudwatch';
import { AWS_CONFIG } from '../config/aws.config';
import { CLOUDWATCH_METRICS_CONFIG } from '../config/scaling.config';

// CloudWatch client singleton
let cloudWatchClient: CloudWatchClient | null = null;

function getCloudWatchClient(): CloudWatchClient {
  if (!cloudWatchClient) {
    cloudWatchClient = new CloudWatchClient({ region: AWS_CONFIG.region });
  }
  return cloudWatchClient;
}

/**
 * Metric dimension type
 */
export interface MetricDimension {
  Name: string;
  Value: string;
}

/**
 * Metric data point
 */
export interface MetricDataPoint {
  metricName: string;
  value: number;
  unit: StandardUnit;
  dimensions?: MetricDimension[];
  timestamp?: Date;
}

/**
 * Batch of metrics to publish
 */
const metricBuffer: MetricDatum[] = [];
const BUFFER_SIZE = 20; // CloudWatch allows max 20 metrics per request
const FLUSH_INTERVAL_MS = 60000; // Flush every minute

// Auto-flush timer
let flushTimer: NodeJS.Timeout | null = null;

/**
 * Start the auto-flush timer
 */
function startAutoFlush(): void {
  if (!flushTimer) {
    flushTimer = setInterval(() => {
      flushMetrics().catch(console.error);
    }, FLUSH_INTERVAL_MS);
  }
}

/**
 * Stop the auto-flush timer
 */
export function stopAutoFlush(): void {
  if (flushTimer) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
}

/**
 * Add a metric to the buffer
 */
function bufferMetric(metric: MetricDatum): void {
  metricBuffer.push(metric);
  startAutoFlush();
  
  // Flush if buffer is full
  if (metricBuffer.length >= BUFFER_SIZE) {
    flushMetrics().catch(console.error);
  }
}

/**
 * Flush buffered metrics to CloudWatch
 */
export async function flushMetrics(): Promise<void> {
  if (metricBuffer.length === 0) return;
  
  const metricsToSend = metricBuffer.splice(0, BUFFER_SIZE);
  
  try {
    const client = getCloudWatchClient();
    const command = new PutMetricDataCommand({
      Namespace: CLOUDWATCH_METRICS_CONFIG.namespace,
      MetricData: metricsToSend
    });
    
    await client.send(command);
  } catch (error) {
    // Re-add metrics to buffer on failure (with limit to prevent memory issues)
    if (metricBuffer.length < BUFFER_SIZE * 5) {
      metricBuffer.unshift(...metricsToSend);
    }
    console.error('Failed to publish metrics to CloudWatch:', error);
  }
}

/**
 * Publish a single metric immediately
 */
export async function publishMetric(dataPoint: MetricDataPoint): Promise<void> {
  const metric: MetricDatum = {
    MetricName: dataPoint.metricName,
    Value: dataPoint.value,
    Unit: dataPoint.unit,
    Timestamp: dataPoint.timestamp || new Date(),
    Dimensions: dataPoint.dimensions
  };
  
  bufferMetric(metric);
}

/**
 * Publish multiple metrics
 */
export async function publishMetrics(dataPoints: MetricDataPoint[]): Promise<void> {
  for (const dataPoint of dataPoints) {
    await publishMetric(dataPoint);
  }
}

// ============================================
// Authentication Metrics
// ============================================

/**
 * Record a login attempt
 */
export async function recordLoginAttempt(
  realmId: string,
  success: boolean,
  latencyMs: number
): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.realm, Value: realmId }
  ];
  
  // Record attempt count
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.loginAttempts,
    value: 1,
    unit: StandardUnit.Count,
    dimensions
  });
  
  // Record success/failure
  if (success) {
    await publishMetric({
      metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.loginSuccesses,
      value: 1,
      unit: StandardUnit.Count,
      dimensions
    });
  } else {
    await publishMetric({
      metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.loginFailures,
      value: 1,
      unit: StandardUnit.Count,
      dimensions
    });
  }
  
  // Record latency
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.authLatency,
    value: latencyMs,
    unit: StandardUnit.Milliseconds,
    dimensions
  });
}

/**
 * Record a registration
 */
export async function recordRegistration(
  realmId: string,
  latencyMs: number
): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.realm, Value: realmId }
  ];
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.registrations,
    value: 1,
    unit: StandardUnit.Count,
    dimensions
  });
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.authLatency,
    value: latencyMs,
    unit: StandardUnit.Milliseconds,
    dimensions
  });
}

/**
 * Record a token refresh
 */
export async function recordTokenRefresh(
  realmId: string,
  latencyMs: number
): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.realm, Value: realmId }
  ];
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.tokenRefreshes,
    value: 1,
    unit: StandardUnit.Count,
    dimensions
  });
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.authLatency,
    value: latencyMs,
    unit: StandardUnit.Milliseconds,
    dimensions
  });
}

// ============================================
// Error Metrics
// ============================================

/**
 * Record an error
 */
export async function recordError(
  realmId: string,
  errorType: string
): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.realm, Value: realmId },
    { Name: 'ErrorType', Value: errorType }
  ];
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.errorRate,
    value: 1,
    unit: StandardUnit.Count,
    dimensions
  });
}

/**
 * Record a rate limit hit
 */
export async function recordRateLimitHit(realmId: string): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.realm, Value: realmId }
  ];
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.rateLimitHits,
    value: 1,
    unit: StandardUnit.Count,
    dimensions
  });
}

// ============================================
// Database Metrics
// ============================================

/**
 * Record database operation latency
 */
export async function recordDbLatency(
  operation: string,
  latencyMs: number
): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.operation, Value: operation }
  ];
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.dbLatency,
    value: latencyMs,
    unit: StandardUnit.Milliseconds,
    dimensions
  });
}

// ============================================
// Capacity Metrics
// ============================================

/**
 * Record active users count
 */
export async function recordActiveUsers(
  realmId: string,
  count: number
): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.realm, Value: realmId }
  ];
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.activeUsers,
    value: count,
    unit: StandardUnit.Count,
    dimensions
  });
}

/**
 * Record active sessions count
 */
export async function recordActiveSessions(
  realmId: string,
  count: number
): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.realm, Value: realmId }
  ];
  
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.activeSessions,
    value: count,
    unit: StandardUnit.Count,
    dimensions
  });
}

/**
 * Record total realm count
 */
export async function recordRealmCount(count: number): Promise<void> {
  await publishMetric({
    metricName: CLOUDWATCH_METRICS_CONFIG.customMetrics.realmCount,
    value: count,
    unit: StandardUnit.Count
  });
}

// ============================================
// Lambda Function Metrics
// ============================================

/**
 * Record Lambda function invocation
 */
export async function recordLambdaInvocation(
  functionName: string,
  durationMs: number,
  success: boolean
): Promise<void> {
  const dimensions: MetricDimension[] = [
    { Name: CLOUDWATCH_METRICS_CONFIG.dimensions.function, Value: functionName }
  ];
  
  // Record invocation
  await publishMetric({
    metricName: 'Invocations',
    value: 1,
    unit: StandardUnit.Count,
    dimensions
  });
  
  // Record duration
  await publishMetric({
    metricName: 'Duration',
    value: durationMs,
    unit: StandardUnit.Milliseconds,
    dimensions
  });
  
  // Record errors
  if (!success) {
    await publishMetric({
      metricName: 'Errors',
      value: 1,
      unit: StandardUnit.Count,
      dimensions
    });
  }
}
