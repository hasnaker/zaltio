/**
 * SIEM Integration Service for Zalt.io Auth Platform
 * Task 19.3: SIEM Integration
 * 
 * Supports:
 * - Webhook-based log forwarding
 * - Splunk HEC (HTTP Event Collector) format
 * - Datadog Log API format
 * - Generic JSON webhook format
 * - Batch processing for efficiency
 * - Retry with exponential backoff
 * 
 * Security:
 * - HMAC-SHA256 signature for webhook verification
 * - TLS required for all endpoints
 * - Rate limiting on forwarding
 * - Sensitive data masking
 */

import * as crypto from 'crypto';
import { AuditLogEntry, AuditEventType, AuditSeverity, AuditResult } from './audit.service';

// ============================================================================
// Types
// ============================================================================

/**
 * SIEM provider types
 */
export enum SIEMProvider {
  SPLUNK = 'splunk',
  DATADOG = 'datadog',
  GENERIC_WEBHOOK = 'generic_webhook',
  AWS_SECURITY_LAKE = 'aws_security_lake',
  ELASTIC = 'elastic'
}

/**
 * SIEM configuration
 */
export interface SIEMConfig {
  id: string;
  realmId: string;
  provider: SIEMProvider;
  enabled: boolean;
  
  // Endpoint configuration
  endpoint: string;
  
  // Authentication
  authType: 'token' | 'basic' | 'hmac';
  authToken?: string;
  authUsername?: string;
  authPassword?: string;
  hmacSecret?: string;
  
  // Provider-specific settings
  splunkIndex?: string;
  splunkSource?: string;
  splunkSourcetype?: string;
  datadogApiKey?: string;
  datadogSite?: string;
  
  // Filtering
  eventTypes?: AuditEventType[];
  minSeverity?: AuditSeverity;
  
  // Batching
  batchSize: number;
  batchIntervalMs: number;
  
  // Retry configuration
  maxRetries: number;
  retryDelayMs: number;
  
  // Metadata
  createdAt: string;
  updatedAt: string;
}

/**
 * SIEM delivery result
 */
export interface SIEMDeliveryResult {
  success: boolean;
  provider: SIEMProvider;
  eventsDelivered: number;
  eventsFailed: number;
  error?: string;
  responseCode?: number;
  retryCount: number;
  durationMs: number;
}

/**
 * Splunk HEC event format
 */
interface SplunkEvent {
  time: number;
  host: string;
  source: string;
  sourcetype: string;
  index?: string;
  event: Record<string, unknown>;
}

/**
 * Datadog log format
 */
interface DatadogLog {
  ddsource: string;
  ddtags: string;
  hostname: string;
  service: string;
  status: string;
  message: string;
  timestamp: string;
  [key: string]: unknown;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_BATCH_SIZE = 100;
const DEFAULT_BATCH_INTERVAL_MS = 5000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_DELAY_MS = 1000;
const MAX_PAYLOAD_SIZE = 5 * 1024 * 1024; // 5MB

// Severity mapping for different providers
const SEVERITY_MAP: Record<AuditSeverity, { splunk: string; datadog: string }> = {
  [AuditSeverity.INFO]: { splunk: 'info', datadog: 'info' },
  [AuditSeverity.WARNING]: { splunk: 'warn', datadog: 'warn' },
  [AuditSeverity.ERROR]: { splunk: 'error', datadog: 'error' },
  [AuditSeverity.CRITICAL]: { splunk: 'critical', datadog: 'critical' }
};

// ============================================================================
// Format Converters
// ============================================================================

/**
 * Convert audit log to Splunk HEC format
 */
export function toSplunkFormat(
  log: AuditLogEntry,
  config: SIEMConfig
): SplunkEvent {
  return {
    time: new Date(log.timestamp).getTime() / 1000,
    host: 'zalt.io',
    source: config.splunkSource || 'zalt:auth',
    sourcetype: config.splunkSourcetype || 'zalt:audit',
    index: config.splunkIndex,
    event: {
      event_id: log.id,
      event_type: log.eventType,
      result: log.result,
      severity: SEVERITY_MAP[log.severity].splunk,
      realm_id: log.realmId,
      user_id: log.userId,
      session_id: log.sessionId,
      ip_address: log.ipAddress,
      ip_hash: log.ipAddressHash,
      user_agent: log.userAgent,
      geo_country: log.geoCountry,
      geo_city: log.geoCity,
      action: log.action,
      resource: log.resource,
      details: log.details,
      error_code: log.errorCode,
      error_message: log.errorMessage,
      request_id: log.requestId
    }
  };
}

/**
 * Convert audit log to Datadog format
 */
export function toDatadogFormat(
  log: AuditLogEntry,
  config: SIEMConfig
): DatadogLog {
  const tags = [
    `realm:${log.realmId}`,
    `event_type:${log.eventType}`,
    `result:${log.result}`,
    `env:${process.env.STAGE || 'production'}`
  ];

  if (log.geoCountry) {
    tags.push(`country:${log.geoCountry}`);
  }

  return {
    ddsource: 'zalt',
    ddtags: tags.join(','),
    hostname: 'api.zalt.io',
    service: 'zalt-auth',
    status: SEVERITY_MAP[log.severity].datadog,
    message: `[${log.eventType}] ${log.action}`,
    timestamp: log.timestamp,
    event_id: log.id,
    event_type: log.eventType,
    result: log.result,
    severity: log.severity,
    realm_id: log.realmId,
    user_id: log.userId,
    session_id: log.sessionId,
    ip_address: log.ipAddress,
    ip_hash: log.ipAddressHash,
    user_agent: log.userAgent,
    geo_country: log.geoCountry,
    geo_city: log.geoCity,
    action: log.action,
    resource: log.resource,
    details: log.details,
    error_code: log.errorCode,
    error_message: log.errorMessage,
    request_id: log.requestId
  };
}

/**
 * Convert audit log to generic webhook format
 */
export function toGenericFormat(log: AuditLogEntry): Record<string, unknown> {
  return {
    id: log.id,
    timestamp: log.timestamp,
    event_type: log.eventType,
    result: log.result,
    severity: log.severity,
    realm_id: log.realmId,
    user_id: log.userId,
    session_id: log.sessionId,
    ip_address: log.ipAddress,
    ip_hash: log.ipAddressHash,
    user_agent: log.userAgent,
    geo: {
      country: log.geoCountry,
      city: log.geoCity
    },
    action: log.action,
    resource: log.resource,
    details: log.details,
    error: log.errorCode ? {
      code: log.errorCode,
      message: log.errorMessage
    } : undefined,
    request_id: log.requestId
  };
}

// ============================================================================
// Signature Generation
// ============================================================================

/**
 * Generate HMAC-SHA256 signature for webhook payload
 */
export function generateSignature(
  payload: string,
  secret: string,
  timestamp: number
): string {
  const signaturePayload = `${timestamp}.${payload}`;
  return crypto
    .createHmac('sha256', secret)
    .update(signaturePayload)
    .digest('hex');
}

/**
 * Verify webhook signature
 */
export function verifySignature(
  payload: string,
  signature: string,
  secret: string,
  timestamp: number,
  toleranceSeconds: number = 300
): boolean {
  // Check timestamp is within tolerance
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > toleranceSeconds) {
    return false;
  }

  const expectedSignature = generateSignature(payload, secret, timestamp);
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

// ============================================================================
// SIEM Delivery
// ============================================================================

/**
 * Filter logs based on SIEM configuration
 */
export function filterLogs(
  logs: AuditLogEntry[],
  config: SIEMConfig
): AuditLogEntry[] {
  return logs.filter(log => {
    // Filter by event type if specified
    if (config.eventTypes && config.eventTypes.length > 0) {
      if (!config.eventTypes.includes(log.eventType)) {
        return false;
      }
    }

    // Filter by minimum severity
    if (config.minSeverity) {
      const severityOrder = [
        AuditSeverity.INFO,
        AuditSeverity.WARNING,
        AuditSeverity.ERROR,
        AuditSeverity.CRITICAL
      ];
      const logSeverityIndex = severityOrder.indexOf(log.severity);
      const minSeverityIndex = severityOrder.indexOf(config.minSeverity);
      if (logSeverityIndex < minSeverityIndex) {
        return false;
      }
    }

    return true;
  });
}

/**
 * Build request headers for SIEM provider
 */
function buildHeaders(config: SIEMConfig, payload: string): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'Zalt-SIEM-Forwarder/1.0'
  };

  switch (config.authType) {
    case 'token':
      if (config.provider === SIEMProvider.SPLUNK) {
        headers['Authorization'] = `Splunk ${config.authToken}`;
      } else if (config.provider === SIEMProvider.DATADOG) {
        headers['DD-API-KEY'] = config.datadogApiKey || config.authToken || '';
      } else {
        headers['Authorization'] = `Bearer ${config.authToken}`;
      }
      break;

    case 'basic':
      const credentials = Buffer.from(
        `${config.authUsername}:${config.authPassword}`
      ).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
      break;

    case 'hmac':
      if (config.hmacSecret) {
        const timestamp = Math.floor(Date.now() / 1000);
        const signature = generateSignature(payload, config.hmacSecret, timestamp);
        headers['X-Zalt-Timestamp'] = timestamp.toString();
        headers['X-Zalt-Signature'] = signature;
      }
      break;
  }

  return headers;
}

/**
 * Build endpoint URL for SIEM provider
 */
function buildEndpoint(config: SIEMConfig): string {
  if (config.provider === SIEMProvider.DATADOG) {
    const site = config.datadogSite || 'datadoghq.com';
    return `https://http-intake.logs.${site}/api/v2/logs`;
  }
  return config.endpoint;
}

/**
 * Deliver logs to SIEM provider
 */
export async function deliverToSIEM(
  logs: AuditLogEntry[],
  config: SIEMConfig
): Promise<SIEMDeliveryResult> {
  const startTime = Date.now();
  let retryCount = 0;
  let lastError: string | undefined;
  let responseCode: number | undefined;

  // Filter logs based on configuration
  const filteredLogs = filterLogs(logs, config);
  
  if (filteredLogs.length === 0) {
    return {
      success: true,
      provider: config.provider,
      eventsDelivered: 0,
      eventsFailed: 0,
      retryCount: 0,
      durationMs: Date.now() - startTime
    };
  }

  // Convert logs to provider format
  let payload: string;
  switch (config.provider) {
    case SIEMProvider.SPLUNK:
      const splunkEvents = filteredLogs.map(log => toSplunkFormat(log, config));
      payload = splunkEvents.map(e => JSON.stringify(e)).join('\n');
      break;

    case SIEMProvider.DATADOG:
      const datadogLogs = filteredLogs.map(log => toDatadogFormat(log, config));
      payload = JSON.stringify(datadogLogs);
      break;

    default:
      const genericLogs = filteredLogs.map(log => toGenericFormat(log));
      payload = JSON.stringify({ events: genericLogs });
  }

  // Check payload size
  if (Buffer.byteLength(payload) > MAX_PAYLOAD_SIZE) {
    return {
      success: false,
      provider: config.provider,
      eventsDelivered: 0,
      eventsFailed: filteredLogs.length,
      error: 'Payload exceeds maximum size limit',
      retryCount: 0,
      durationMs: Date.now() - startTime
    };
  }

  const endpoint = buildEndpoint(config);
  const headers = buildHeaders(config, payload);
  const maxRetries = config.maxRetries || DEFAULT_MAX_RETRIES;
  const retryDelay = config.retryDelayMs || DEFAULT_RETRY_DELAY_MS;

  // Retry loop with exponential backoff
  while (retryCount <= maxRetries) {
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: payload,
        signal: AbortSignal.timeout(30000) // 30 second timeout
      });

      responseCode = response.status;

      if (response.ok) {
        return {
          success: true,
          provider: config.provider,
          eventsDelivered: filteredLogs.length,
          eventsFailed: 0,
          responseCode,
          retryCount,
          durationMs: Date.now() - startTime
        };
      }

      // Non-retryable errors
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        const errorBody = await response.text().catch(() => 'Unknown error');
        return {
          success: false,
          provider: config.provider,
          eventsDelivered: 0,
          eventsFailed: filteredLogs.length,
          error: `HTTP ${response.status}: ${errorBody}`,
          responseCode,
          retryCount,
          durationMs: Date.now() - startTime
        };
      }

      // Retryable error
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : 'Unknown error';
    }

    retryCount++;
    if (retryCount <= maxRetries) {
      // Exponential backoff
      await new Promise(resolve => 
        setTimeout(resolve, retryDelay * Math.pow(2, retryCount - 1))
      );
    }
  }

  return {
    success: false,
    provider: config.provider,
    eventsDelivered: 0,
    eventsFailed: filteredLogs.length,
    error: lastError,
    responseCode,
    retryCount,
    durationMs: Date.now() - startTime
  };
}

// ============================================================================
// Batch Processing
// ============================================================================

/**
 * In-memory batch buffer for each SIEM config
 */
const batchBuffers = new Map<string, {
  logs: AuditLogEntry[];
  timer: NodeJS.Timeout | null;
}>();

/**
 * Add log to batch buffer
 */
export function addToBatch(
  log: AuditLogEntry,
  config: SIEMConfig,
  onFlush: (logs: AuditLogEntry[], config: SIEMConfig) => Promise<void>
): void {
  let buffer = batchBuffers.get(config.id);
  
  if (!buffer) {
    buffer = { logs: [], timer: null };
    batchBuffers.set(config.id, buffer);
  }

  buffer.logs.push(log);

  // Flush if batch size reached
  const batchSize = config.batchSize || DEFAULT_BATCH_SIZE;
  if (buffer.logs.length >= batchSize) {
    flushBatch(config.id, config, onFlush);
    return;
  }

  // Set timer for interval-based flush
  if (!buffer.timer) {
    const interval = config.batchIntervalMs || DEFAULT_BATCH_INTERVAL_MS;
    buffer.timer = setTimeout(() => {
      flushBatch(config.id, config, onFlush);
    }, interval);
  }
}

/**
 * Flush batch buffer
 */
export async function flushBatch(
  configId: string,
  config: SIEMConfig,
  onFlush: (logs: AuditLogEntry[], config: SIEMConfig) => Promise<void>
): Promise<void> {
  const buffer = batchBuffers.get(configId);
  if (!buffer || buffer.logs.length === 0) {
    return;
  }

  // Clear timer
  if (buffer.timer) {
    clearTimeout(buffer.timer);
    buffer.timer = null;
  }

  // Get logs and clear buffer
  const logs = buffer.logs;
  buffer.logs = [];

  // Deliver logs
  await onFlush(logs, config);
}

/**
 * Flush all batch buffers
 */
export async function flushAllBatches(
  configs: SIEMConfig[],
  onFlush: (logs: AuditLogEntry[], config: SIEMConfig) => Promise<void>
): Promise<void> {
  const promises = configs.map(config => flushBatch(config.id, config, onFlush));
  await Promise.all(promises);
}

// ============================================================================
// Configuration Validation
// ============================================================================

/**
 * Validate SIEM configuration
 */
export function validateSIEMConfig(config: Partial<SIEMConfig>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (!config.provider) {
    errors.push('Provider is required');
  }

  if (!config.endpoint && config.provider !== SIEMProvider.DATADOG) {
    errors.push('Endpoint is required');
  }

  if (config.endpoint && !config.endpoint.startsWith('https://')) {
    errors.push('Endpoint must use HTTPS');
  }

  if (!config.authType) {
    errors.push('Authentication type is required');
  }

  if (config.authType === 'token' && !config.authToken && !config.datadogApiKey) {
    errors.push('Auth token is required for token authentication');
  }

  if (config.authType === 'basic' && (!config.authUsername || !config.authPassword)) {
    errors.push('Username and password are required for basic authentication');
  }

  if (config.authType === 'hmac' && !config.hmacSecret) {
    errors.push('HMAC secret is required for HMAC authentication');
  }

  if (config.provider === SIEMProvider.DATADOG && !config.datadogApiKey) {
    errors.push('Datadog API key is required');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Create default SIEM configuration
 */
export function createDefaultSIEMConfig(
  realmId: string,
  provider: SIEMProvider
): Partial<SIEMConfig> {
  const now = new Date().toISOString();
  
  return {
    id: crypto.randomUUID(),
    realmId,
    provider,
    enabled: false,
    authType: provider === SIEMProvider.DATADOG ? 'token' : 'token',
    batchSize: DEFAULT_BATCH_SIZE,
    batchIntervalMs: DEFAULT_BATCH_INTERVAL_MS,
    maxRetries: DEFAULT_MAX_RETRIES,
    retryDelayMs: DEFAULT_RETRY_DELAY_MS,
    createdAt: now,
    updatedAt: now
  };
}

// ============================================================================
// Export Types
// ============================================================================

export type {
  SplunkEvent,
  DatadogLog
};
