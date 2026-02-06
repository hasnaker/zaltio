/**
 * SIEM Service Tests
 * Task 19.3: SIEM Integration
 * 
 * Tests:
 * - Format conversion (Splunk, Datadog, Generic)
 * - Signature generation and verification
 * - Log filtering
 * - Configuration validation
 * - Batch processing
 */

import {
  SIEMProvider,
  SIEMConfig,
  toSplunkFormat,
  toDatadogFormat,
  toGenericFormat,
  generateSignature,
  verifySignature,
  filterLogs,
  validateSIEMConfig,
  createDefaultSIEMConfig,
  addToBatch,
  flushBatch,
  deliverToSIEM
} from './siem.service';
import { AuditLogEntry, AuditEventType, AuditSeverity, AuditResult } from './audit.service';

// ============================================================================
// Test Data
// ============================================================================

const createMockAuditLog = (overrides: Partial<AuditLogEntry> = {}): AuditLogEntry => ({
  id: 'audit-123',
  timestamp: '2026-02-01T10:00:00.000Z',
  eventType: AuditEventType.LOGIN_SUCCESS,
  result: AuditResult.SUCCESS,
  severity: AuditSeverity.INFO,
  realmId: 'realm-clinisyn',
  userId: 'user-456',
  sessionId: 'session-789',
  ipAddress: '192.168.*.*',
  ipAddressHash: 'abc123def456',
  userAgent: 'Mozilla/5.0',
  geoCountry: 'TR',
  geoCity: 'Istanbul',
  action: 'User logged in successfully',
  resource: '/login',
  details: { mfa_used: false },
  pk: 'REALM#realm-clinisyn',
  sk: 'TIMESTAMP#2026-02-01T10:00:00.000Z#audit-123',
  ...overrides
});

const createMockSIEMConfig = (overrides: Partial<SIEMConfig> = {}): SIEMConfig => ({
  id: 'siem-config-123',
  realmId: 'realm-clinisyn',
  provider: SIEMProvider.SPLUNK,
  enabled: true,
  endpoint: 'https://splunk.example.com:8088/services/collector',
  authType: 'token',
  authToken: 'splunk-hec-token',
  splunkIndex: 'zalt_audit',
  splunkSource: 'zalt:auth',
  splunkSourcetype: 'zalt:audit',
  batchSize: 100,
  batchIntervalMs: 5000,
  maxRetries: 3,
  retryDelayMs: 1000,
  createdAt: '2026-02-01T00:00:00.000Z',
  updatedAt: '2026-02-01T00:00:00.000Z',
  ...overrides
});

// ============================================================================
// Format Conversion Tests
// ============================================================================

describe('SIEM Format Conversion', () => {
  describe('toSplunkFormat', () => {
    it('should convert audit log to Splunk HEC format', () => {
      const log = createMockAuditLog();
      const config = createMockSIEMConfig();
      
      const result = toSplunkFormat(log, config);
      
      expect(result.time).toBe(new Date(log.timestamp).getTime() / 1000);
      expect(result.host).toBe('zalt.io');
      expect(result.source).toBe('zalt:auth');
      expect(result.sourcetype).toBe('zalt:audit');
      expect(result.index).toBe('zalt_audit');
      expect(result.event.event_id).toBe(log.id);
      expect(result.event.event_type).toBe(log.eventType);
      expect(result.event.realm_id).toBe(log.realmId);
      expect(result.event.user_id).toBe(log.userId);
      expect(result.event.severity).toBe('info');
    });

    it('should use default source values when not configured', () => {
      const log = createMockAuditLog();
      const config = createMockSIEMConfig({
        splunkSource: undefined,
        splunkSourcetype: undefined,
        splunkIndex: undefined
      });
      
      const result = toSplunkFormat(log, config);
      
      expect(result.source).toBe('zalt:auth');
      expect(result.sourcetype).toBe('zalt:audit');
      expect(result.index).toBeUndefined();
    });

    it('should map severity correctly', () => {
      const severities: [AuditSeverity, string][] = [
        [AuditSeverity.INFO, 'info'],
        [AuditSeverity.WARNING, 'warn'],
        [AuditSeverity.ERROR, 'error'],
        [AuditSeverity.CRITICAL, 'critical']
      ];

      const config = createMockSIEMConfig();

      for (const [severity, expected] of severities) {
        const log = createMockAuditLog({ severity });
        const result = toSplunkFormat(log, config);
        expect(result.event.severity).toBe(expected);
      }
    });
  });

  describe('toDatadogFormat', () => {
    it('should convert audit log to Datadog format', () => {
      const log = createMockAuditLog();
      const config = createMockSIEMConfig({ provider: SIEMProvider.DATADOG });
      
      const result = toDatadogFormat(log, config);
      
      expect(result.ddsource).toBe('zalt');
      expect(result.hostname).toBe('api.zalt.io');
      expect(result.service).toBe('zalt-auth');
      expect(result.status).toBe('info');
      expect(result.message).toContain(log.eventType);
      expect(result.timestamp).toBe(log.timestamp);
      expect(result.event_id).toBe(log.id);
      expect(result.realm_id).toBe(log.realmId);
    });

    it('should include tags with realm and event type', () => {
      const log = createMockAuditLog();
      const config = createMockSIEMConfig({ provider: SIEMProvider.DATADOG });
      
      const result = toDatadogFormat(log, config);
      
      expect(result.ddtags).toContain('realm:realm-clinisyn');
      expect(result.ddtags).toContain('event_type:login_success');
      expect(result.ddtags).toContain('result:success');
    });

    it('should include country tag when geo data available', () => {
      const log = createMockAuditLog({ geoCountry: 'US' });
      const config = createMockSIEMConfig({ provider: SIEMProvider.DATADOG });
      
      const result = toDatadogFormat(log, config);
      
      expect(result.ddtags).toContain('country:US');
    });
  });

  describe('toGenericFormat', () => {
    it('should convert audit log to generic webhook format', () => {
      const log = createMockAuditLog();
      
      const result = toGenericFormat(log);
      
      expect(result.id).toBe(log.id);
      expect(result.timestamp).toBe(log.timestamp);
      expect(result.event_type).toBe(log.eventType);
      expect(result.result).toBe(log.result);
      expect(result.severity).toBe(log.severity);
      expect(result.realm_id).toBe(log.realmId);
      expect(result.user_id).toBe(log.userId);
      expect((result.geo as Record<string, unknown>).country).toBe(log.geoCountry);
    });

    it('should include error object when error code present', () => {
      const log = createMockAuditLog({
        errorCode: 'AUTH_FAILED',
        errorMessage: 'Invalid credentials'
      });
      
      const result = toGenericFormat(log);
      
      expect(result.error).toBeDefined();
      expect((result.error as Record<string, unknown>).code).toBe('AUTH_FAILED');
      expect((result.error as Record<string, unknown>).message).toBe('Invalid credentials');
    });

    it('should not include error object when no error code', () => {
      const log = createMockAuditLog({ errorCode: undefined });
      
      const result = toGenericFormat(log);
      
      expect(result.error).toBeUndefined();
    });
  });
});

// ============================================================================
// Signature Tests
// ============================================================================

describe('SIEM Signature', () => {
  const secret = 'test-hmac-secret-key';
  const payload = '{"event":"test"}';
  const timestamp = 1706781600; // Fixed timestamp for testing

  describe('generateSignature', () => {
    it('should generate consistent HMAC-SHA256 signature', () => {
      const sig1 = generateSignature(payload, secret, timestamp);
      const sig2 = generateSignature(payload, secret, timestamp);
      
      expect(sig1).toBe(sig2);
      expect(sig1).toHaveLength(64); // SHA256 hex = 64 chars
    });

    it('should generate different signatures for different payloads', () => {
      const sig1 = generateSignature('{"event":"test1"}', secret, timestamp);
      const sig2 = generateSignature('{"event":"test2"}', secret, timestamp);
      
      expect(sig1).not.toBe(sig2);
    });

    it('should generate different signatures for different timestamps', () => {
      const sig1 = generateSignature(payload, secret, timestamp);
      const sig2 = generateSignature(payload, secret, timestamp + 1);
      
      expect(sig1).not.toBe(sig2);
    });

    it('should generate different signatures for different secrets', () => {
      const sig1 = generateSignature(payload, 'secret1', timestamp);
      const sig2 = generateSignature(payload, 'secret2', timestamp);
      
      expect(sig1).not.toBe(sig2);
    });
  });

  describe('verifySignature', () => {
    it('should verify valid signature', () => {
      const signature = generateSignature(payload, secret, timestamp);
      
      // Mock Date.now to return timestamp within tolerance
      const originalNow = Date.now;
      Date.now = () => timestamp * 1000;
      
      const result = verifySignature(payload, signature, secret, timestamp);
      
      Date.now = originalNow;
      
      expect(result).toBe(true);
    });

    it('should reject signature with wrong payload', () => {
      const signature = generateSignature(payload, secret, timestamp);
      
      const originalNow = Date.now;
      Date.now = () => timestamp * 1000;
      
      const result = verifySignature('{"event":"wrong"}', signature, secret, timestamp);
      
      Date.now = originalNow;
      
      expect(result).toBe(false);
    });

    it('should reject signature with wrong secret', () => {
      const signature = generateSignature(payload, secret, timestamp);
      
      const originalNow = Date.now;
      Date.now = () => timestamp * 1000;
      
      const result = verifySignature(payload, signature, 'wrong-secret', timestamp);
      
      Date.now = originalNow;
      
      expect(result).toBe(false);
    });

    it('should reject signature outside tolerance window', () => {
      const signature = generateSignature(payload, secret, timestamp);
      
      // Set current time to 10 minutes after timestamp (outside 5 min tolerance)
      const originalNow = Date.now;
      Date.now = () => (timestamp + 600) * 1000;
      
      const result = verifySignature(payload, signature, secret, timestamp, 300);
      
      Date.now = originalNow;
      
      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// Log Filtering Tests
// ============================================================================

describe('SIEM Log Filtering', () => {
  describe('filterLogs', () => {
    it('should return all logs when no filters configured', () => {
      const logs = [
        createMockAuditLog({ eventType: AuditEventType.LOGIN_SUCCESS }),
        createMockAuditLog({ eventType: AuditEventType.LOGIN_FAILURE }),
        createMockAuditLog({ eventType: AuditEventType.REGISTER })
      ];
      const config = createMockSIEMConfig();
      
      const result = filterLogs(logs, config);
      
      expect(result).toHaveLength(3);
    });

    it('should filter by event types', () => {
      const logs = [
        createMockAuditLog({ eventType: AuditEventType.LOGIN_SUCCESS }),
        createMockAuditLog({ eventType: AuditEventType.LOGIN_FAILURE }),
        createMockAuditLog({ eventType: AuditEventType.REGISTER })
      ];
      const config = createMockSIEMConfig({
        eventTypes: [AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGIN_FAILURE]
      });
      
      const result = filterLogs(logs, config);
      
      expect(result).toHaveLength(2);
      expect(result.map(l => l.eventType)).toContain(AuditEventType.LOGIN_SUCCESS);
      expect(result.map(l => l.eventType)).toContain(AuditEventType.LOGIN_FAILURE);
      expect(result.map(l => l.eventType)).not.toContain(AuditEventType.REGISTER);
    });

    it('should filter by minimum severity', () => {
      const logs = [
        createMockAuditLog({ severity: AuditSeverity.INFO }),
        createMockAuditLog({ severity: AuditSeverity.WARNING }),
        createMockAuditLog({ severity: AuditSeverity.ERROR }),
        createMockAuditLog({ severity: AuditSeverity.CRITICAL })
      ];
      const config = createMockSIEMConfig({
        minSeverity: AuditSeverity.WARNING
      });
      
      const result = filterLogs(logs, config);
      
      expect(result).toHaveLength(3);
      expect(result.map(l => l.severity)).not.toContain(AuditSeverity.INFO);
    });

    it('should combine event type and severity filters', () => {
      const logs = [
        createMockAuditLog({ 
          eventType: AuditEventType.LOGIN_SUCCESS, 
          severity: AuditSeverity.INFO 
        }),
        createMockAuditLog({ 
          eventType: AuditEventType.LOGIN_FAILURE, 
          severity: AuditSeverity.WARNING 
        }),
        createMockAuditLog({ 
          eventType: AuditEventType.ACCOUNT_LOCK, 
          severity: AuditSeverity.ERROR 
        })
      ];
      const config = createMockSIEMConfig({
        eventTypes: [AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGIN_FAILURE],
        minSeverity: AuditSeverity.WARNING
      });
      
      const result = filterLogs(logs, config);
      
      expect(result).toHaveLength(1);
      expect(result[0].eventType).toBe(AuditEventType.LOGIN_FAILURE);
    });
  });
});

// ============================================================================
// Configuration Validation Tests
// ============================================================================

describe('SIEM Configuration Validation', () => {
  describe('validateSIEMConfig', () => {
    it('should validate complete Splunk configuration', () => {
      const config: Partial<SIEMConfig> = {
        provider: SIEMProvider.SPLUNK,
        endpoint: 'https://splunk.example.com:8088/services/collector',
        authType: 'token',
        authToken: 'splunk-hec-token'
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should validate complete Datadog configuration', () => {
      const config: Partial<SIEMConfig> = {
        provider: SIEMProvider.DATADOG,
        authType: 'token',
        datadogApiKey: 'dd-api-key-123'
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject missing provider', () => {
      const config: Partial<SIEMConfig> = {
        endpoint: 'https://example.com',
        authType: 'token',
        authToken: 'token'
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Provider is required');
    });

    it('should reject missing endpoint for non-Datadog providers', () => {
      const config: Partial<SIEMConfig> = {
        provider: SIEMProvider.SPLUNK,
        authType: 'token',
        authToken: 'token'
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Endpoint is required');
    });

    it('should reject non-HTTPS endpoint', () => {
      const config: Partial<SIEMConfig> = {
        provider: SIEMProvider.SPLUNK,
        endpoint: 'http://splunk.example.com',
        authType: 'token',
        authToken: 'token'
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Endpoint must use HTTPS');
    });

    it('should reject missing auth token for token auth', () => {
      const config: Partial<SIEMConfig> = {
        provider: SIEMProvider.SPLUNK,
        endpoint: 'https://splunk.example.com',
        authType: 'token'
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Auth token is required for token authentication');
    });

    it('should reject missing credentials for basic auth', () => {
      const config: Partial<SIEMConfig> = {
        provider: SIEMProvider.GENERIC_WEBHOOK,
        endpoint: 'https://webhook.example.com',
        authType: 'basic',
        authUsername: 'user'
        // Missing password
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Username and password are required for basic authentication');
    });

    it('should reject missing HMAC secret for HMAC auth', () => {
      const config: Partial<SIEMConfig> = {
        provider: SIEMProvider.GENERIC_WEBHOOK,
        endpoint: 'https://webhook.example.com',
        authType: 'hmac'
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('HMAC secret is required for HMAC authentication');
    });

    it('should reject Datadog without API key', () => {
      const config: Partial<SIEMConfig> = {
        provider: SIEMProvider.DATADOG,
        authType: 'token',
        authToken: 'some-token'
        // Missing datadogApiKey
      };
      
      const result = validateSIEMConfig(config);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Datadog API key is required');
    });
  });

  describe('createDefaultSIEMConfig', () => {
    it('should create default Splunk configuration', () => {
      const config = createDefaultSIEMConfig('realm-123', SIEMProvider.SPLUNK);
      
      expect(config.realmId).toBe('realm-123');
      expect(config.provider).toBe(SIEMProvider.SPLUNK);
      expect(config.enabled).toBe(false);
      expect(config.batchSize).toBe(100);
      expect(config.maxRetries).toBe(3);
      expect(config.id).toBeDefined();
      expect(config.createdAt).toBeDefined();
    });

    it('should create default Datadog configuration', () => {
      const config = createDefaultSIEMConfig('realm-456', SIEMProvider.DATADOG);
      
      expect(config.realmId).toBe('realm-456');
      expect(config.provider).toBe(SIEMProvider.DATADOG);
      expect(config.authType).toBe('token');
    });
  });
});

// ============================================================================
// Batch Processing Tests
// ============================================================================

describe('SIEM Batch Processing', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('addToBatch', () => {
    it('should accumulate logs in batch', async () => {
      // Use unique config ID to avoid cross-test pollution
      const config = createMockSIEMConfig({ id: 'batch-test-1', batchSize: 5 });
      const flushedLogs: AuditLogEntry[] = [];
      const onFlush = async (logs: AuditLogEntry[]) => {
        flushedLogs.push(...logs);
      };

      // Add 3 logs (below batch size)
      addToBatch(createMockAuditLog({ id: '1' }), config, onFlush);
      addToBatch(createMockAuditLog({ id: '2' }), config, onFlush);
      addToBatch(createMockAuditLog({ id: '3' }), config, onFlush);

      // Should not flush yet
      expect(flushedLogs).toHaveLength(0);
      
      // Clean up - flush remaining
      await flushBatch(config.id, config, onFlush);
    });

    it('should flush when batch size reached', async () => {
      // Use unique config ID to avoid cross-test pollution
      const config = createMockSIEMConfig({ id: 'batch-test-2', batchSize: 3 });
      const flushedLogs: AuditLogEntry[] = [];
      const onFlush = async (logs: AuditLogEntry[]) => {
        flushedLogs.push(...logs);
      };

      // Add 3 logs (equals batch size)
      addToBatch(createMockAuditLog({ id: '1' }), config, onFlush);
      addToBatch(createMockAuditLog({ id: '2' }), config, onFlush);
      addToBatch(createMockAuditLog({ id: '3' }), config, onFlush);

      // Allow async flush to complete
      await Promise.resolve();

      expect(flushedLogs).toHaveLength(3);
    });
  });

  describe('flushBatch', () => {
    it('should flush accumulated logs', async () => {
      // Use unique config ID to avoid cross-test pollution
      const config = createMockSIEMConfig({ id: 'batch-test-3', batchSize: 100 });
      const flushedLogs: AuditLogEntry[] = [];
      const onFlush = async (logs: AuditLogEntry[]) => {
        flushedLogs.push(...logs);
      };

      // Add logs
      addToBatch(createMockAuditLog({ id: '1' }), config, onFlush);
      addToBatch(createMockAuditLog({ id: '2' }), config, onFlush);

      // Manual flush
      await flushBatch(config.id, config, onFlush);

      expect(flushedLogs).toHaveLength(2);
    });

    it('should handle empty batch gracefully', async () => {
      const config = createMockSIEMConfig({ id: 'batch-test-4' });
      let flushCalled = false;
      const onFlush = async () => {
        flushCalled = true;
      };

      // Flush without adding any logs
      await flushBatch('non-existent-config', config, onFlush);

      expect(flushCalled).toBe(false);
    });
  });
});

// ============================================================================
// Delivery Tests (with mocked fetch)
// ============================================================================

describe('SIEM Delivery', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    // Reset fetch mock
    global.fetch = jest.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  describe('deliverToSIEM', () => {
    it('should deliver logs successfully', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        status: 200
      });

      const logs = [createMockAuditLog()];
      const config = createMockSIEMConfig();

      const result = await deliverToSIEM(logs, config);

      expect(result.success).toBe(true);
      expect(result.eventsDelivered).toBe(1);
      expect(result.eventsFailed).toBe(0);
      expect(result.responseCode).toBe(200);
    });

    it('should return success for empty filtered logs', async () => {
      const logs = [createMockAuditLog({ eventType: AuditEventType.REGISTER })];
      const config = createMockSIEMConfig({
        eventTypes: [AuditEventType.LOGIN_SUCCESS] // Filter out REGISTER
      });

      const result = await deliverToSIEM(logs, config);

      expect(result.success).toBe(true);
      expect(result.eventsDelivered).toBe(0);
      expect(result.eventsFailed).toBe(0);
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('should handle non-retryable errors', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: async () => 'Unauthorized'
      });

      const logs = [createMockAuditLog()];
      const config = createMockSIEMConfig();

      const result = await deliverToSIEM(logs, config);

      expect(result.success).toBe(false);
      expect(result.eventsDelivered).toBe(0);
      expect(result.eventsFailed).toBe(1);
      expect(result.error).toContain('401');
      expect(result.retryCount).toBe(0);
    });

    it('should retry on server errors', async () => {
      // First call fails with 500, second succeeds
      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: false,
          status: 500
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200
        });

      const logs = [createMockAuditLog()];
      const config = createMockSIEMConfig({
        maxRetries: 3,
        retryDelayMs: 10 // Short delay for testing
      });

      const result = await deliverToSIEM(logs, config);

      expect(result.success).toBe(true);
      expect(result.retryCount).toBe(1);
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    it('should use correct Splunk authorization header', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        status: 200
      });

      const logs = [createMockAuditLog()];
      const config = createMockSIEMConfig({
        provider: SIEMProvider.SPLUNK,
        authToken: 'my-splunk-token'
      });

      await deliverToSIEM(logs, config);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Splunk my-splunk-token'
          })
        })
      );
    });

    it('should use correct Datadog API key header', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        status: 200
      });

      const logs = [createMockAuditLog()];
      const config = createMockSIEMConfig({
        provider: SIEMProvider.DATADOG,
        datadogApiKey: 'my-dd-api-key',
        datadogSite: 'datadoghq.eu'
      });

      await deliverToSIEM(logs, config);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://http-intake.logs.datadoghq.eu/api/v2/logs',
        expect.objectContaining({
          headers: expect.objectContaining({
            'DD-API-KEY': 'my-dd-api-key'
          })
        })
      );
    });

    it('should include HMAC signature headers', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        status: 200
      });

      const logs = [createMockAuditLog()];
      const config = createMockSIEMConfig({
        provider: SIEMProvider.GENERIC_WEBHOOK,
        authType: 'hmac',
        hmacSecret: 'my-hmac-secret'
      });

      await deliverToSIEM(logs, config);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Zalt-Timestamp': expect.any(String),
            'X-Zalt-Signature': expect.any(String)
          })
        })
      );
    });
  });
});
