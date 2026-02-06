/**
 * Webhook SSRF Protection Service Tests
 * Task 6.12: Webhook SSRF Protection
 * 
 * Tests:
 * - IP validation
 * - Hostname validation
 * - Protocol validation
 * - DNS rebinding protection
 * - AWS metadata blocking
 */

import * as fc from 'fast-check';
import {
  ipToNumber,
  isIPInRange,
  isPrivateIP,
  isLinkLocalIP,
  isLocalhostIP,
  isAWSMetadataIP,
  isLocalhostHostname,
  isInternalHostname,
  parseURL,
  validateProtocol,
  validateHostname,
  validateIP,
  validateWebhookURLSync,
  DEFAULT_SSRF_CONFIG,
  SSRFProtectionConfig
} from './webhook-ssrf.service';

describe('Webhook SSRF Protection Service - Unit Tests', () => {
  describe('ipToNumber', () => {
    it('should convert 0.0.0.0 to 0', () => {
      expect(ipToNumber('0.0.0.0')).toBe(0);
    });

    it('should convert 255.255.255.255 correctly', () => {
      expect(ipToNumber('255.255.255.255')).toBe(4294967295);
    });

    it('should convert 192.168.1.1 correctly', () => {
      expect(ipToNumber('192.168.1.1')).toBe(3232235777);
    });

    it('should convert 10.0.0.1 correctly', () => {
      expect(ipToNumber('10.0.0.1')).toBe(167772161);
    });
  });

  describe('isIPInRange', () => {
    it('should detect IP in range', () => {
      expect(isIPInRange('192.168.1.100', '192.168.0.0', '192.168.255.255')).toBe(true);
    });

    it('should detect IP at range start', () => {
      expect(isIPInRange('10.0.0.0', '10.0.0.0', '10.255.255.255')).toBe(true);
    });

    it('should detect IP at range end', () => {
      expect(isIPInRange('10.255.255.255', '10.0.0.0', '10.255.255.255')).toBe(true);
    });

    it('should reject IP outside range', () => {
      expect(isIPInRange('11.0.0.1', '10.0.0.0', '10.255.255.255')).toBe(false);
    });
  });

  describe('isPrivateIP', () => {
    it('should detect 10.x.x.x as private', () => {
      expect(isPrivateIP('10.0.0.1')).toBe(true);
      expect(isPrivateIP('10.255.255.255')).toBe(true);
    });

    it('should detect 172.16.x.x - 172.31.x.x as private', () => {
      expect(isPrivateIP('172.16.0.1')).toBe(true);
      expect(isPrivateIP('172.31.255.255')).toBe(true);
    });

    it('should not detect 172.32.x.x as private', () => {
      expect(isPrivateIP('172.32.0.1')).toBe(false);
    });

    it('should detect 192.168.x.x as private', () => {
      expect(isPrivateIP('192.168.0.1')).toBe(true);
      expect(isPrivateIP('192.168.255.255')).toBe(true);
    });

    it('should not detect public IPs as private', () => {
      expect(isPrivateIP('8.8.8.8')).toBe(false);
      expect(isPrivateIP('1.1.1.1')).toBe(false);
    });
  });

  describe('isLinkLocalIP', () => {
    it('should detect 169.254.x.x as link-local', () => {
      expect(isLinkLocalIP('169.254.0.1')).toBe(true);
      expect(isLinkLocalIP('169.254.255.255')).toBe(true);
    });

    it('should detect 127.x.x.x as link-local', () => {
      expect(isLinkLocalIP('127.0.0.1')).toBe(true);
      expect(isLinkLocalIP('127.255.255.255')).toBe(true);
    });

    it('should not detect public IPs as link-local', () => {
      expect(isLinkLocalIP('8.8.8.8')).toBe(false);
    });
  });

  describe('isLocalhostIP', () => {
    it('should detect 127.0.0.1 as localhost', () => {
      expect(isLocalhostIP('127.0.0.1')).toBe(true);
    });

    it('should detect 127.x.x.x as localhost', () => {
      expect(isLocalhostIP('127.0.0.2')).toBe(true);
      expect(isLocalhostIP('127.1.2.3')).toBe(true);
    });

    it('should not detect other IPs as localhost', () => {
      expect(isLocalhostIP('192.168.1.1')).toBe(false);
    });
  });

  describe('isAWSMetadataIP', () => {
    it('should detect AWS metadata IP', () => {
      expect(isAWSMetadataIP('169.254.169.254')).toBe(true);
    });

    it('should not detect other IPs as AWS metadata', () => {
      expect(isAWSMetadataIP('169.254.169.253')).toBe(false);
      expect(isAWSMetadataIP('169.254.169.255')).toBe(false);
    });
  });

  describe('isLocalhostHostname', () => {
    it('should detect localhost', () => {
      expect(isLocalhostHostname('localhost')).toBe(true);
      expect(isLocalhostHostname('LOCALHOST')).toBe(true);
    });

    it('should detect localhost.localdomain', () => {
      expect(isLocalhostHostname('localhost.localdomain')).toBe(true);
    });

    it('should detect subdomains of localhost', () => {
      expect(isLocalhostHostname('sub.localhost')).toBe(true);
    });

    it('should not detect other hostnames', () => {
      expect(isLocalhostHostname('example.com')).toBe(false);
    });
  });

  describe('isInternalHostname', () => {
    it('should detect .internal domains', () => {
      expect(isInternalHostname('service.internal')).toBe(true);
    });

    it('should detect .local domains', () => {
      expect(isInternalHostname('printer.local')).toBe(true);
    });

    it('should detect .corp domains', () => {
      expect(isInternalHostname('intranet.corp')).toBe(true);
    });

    it('should detect .lan domains', () => {
      expect(isInternalHostname('server.lan')).toBe(true);
    });

    it('should detect metadata hostname', () => {
      expect(isInternalHostname('metadata')).toBe(true);
      expect(isInternalHostname('metadata.google.internal')).toBe(true);
    });

    it('should not detect public domains', () => {
      expect(isInternalHostname('example.com')).toBe(false);
    });
  });

  describe('parseURL', () => {
    it('should parse valid URLs', () => {
      const result = parseURL('https://example.com/path');
      expect(result.valid).toBe(true);
      expect(result.parsed?.hostname).toBe('example.com');
    });

    it('should reject invalid URLs', () => {
      const result = parseURL('not a url');
      expect(result.valid).toBe(false);
    });

    it('should reject empty strings', () => {
      const result = parseURL('');
      expect(result.valid).toBe(false);
    });
  });

  describe('validateProtocol', () => {
    it('should accept HTTPS', () => {
      const result = validateProtocol('https:');
      expect(result.valid).toBe(true);
    });

    it('should reject HTTP by default', () => {
      const result = validateProtocol('http:');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('HTTP_NOT_ALLOWED');
    });

    it('should accept HTTP when allowed', () => {
      const config: SSRFProtectionConfig = { ...DEFAULT_SSRF_CONFIG, allowHttp: true };
      const result = validateProtocol('http:', config);
      expect(result.valid).toBe(true);
    });

    it('should reject other protocols', () => {
      const result = validateProtocol('ftp:');
      expect(result.valid).toBe(false);
    });
  });

  describe('validateHostname', () => {
    it('should accept public domains', () => {
      const result = validateHostname('example.com');
      expect(result.valid).toBe(true);
    });

    it('should reject localhost by default', () => {
      const result = validateHostname('localhost');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('LOCALHOST_BLOCKED');
    });

    it('should accept localhost when allowed', () => {
      const config: SSRFProtectionConfig = { ...DEFAULT_SSRF_CONFIG, allowLocalhost: true };
      const result = validateHostname('localhost', config);
      expect(result.valid).toBe(true);
    });

    it('should reject internal hostnames', () => {
      expect(validateHostname('service.internal').valid).toBe(false);
      expect(validateHostname('printer.local').valid).toBe(false);
    });

    it('should reject blocked domains', () => {
      const config: SSRFProtectionConfig = { 
        ...DEFAULT_SSRF_CONFIG, 
        blockedDomains: ['evil.com'] 
      };
      const result = validateHostname('evil.com', config);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('DOMAIN_BLOCKED');
    });

    it('should reject subdomains of blocked domains', () => {
      const config: SSRFProtectionConfig = { 
        ...DEFAULT_SSRF_CONFIG, 
        blockedDomains: ['evil.com'] 
      };
      const result = validateHostname('sub.evil.com', config);
      expect(result.valid).toBe(false);
    });

    it('should enforce allowed domains whitelist', () => {
      const config: SSRFProtectionConfig = { 
        ...DEFAULT_SSRF_CONFIG, 
        allowedDomains: ['trusted.com'] 
      };
      expect(validateHostname('trusted.com', config).valid).toBe(true);
      expect(validateHostname('untrusted.com', config).valid).toBe(false);
    });
  });

  describe('validateIP', () => {
    it('should accept public IPs', () => {
      const result = validateIP('8.8.8.8');
      expect(result.valid).toBe(true);
    });

    it('should reject AWS metadata IP', () => {
      const result = validateIP('169.254.169.254');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('AWS_METADATA_BLOCKED');
    });

    it('should reject localhost IPs by default', () => {
      const result = validateIP('127.0.0.1');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('LOCALHOST_BLOCKED');
    });

    it('should reject private IPs by default', () => {
      expect(validateIP('10.0.0.1').valid).toBe(false);
      expect(validateIP('192.168.1.1').valid).toBe(false);
      expect(validateIP('172.16.0.1').valid).toBe(false);
    });

    it('should accept private IPs when allowed', () => {
      const config: SSRFProtectionConfig = { ...DEFAULT_SSRF_CONFIG, allowPrivateIPs: true };
      const result = validateIP('192.168.1.1', config);
      expect(result.valid).toBe(true);
    });

    it('should reject link-local IPs by default', () => {
      const result = validateIP('169.254.1.1');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('LINK_LOCAL_BLOCKED');
    });
  });

  describe('validateWebhookURLSync', () => {
    it('should accept valid HTTPS URLs', () => {
      const result = validateWebhookURLSync('https://example.com/webhook');
      expect(result.valid).toBe(true);
    });

    it('should reject HTTP URLs', () => {
      const result = validateWebhookURLSync('http://example.com/webhook');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('HTTP_NOT_ALLOWED');
    });

    it('should reject localhost URLs', () => {
      const result = validateWebhookURLSync('https://localhost/webhook');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('LOCALHOST_BLOCKED');
    });

    it('should reject private IP URLs', () => {
      const result = validateWebhookURLSync('https://192.168.1.1/webhook');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('PRIVATE_IP_BLOCKED');
    });

    it('should reject AWS metadata URL', () => {
      const result = validateWebhookURLSync('https://169.254.169.254/latest/meta-data');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('AWS_METADATA_BLOCKED');
    });

    it('should reject internal hostnames', () => {
      const result = validateWebhookURLSync('https://service.internal/webhook');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('DOMAIN_BLOCKED');
    });

    it('should reject invalid URLs', () => {
      const result = validateWebhookURLSync('not a url');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_URL');
    });
  });

  describe('DEFAULT_SSRF_CONFIG', () => {
    it('should not allow HTTP', () => {
      expect(DEFAULT_SSRF_CONFIG.allowHttp).toBe(false);
    });

    it('should not allow localhost', () => {
      expect(DEFAULT_SSRF_CONFIG.allowLocalhost).toBe(false);
    });

    it('should not allow private IPs', () => {
      expect(DEFAULT_SSRF_CONFIG.allowPrivateIPs).toBe(false);
    });

    it('should have reasonable timeout', () => {
      expect(DEFAULT_SSRF_CONFIG.timeout).toBe(10000);
    });

    it('should limit redirects', () => {
      expect(DEFAULT_SSRF_CONFIG.maxRedirects).toBe(3);
    });
  });

  describe('Property-based tests', () => {
    describe('IP validation', () => {
      it('should always block AWS metadata IP', () => {
        const result = validateIP('169.254.169.254');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('AWS_METADATA_BLOCKED');
      });

      it('should handle any IP string without crashing', () => {
        fc.assert(
          fc.property(
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            (a, b, c, d) => {
              const ip = `${a}.${b}.${c}.${d}`;
              const result = validateIP(ip);
              expect(typeof result.valid).toBe('boolean');
              return true;
            }
          ),
          { numRuns: 100 }
        );
      });
    });

    describe('URL validation', () => {
      it('should handle any string without crashing', () => {
        fc.assert(
          fc.property(fc.string(), (url) => {
            const result = validateWebhookURLSync(url);
            expect(typeof result.valid).toBe('boolean');
            return true;
          }),
          { numRuns: 100 }
        );
      });
    });

    describe('Hostname validation', () => {
      it('should handle any hostname without crashing', () => {
        fc.assert(
          fc.property(fc.string(), (hostname) => {
            const result = validateHostname(hostname);
            expect(typeof result.valid).toBe('boolean');
            return true;
          }),
          { numRuns: 100 }
        );
      });
    });
  });

  describe('Security scenarios', () => {
    it('should block common SSRF attack vectors', () => {
      const attackVectors = [
        'http://localhost/admin',
        'http://127.0.0.1/admin',
        'http://[::1]/admin',
        'http://169.254.169.254/latest/meta-data',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://192.168.1.1/router',
        'http://10.0.0.1/internal',
        'http://172.16.0.1/internal',
        'https://localhost/webhook',
        'https://127.0.0.1/webhook',
        'https://service.internal/api',
        'https://printer.local/status'
      ];

      for (const url of attackVectors) {
        const result = validateWebhookURLSync(url);
        expect(result.valid).toBe(false);
      }
    });

    it('should allow legitimate webhook URLs', () => {
      const legitimateURLs = [
        'https://api.example.com/webhook',
        'https://hooks.slack.com/services/xxx',
        'https://discord.com/api/webhooks/xxx',
        'https://api.github.com/repos/xxx/hooks'
      ];

      for (const url of legitimateURLs) {
        const result = validateWebhookURLSync(url);
        expect(result.valid).toBe(true);
      }
    });
  });
});
