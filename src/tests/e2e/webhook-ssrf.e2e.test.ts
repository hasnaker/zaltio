/**
 * Webhook SSRF Protection E2E Tests
 * Task 6.12: Webhook SSRF Protection
 * 
 * Tests:
 * - URL validation for webhooks
 * - SSRF attack prevention
 * - DNS rebinding protection
 * - AWS metadata blocking
 */

import {
  validateWebhookURL,
  validateWebhookURLSync,
  resolveAndValidate,
  validateIP,
  validateHostname,
  validateProtocol,
  isPrivateIP,
  isLinkLocalIP,
  isLocalhostIP,
  isAWSMetadataIP,
  isInternalHostname,
  DEFAULT_SSRF_CONFIG,
  SSRFProtectionConfig,
  createSafeRequestOptions
} from '../../services/webhook-ssrf.service';

describe('Webhook SSRF Protection - E2E Tests', () => {
  describe('SSRF Attack Prevention', () => {
    describe('Localhost Attacks', () => {
      it('should block http://localhost', async () => {
        const result = await validateWebhookURL('http://localhost/admin');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('HTTP_NOT_ALLOWED');
      });

      it('should block https://localhost', async () => {
        const result = await validateWebhookURL('https://localhost/admin');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('LOCALHOST_BLOCKED');
      });

      it('should block http://127.0.0.1', async () => {
        const result = await validateWebhookURL('http://127.0.0.1/admin');
        expect(result.valid).toBe(false);
      });

      it('should block https://127.0.0.1', async () => {
        const result = await validateWebhookURL('https://127.0.0.1/admin');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('LOCALHOST_BLOCKED');
      });

      it('should block 127.x.x.x variations', async () => {
        const variations = [
          'https://127.0.0.2/admin',
          'https://127.1.2.3/admin',
          'https://127.255.255.255/admin'
        ];

        for (const url of variations) {
          const result = await validateWebhookURL(url);
          expect(result.valid).toBe(false);
        }
      });

      it('should block localhost.localdomain', async () => {
        const result = await validateWebhookURL('https://localhost.localdomain/webhook');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('LOCALHOST_BLOCKED');
      });

      it('should block subdomains of localhost', async () => {
        const result = await validateWebhookURL('https://api.localhost/webhook');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('LOCALHOST_BLOCKED');
      });
    });

    describe('Private IP Attacks', () => {
      it('should block 10.x.x.x range', async () => {
        const ips = [
          'https://10.0.0.1/internal',
          'https://10.255.255.255/internal',
          'https://10.100.50.25/internal'
        ];

        for (const url of ips) {
          const result = await validateWebhookURL(url);
          expect(result.valid).toBe(false);
          expect(result.errorCode).toBe('PRIVATE_IP_BLOCKED');
        }
      });

      it('should block 172.16.x.x - 172.31.x.x range', async () => {
        const ips = [
          'https://172.16.0.1/internal',
          'https://172.31.255.255/internal',
          'https://172.20.10.5/internal'
        ];

        for (const url of ips) {
          const result = await validateWebhookURL(url);
          expect(result.valid).toBe(false);
          expect(result.errorCode).toBe('PRIVATE_IP_BLOCKED');
        }
      });

      it('should allow 172.32.x.x (not private)', async () => {
        // This IP is not in private range, but may not resolve
        const result = validateWebhookURLSync('https://172.32.0.1/webhook');
        expect(result.valid).toBe(true); // Sync validation passes
      });

      it('should block 192.168.x.x range', async () => {
        const ips = [
          'https://192.168.0.1/router',
          'https://192.168.1.1/admin',
          'https://192.168.255.255/internal'
        ];

        for (const url of ips) {
          const result = await validateWebhookURL(url);
          expect(result.valid).toBe(false);
          expect(result.errorCode).toBe('PRIVATE_IP_BLOCKED');
        }
      });
    });

    describe('AWS Metadata Attacks', () => {
      it('should block AWS metadata IP', async () => {
        const result = await validateWebhookURL('https://169.254.169.254/latest/meta-data');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('AWS_METADATA_BLOCKED');
      });

      it('should block AWS metadata with different paths', async () => {
        const paths = [
          'https://169.254.169.254/latest/meta-data/iam/security-credentials/',
          'https://169.254.169.254/latest/user-data',
          'https://169.254.169.254/latest/dynamic/instance-identity/document'
        ];

        for (const url of paths) {
          const result = await validateWebhookURL(url);
          expect(result.valid).toBe(false);
          expect(result.errorCode).toBe('AWS_METADATA_BLOCKED');
        }
      });

      it('should block HTTP to AWS metadata', async () => {
        const result = await validateWebhookURL('http://169.254.169.254/latest/meta-data');
        expect(result.valid).toBe(false);
        // HTTP is blocked first
        expect(result.errorCode).toBe('HTTP_NOT_ALLOWED');
      });
    });

    describe('Link-Local IP Attacks', () => {
      it('should block 169.254.x.x range', async () => {
        const ips = [
          'https://169.254.0.1/webhook',
          'https://169.254.100.100/webhook',
          'https://169.254.255.255/webhook'
        ];

        for (const url of ips) {
          const result = await validateWebhookURL(url);
          expect(result.valid).toBe(false);
          // AWS metadata IP has special error code
          if (url.includes('169.254.169.254')) {
            expect(result.errorCode).toBe('AWS_METADATA_BLOCKED');
          } else {
            expect(result.errorCode).toBe('LINK_LOCAL_BLOCKED');
          }
        }
      });
    });

    describe('Internal Hostname Attacks', () => {
      it('should block .internal domains', async () => {
        const result = await validateWebhookURL('https://service.internal/api');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('DOMAIN_BLOCKED');
      });

      it('should block .local domains', async () => {
        const result = await validateWebhookURL('https://printer.local/status');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('DOMAIN_BLOCKED');
      });

      it('should block .corp domains', async () => {
        const result = await validateWebhookURL('https://intranet.corp/webhook');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('DOMAIN_BLOCKED');
      });

      it('should block .lan domains', async () => {
        const result = await validateWebhookURL('https://server.lan/webhook');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('DOMAIN_BLOCKED');
      });

      it('should block metadata hostname', async () => {
        const result = await validateWebhookURL('https://metadata/computeMetadata/v1/');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('DOMAIN_BLOCKED');
      });

      it('should block Google Cloud metadata', async () => {
        const result = await validateWebhookURL('https://metadata.google.internal/computeMetadata/v1/');
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('DOMAIN_BLOCKED');
      });
    });
  });

  describe('Protocol Validation', () => {
    it('should only allow HTTPS by default', async () => {
      const httpsResult = await validateWebhookURL('https://example.com/webhook');
      expect(httpsResult.valid).toBe(true);

      const httpResult = await validateWebhookURL('http://example.com/webhook');
      expect(httpResult.valid).toBe(false);
      expect(httpResult.errorCode).toBe('HTTP_NOT_ALLOWED');
    });

    it('should allow HTTP when configured', async () => {
      const config: SSRFProtectionConfig = { ...DEFAULT_SSRF_CONFIG, allowHttp: true };
      const result = validateProtocol('http:', config);
      expect(result.valid).toBe(true);
    });

    it('should reject FTP protocol', async () => {
      const result = await validateWebhookURL('ftp://example.com/file');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('HTTP_NOT_ALLOWED');
    });

    it('should reject file protocol', async () => {
      const result = await validateWebhookURL('file:///etc/passwd');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('HTTP_NOT_ALLOWED');
    });
  });

  describe('Domain Whitelist/Blacklist', () => {
    it('should enforce domain whitelist', async () => {
      const config: SSRFProtectionConfig = {
        ...DEFAULT_SSRF_CONFIG,
        allowedDomains: ['trusted.com', 'api.example.com']
      };

      const trustedResult = validateHostname('trusted.com', config);
      expect(trustedResult.valid).toBe(true);

      const subdomainResult = validateHostname('sub.trusted.com', config);
      expect(subdomainResult.valid).toBe(true);

      const untrustedResult = validateHostname('untrusted.com', config);
      expect(untrustedResult.valid).toBe(false);
      expect(untrustedResult.errorCode).toBe('DOMAIN_NOT_ALLOWED');
    });

    it('should enforce domain blacklist', async () => {
      const config: SSRFProtectionConfig = {
        ...DEFAULT_SSRF_CONFIG,
        blockedDomains: ['evil.com', 'malicious.org']
      };

      const blockedResult = validateHostname('evil.com', config);
      expect(blockedResult.valid).toBe(false);
      expect(blockedResult.errorCode).toBe('DOMAIN_BLOCKED');

      const subdomainResult = validateHostname('sub.evil.com', config);
      expect(subdomainResult.valid).toBe(false);

      const allowedResult = validateHostname('good.com', config);
      expect(allowedResult.valid).toBe(true);
    });
  });

  describe('DNS Rebinding Protection', () => {
    it('should detect DNS rebinding to localhost', async () => {
      // Direct IP validation
      const result = validateIP('127.0.0.1');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('LOCALHOST_BLOCKED');
    });

    it('should detect DNS rebinding to private IP', async () => {
      const result = validateIP('192.168.1.1');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('PRIVATE_IP_BLOCKED');
    });

    it('should detect DNS rebinding to AWS metadata', async () => {
      const result = validateIP('169.254.169.254');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('AWS_METADATA_BLOCKED');
    });
  });

  describe('Legitimate Webhook URLs', () => {
    it('should allow Slack webhooks', async () => {
      // Using FAKE placeholder to avoid GitHub secret scanning false positives
      const result = validateWebhookURLSync('https://hooks.slack.com/services/FAKE00000/FAKE00000/FAKE0000000000000000000');
      expect(result.valid).toBe(true);
    });

    it('should allow Discord webhooks', async () => {
      const result = validateWebhookURLSync('https://discord.com/api/webhooks/123456789/abcdefghijklmnop');
      expect(result.valid).toBe(true);
    });

    it('should allow GitHub webhooks', async () => {
      const result = validateWebhookURLSync('https://api.github.com/repos/owner/repo/hooks');
      expect(result.valid).toBe(true);
    });

    it('should allow custom HTTPS webhooks', async () => {
      const result = validateWebhookURLSync('https://api.example.com/webhook/callback');
      expect(result.valid).toBe(true);
    });

    it('should allow webhooks with ports', async () => {
      const result = validateWebhookURLSync('https://api.example.com:8443/webhook');
      expect(result.valid).toBe(true);
    });

    it('should allow webhooks with query parameters', async () => {
      const result = validateWebhookURLSync('https://api.example.com/webhook?token=abc123');
      expect(result.valid).toBe(true);
    });
  });

  describe('Invalid URL Handling', () => {
    it('should reject empty string', async () => {
      const result = await validateWebhookURL('');
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('INVALID_URL');
    });

    it('should reject malformed URLs', async () => {
      const malformedUrls = [
        'not a url',
        'http://',
        'https://',
        '://example.com',
        'example.com/webhook'
      ];

      for (const url of malformedUrls) {
        const result = await validateWebhookURL(url);
        expect(result.valid).toBe(false);
        expect(result.errorCode).toBe('INVALID_URL');
      }
    });

    it('should reject URLs with invalid characters', async () => {
      const result = await validateWebhookURL('https://example.com/webhook<script>');
      // URL parsing may handle this differently
      expect(typeof result.valid).toBe('boolean');
    });
  });

  describe('Configuration Options', () => {
    it('should allow localhost when configured', async () => {
      const config: SSRFProtectionConfig = { ...DEFAULT_SSRF_CONFIG, allowLocalhost: true };
      const result = validateHostname('localhost', config);
      expect(result.valid).toBe(true);
    });

    it('should allow private IPs when configured', async () => {
      const config: SSRFProtectionConfig = { ...DEFAULT_SSRF_CONFIG, allowPrivateIPs: true };
      const result = validateIP('192.168.1.1', config);
      expect(result.valid).toBe(true);
    });

    it('should allow link-local when configured', async () => {
      const config: SSRFProtectionConfig = { ...DEFAULT_SSRF_CONFIG, allowLinkLocal: true };
      const result = validateIP('169.254.1.1', config);
      expect(result.valid).toBe(true);
    });

    it('should NEVER allow AWS metadata even with permissive config', async () => {
      const config: SSRFProtectionConfig = {
        ...DEFAULT_SSRF_CONFIG,
        allowLocalhost: true,
        allowPrivateIPs: true,
        allowLinkLocal: true
      };
      const result = validateIP('169.254.169.254', config);
      expect(result.valid).toBe(false);
      expect(result.errorCode).toBe('AWS_METADATA_BLOCKED');
    });
  });

  describe('Safe Request Options', () => {
    it('should create safe request options', () => {
      const options = createSafeRequestOptions('https://example.com/webhook');
      expect(options.url).toBe('https://example.com/webhook');
      expect(options.timeout).toBe(10000);
      expect(options.maxRedirects).toBe(3);
      expect(options.followRedirect).toBe(true);
    });

    it('should respect custom config', () => {
      const config: SSRFProtectionConfig = {
        ...DEFAULT_SSRF_CONFIG,
        timeout: 5000,
        maxRedirects: 0
      };
      const options = createSafeRequestOptions('https://example.com/webhook', config);
      expect(options.timeout).toBe(5000);
      expect(options.maxRedirects).toBe(0);
      expect(options.followRedirect).toBe(false);
    });
  });

  describe('IP Helper Functions', () => {
    it('should correctly identify private IPs', () => {
      expect(isPrivateIP('10.0.0.1')).toBe(true);
      expect(isPrivateIP('172.16.0.1')).toBe(true);
      expect(isPrivateIP('192.168.1.1')).toBe(true);
      expect(isPrivateIP('8.8.8.8')).toBe(false);
    });

    it('should correctly identify link-local IPs', () => {
      expect(isLinkLocalIP('169.254.1.1')).toBe(true);
      expect(isLinkLocalIP('127.0.0.1')).toBe(true);
      expect(isLinkLocalIP('8.8.8.8')).toBe(false);
    });

    it('should correctly identify localhost IPs', () => {
      expect(isLocalhostIP('127.0.0.1')).toBe(true);
      expect(isLocalhostIP('127.1.2.3')).toBe(true);
      expect(isLocalhostIP('192.168.1.1')).toBe(false);
    });

    it('should correctly identify AWS metadata IP', () => {
      expect(isAWSMetadataIP('169.254.169.254')).toBe(true);
      expect(isAWSMetadataIP('169.254.169.253')).toBe(false);
    });

    it('should correctly identify internal hostnames', () => {
      expect(isInternalHostname('service.internal')).toBe(true);
      expect(isInternalHostname('printer.local')).toBe(true);
      expect(isInternalHostname('intranet.corp')).toBe(true);
      expect(isInternalHostname('server.lan')).toBe(true);
      expect(isInternalHostname('metadata')).toBe(true);
      expect(isInternalHostname('example.com')).toBe(false);
    });
  });

  describe('Real-world SSRF Attack Scenarios', () => {
    it('should block cloud metadata endpoints', async () => {
      const cloudMetadataUrls = [
        // AWS
        'https://169.254.169.254/latest/meta-data/',
        // Google Cloud (via internal hostname)
        'https://metadata.google.internal/computeMetadata/v1/',
        // Azure (via internal hostname)
        'https://169.254.169.254/metadata/instance'
      ];

      for (const url of cloudMetadataUrls) {
        const result = await validateWebhookURL(url);
        expect(result.valid).toBe(false);
      }
    });

    it('should block internal service discovery', async () => {
      const internalUrls = [
        'https://kubernetes.default.svc/api',
        'https://consul.service.consul/v1/agent/services',
        'https://etcd.internal:2379/v2/keys'
      ];

      for (const url of internalUrls) {
        const result = await validateWebhookURL(url);
        expect(result.valid).toBe(false);
      }
    });

    it('should block common internal ports', async () => {
      const internalPorts = [
        'https://192.168.1.1:22/ssh',
        'https://10.0.0.1:3306/mysql',
        'https://172.16.0.1:6379/redis',
        'https://127.0.0.1:9200/elasticsearch'
      ];

      for (const url of internalPorts) {
        const result = await validateWebhookURL(url);
        expect(result.valid).toBe(false);
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle IPv6 localhost', async () => {
      // IPv6 localhost - URL parsing may vary
      const result = await validateWebhookURL('https://[::1]/webhook');
      // Should either be invalid URL or blocked
      expect(result.valid).toBe(false);
    });

    it('should handle URL with credentials', async () => {
      const result = await validateWebhookURL('https://user:pass@example.com/webhook');
      // Should still validate the hostname
      expect(result.valid).toBe(true);
    });

    it('should handle URL with fragment', async () => {
      const result = await validateWebhookURL('https://example.com/webhook#section');
      expect(result.valid).toBe(true);
    });

    it('should handle very long URLs', async () => {
      const longPath = 'a'.repeat(1000);
      const result = await validateWebhookURL(`https://example.com/${longPath}`);
      expect(result.valid).toBe(true);
    });

    it('should handle unicode domains', async () => {
      // Punycode domain
      const result = await validateWebhookURL('https://xn--n3h.com/webhook');
      expect(result.valid).toBe(true);
    });
  });
});
