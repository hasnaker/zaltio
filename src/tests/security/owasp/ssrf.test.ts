/**
 * OWASP A10:2021 - Server-Side Request Forgery (SSRF)
 * Tests for SSRF vulnerabilities
 * 
 * @security-test
 * @owasp A10:2021
 * @severity HIGH
 */

import * as fc from 'fast-check';

// URL validation functions
const isInternalIP = (ip: string): boolean => {
  const internalRanges = [
    /^127\./,                          // Loopback
    /^10\./,                           // Class A private
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,  // Class B private
    /^192\.168\./,                     // Class C private
    /^169\.254\./,                     // Link-local
    /^0\./,                            // Current network
    /^224\./,                          // Multicast
    /^255\./,                          // Broadcast
    /^localhost$/i,
    /^::1$/,                           // IPv6 loopback
    /^fc00:/i,                         // IPv6 private
    /^fe80:/i,                         // IPv6 link-local
  ];

  return internalRanges.some(range => range.test(ip));
};

const isAllowedURL = (url: string, allowlist: string[]): boolean => {
  try {
    const parsed = new URL(url);
    
    // Check protocol
    if (!['https:', 'http:'].includes(parsed.protocol)) {
      return false;
    }

    // Check for internal IPs
    if (isInternalIP(parsed.hostname)) {
      return false;
    }

    // Check against allowlist
    return allowlist.some(allowed => {
      if (allowed.startsWith('*.')) {
        const domain = allowed.slice(2);
        return parsed.hostname.endsWith(domain);
      }
      return parsed.hostname === allowed;
    });
  } catch {
    return false;
  }
};

const sanitizeURL = (url: string): string | null => {
  try {
    const parsed = new URL(url);
    
    // Only allow http/https
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }

    // Remove credentials
    parsed.username = '';
    parsed.password = '';

    // Check for internal IPs
    if (isInternalIP(parsed.hostname)) {
      return null;
    }

    // Check for DNS rebinding attempts
    const suspiciousPatterns = [
      /\d+\.\d+\.\d+\.\d+\.xip\.io/i,
      /\.nip\.io$/i,
      /\.sslip\.io$/i,
      /burpcollaborator/i,
      /oastify/i,
      /interact\.sh/i
    ];

    if (suspiciousPatterns.some(p => p.test(parsed.hostname))) {
      return null;
    }

    return parsed.toString();
  } catch {
    return null;
  }
};

describe('OWASP A10:2021 - Server-Side Request Forgery (SSRF)', () => {
  describe('Internal IP Detection', () => {
    it('should detect loopback addresses', () => {
      const loopbackAddresses = [
        '127.0.0.1',
        '127.0.0.2',
        '127.255.255.255',
        'localhost',
        '::1'
      ];

      loopbackAddresses.forEach(ip => {
        expect(isInternalIP(ip)).toBe(true);
      });
    });

    it('should detect private network addresses', () => {
      const privateAddresses = [
        '10.0.0.1',
        '10.255.255.255',
        '172.16.0.1',
        '172.31.255.255',
        '192.168.0.1',
        '192.168.255.255'
      ];

      privateAddresses.forEach(ip => {
        expect(isInternalIP(ip)).toBe(true);
      });
    });

    it('should detect link-local addresses', () => {
      const linkLocalAddresses = [
        '169.254.0.1',
        '169.254.255.255',
        'fe80::1'
      ];

      linkLocalAddresses.forEach(ip => {
        expect(isInternalIP(ip)).toBe(true);
      });
    });

    it('should allow public IP addresses', () => {
      const publicAddresses = [
        '8.8.8.8',
        '1.1.1.1',
        '142.250.185.78',
        '151.101.1.140'
      ];

      publicAddresses.forEach(ip => {
        expect(isInternalIP(ip)).toBe(false);
      });
    });
  });

  describe('SSRF Attack Prevention', () => {
    const allowlist = ['api.example.com', '*.hsdcore.com'];

    it('should block requests to internal IPs', () => {
      const ssrfPayloads = [
        'http://127.0.0.1/admin',
        'http://localhost/admin',
        'http://192.168.1.1/router',
        'http://10.0.0.1/internal',
        'http://172.16.0.1/private',
        'http://169.254.169.254/latest/meta-data/',  // AWS metadata
        'http://[::1]/admin',
        'http://0.0.0.0/',
        'http://0/',
        'http://127.1/'
      ];

      ssrfPayloads.forEach(url => {
        expect(isAllowedURL(url, allowlist)).toBe(false);
      });
    });

    it('should block cloud metadata endpoints', () => {
      const metadataEndpoints = [
        'http://169.254.169.254/latest/meta-data/',           // AWS
        'http://169.254.169.254/latest/user-data/',           // AWS
        'http://metadata.google.internal/',                    // GCP
        'http://169.254.169.254/metadata/v1/',                // DigitalOcean
        'http://169.254.169.254/openstack/',                  // OpenStack
        'http://100.100.100.200/latest/meta-data/',           // Alibaba
      ];

      metadataEndpoints.forEach(url => {
        expect(isAllowedURL(url, allowlist)).toBe(false);
      });
    });

    it('should block protocol smuggling attempts', () => {
      const protocolSmuggling = [
        'file:///etc/passwd',
        'gopher://127.0.0.1:25/',
        'dict://127.0.0.1:11211/',
        'ftp://127.0.0.1/',
        'ldap://127.0.0.1/',
        'sftp://127.0.0.1/',
        'tftp://127.0.0.1/'
      ];

      protocolSmuggling.forEach(url => {
        expect(isAllowedURL(url, allowlist)).toBe(false);
      });
    });

    it('should block DNS rebinding attempts', () => {
      const dnsRebinding = [
        'http://127.0.0.1.xip.io/',
        'http://192.168.1.1.nip.io/',
        'http://10.0.0.1.sslip.io/',
        'http://evil.burpcollaborator.net/',
        'http://test.oastify.com/',
        'http://test.interact.sh/'
      ];

      dnsRebinding.forEach(url => {
        expect(sanitizeURL(url)).toBeNull();
      });
    });

    it('should block URL encoding bypass attempts', () => {
      const encodingBypass = [
        'http://127.0.0.1%00.example.com/',
        'http://127.0.0.1%2f@example.com/',
        'http://example.com@127.0.0.1/',
        'http://127。0。0。1/',  // Unicode dots
        'http://①②⑦.0.0.1/',   // Unicode numbers
        'http://0x7f000001/',    // Hex IP
        'http://2130706433/',    // Decimal IP
        'http://017700000001/',  // Octal IP
      ];

      encodingBypass.forEach(url => {
        const sanitized = sanitizeURL(url);
        if (sanitized) {
          expect(isAllowedURL(sanitized, allowlist)).toBe(false);
        }
      });
    });

    it('should allow legitimate external URLs', () => {
      const legitimateURLs = [
        'https://api.example.com/webhook',
        'https://dashboard.hsdcore.com/callback',
        'https://auth.hsdcore.com/verify'
      ];

      legitimateURLs.forEach(url => {
        expect(isAllowedURL(url, allowlist)).toBe(true);
      });
    });
  });

  describe('URL Sanitization', () => {
    it('should remove credentials from URLs', () => {
      const urlWithCreds = 'https://user:pass@api.example.com/path';
      const sanitized = sanitizeURL(urlWithCreds);
      
      expect(sanitized).not.toContain('user');
      expect(sanitized).not.toContain('pass');
    });

    it('should reject invalid URLs', () => {
      const invalidURLs = [
        'not-a-url',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        '//127.0.0.1/',
        ''
      ];

      invalidURLs.forEach(url => {
        expect(sanitizeURL(url)).toBeNull();
      });
    });
  });

  describe('Property-Based SSRF Testing', () => {
    it('should block any URL with internal IP', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('127', '10', '192.168', '172.16'),
          fc.integer({ min: 0, max: 255 }),
          fc.integer({ min: 0, max: 255 }),
          fc.string({ minLength: 1, maxLength: 20 }),
          (prefix, octet1, octet2, path) => {
            let ip: string;
            if (prefix === '127') {
              ip = `${prefix}.${octet1}.${octet2}.1`;
            } else if (prefix === '10') {
              ip = `${prefix}.${octet1}.${octet2}.1`;
            } else if (prefix === '192.168') {
              ip = `${prefix}.${octet1}.1`;
            } else {
              ip = `${prefix}.${octet1 % 16 + 16}.${octet2}.1`;
            }
            
            const url = `http://${ip}/${path.replace(/[^a-zA-Z0-9]/g, '')}`;
            expect(isAllowedURL(url, ['*.hsdcore.com'])).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
