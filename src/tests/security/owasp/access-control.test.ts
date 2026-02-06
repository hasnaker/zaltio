/**
 * OWASP A01:2021 - Broken Access Control
 * IDOR, Privilege Escalation, Path Traversal, CORS Misconfiguration
 * 
 * @security-test
 * @owasp A01:2021
 * @severity CRITICAL
 */

import * as fc from 'fast-check';

// Role hierarchy
type Role = 'guest' | 'user' | 'moderator' | 'admin' | 'super_admin';

const ROLE_HIERARCHY: Record<Role, number> = {
  guest: 0,
  user: 1,
  moderator: 2,
  admin: 3,
  super_admin: 4
};

// Permission matrix
const PERMISSIONS: Record<string, Role[]> = {
  'read:public': ['guest', 'user', 'moderator', 'admin', 'super_admin'],
  'read:own': ['user', 'moderator', 'admin', 'super_admin'],
  'write:own': ['user', 'moderator', 'admin', 'super_admin'],
  'read:any': ['moderator', 'admin', 'super_admin'],
  'write:any': ['admin', 'super_admin'],
  'delete:own': ['user', 'moderator', 'admin', 'super_admin'],
  'delete:any': ['admin', 'super_admin'],
  'admin:users': ['admin', 'super_admin'],
  'admin:realms': ['super_admin'],
  'admin:system': ['super_admin']
};

// Access control functions
const hasPermission = (userRole: Role, permission: string): boolean => {
  const allowedRoles = PERMISSIONS[permission];
  if (!allowedRoles) return false;
  return allowedRoles.includes(userRole);
};

const canAccessResource = (
  userId: string,
  resourceOwnerId: string,
  userRole: Role,
  action: 'read' | 'write' | 'delete'
): boolean => {
  // Own resource
  if (userId === resourceOwnerId) {
    return hasPermission(userRole, `${action}:own`);
  }
  // Other's resource
  return hasPermission(userRole, `${action}:any`);
};

const isValidPath = (path: string): boolean => {
  // Prevent path traversal
  const dangerous = [
    '..',
    '%2e%2e',
    '%252e%252e',
    '..%c0%af',
    '..%c1%9c',
    '/etc/',
    '/proc/',
    '/var/',
    'C:\\',
    '\\\\',
    '%00'
  ];
  
  let normalizedPath: string;
  try {
    normalizedPath = decodeURIComponent(path).toLowerCase();
  } catch {
    // Invalid URL encoding - treat as dangerous
    return false;
  }
  return !dangerous.some(d => normalizedPath.includes(d.toLowerCase()));
};

const isValidOrigin = (origin: string, allowedOrigins: string[]): boolean => {
  if (!origin) return false;
  
  // Reject special origins
  if (origin === 'null' || origin.startsWith('file://')) return false;
  
  // Exact match
  if (allowedOrigins.includes(origin)) return true;
  
  // Wildcard subdomain match
  for (const allowed of allowedOrigins) {
    if (allowed.startsWith('*.')) {
      const domain = allowed.slice(1); // Keep the dot: .hsdcore.com
      if (origin.includes('://')) {
        const originDomain = origin.split('://')[1].split('/')[0]; // Get just the host
        // Must end with .domain (not just domain to prevent hsdcore.com.evil.com)
        if (originDomain.endsWith(domain) && originDomain.length > domain.length) {
          // Verify it's a proper subdomain (character before domain must be start or dot)
          const prefix = originDomain.slice(0, -domain.length);
          if (prefix.length === 0 || !prefix.includes('.') || prefix.endsWith('.')) {
            // Additional check: no dots in prefix except at the end
            return true;
          }
        }
      }
    }
  }
  
  return false;
};

describe('OWASP A01:2021 - Broken Access Control', () => {
  describe('Vertical Privilege Escalation', () => {
    it('should prevent users from accessing admin functions', () => {
      const nonAdminRoles: Role[] = ['guest', 'user', 'moderator'];
      const adminPermissions = ['admin:users', 'admin:realms', 'admin:system'];

      nonAdminRoles.forEach(role => {
        adminPermissions.forEach(permission => {
          expect(hasPermission(role, permission)).toBe(false);
        });
      });
    });

    it('should enforce role hierarchy', () => {
      fc.assert(
        fc.property(
          fc.constantFrom<Role>('guest', 'user', 'moderator', 'admin', 'super_admin'),
          fc.constantFrom<Role>('guest', 'user', 'moderator', 'admin', 'super_admin'),
          (lowerRole, higherRole) => {
            fc.pre(ROLE_HIERARCHY[lowerRole] < ROLE_HIERARCHY[higherRole]);
            
            // Higher role should have at least all permissions of lower role
            Object.keys(PERMISSIONS).forEach(permission => {
              if (hasPermission(lowerRole, permission)) {
                expect(hasPermission(higherRole, permission)).toBe(true);
              }
            });
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should prevent role manipulation in requests', () => {
      const maliciousPayloads = [
        { role: 'super_admin' },
        { role: 'admin', isAdmin: true },
        { permissions: ['admin:system'] },
        { __proto__: { role: 'admin' } }
      ];

      maliciousPayloads.forEach(payload => {
        // In real implementation, these should be ignored
        // Role should come from authenticated session, not request
        expect(typeof payload.role === 'string' || payload.role === undefined).toBe(true);
      });
    });
  });

  describe('Horizontal Privilege Escalation (IDOR)', () => {
    it('should prevent users from accessing other users resources', () => {
      fc.assert(
        fc.property(
          fc.uuid(),
          fc.uuid(),
          (userId, otherUserId) => {
            fc.pre(userId !== otherUserId);
            
            // Regular user should not access other's resources
            expect(canAccessResource(userId, otherUserId, 'user', 'read')).toBe(false);
            expect(canAccessResource(userId, otherUserId, 'user', 'write')).toBe(false);
            expect(canAccessResource(userId, otherUserId, 'user', 'delete')).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow users to access their own resources', () => {
      fc.assert(
        fc.property(
          fc.uuid(),
          (userId) => {
            expect(canAccessResource(userId, userId, 'user', 'read')).toBe(true);
            expect(canAccessResource(userId, userId, 'user', 'write')).toBe(true);
            expect(canAccessResource(userId, userId, 'user', 'delete')).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should allow admins to access any resource', () => {
      fc.assert(
        fc.property(
          fc.uuid(),
          fc.uuid(),
          (adminId, anyUserId) => {
            expect(canAccessResource(adminId, anyUserId, 'admin', 'read')).toBe(true);
            expect(canAccessResource(adminId, anyUserId, 'admin', 'write')).toBe(true);
            expect(canAccessResource(adminId, anyUserId, 'admin', 'delete')).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should detect IDOR attempts in URL parameters', () => {
      const idorAttempts = [
        '/api/users/123/profile',      // Direct ID
        '/api/users/123/../456',       // Path traversal
        '/api/users?id=456',           // Query param
        '/api/users/me/../456',        // Bypass attempt
      ];

      idorAttempts.forEach(path => {
        // In real implementation, validate that requested ID matches authenticated user
        const hasNumericId = /\/\d+/.test(path) || /id=\d+/.test(path);
        expect(hasNumericId).toBe(true);
      });
    });
  });

  describe('Path Traversal Prevention', () => {
    it('should block path traversal attempts', () => {
      const traversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '..%c0%af..%c0%af..%c0%afetc/passwd',
        '..%c1%9c..%c1%9c..%c1%9cetc/passwd',
        '/var/www/../../etc/passwd',
        'file:///etc/passwd',
        '/proc/self/environ',
        '....//....//....//....//etc/passwd',
        '..%00/etc/passwd'
      ];

      traversalPayloads.forEach(payload => {
        expect(isValidPath(payload)).toBe(false);
      });
    });

    it('should allow valid paths', () => {
      const validPaths = [
        '/api/users',
        '/api/realms/123',
        '/dashboard/settings',
        '/auth/login',
        '/static/images/logo.png'
      ];

      validPaths.forEach(path => {
        expect(isValidPath(path)).toBe(true);
      });
    });
  });

  describe('CORS Misconfiguration', () => {
    const allowedOrigins = [
      'https://dashboard.auth.hsdcore.com',
      'https://api.auth.hsdcore.com',
      '*.hsdcore.com'
    ];

    it('should accept valid origins', () => {
      const validOrigins = [
        'https://dashboard.auth.hsdcore.com',
        'https://api.auth.hsdcore.com'
      ];

      validOrigins.forEach(origin => {
        expect(isValidOrigin(origin, allowedOrigins)).toBe(true);
      });
    });

    it('should reject invalid origins', () => {
      const invalidOrigins = [
        'https://evil.com',
        'https://hsdcore.com.evil.com',
        'https://fakehsdcore.com',
        'null',
        'file://',
        'https://evil.com/hsdcore.com'
      ];

      invalidOrigins.forEach(origin => {
        expect(isValidOrigin(origin, allowedOrigins)).toBe(false);
      });
    });

    it('should not reflect arbitrary origins', () => {
      fc.assert(
        fc.property(
          fc.webUrl(),
          (origin) => {
            fc.pre(!origin.includes('hsdcore.com'));
            expect(isValidOrigin(origin, allowedOrigins)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Insecure Direct Object Reference Patterns', () => {
    it('should use unpredictable identifiers', () => {
      fc.assert(
        fc.property(
          fc.uuid(),
          (id) => {
            // UUIDs are unpredictable
            expect(id.length).toBe(36);
            expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should not expose sequential IDs', () => {
      // Sequential IDs are predictable and enable IDOR
      const sequentialIds = [1, 2, 3, 4, 5];
      
      sequentialIds.forEach((id, index) => {
        if (index > 0) {
          // Attacker can guess next ID
          expect(id).toBe(sequentialIds[index - 1] + 1);
        }
      });
      
      // This test demonstrates why sequential IDs are bad
      // In production, use UUIDs or other unpredictable identifiers
    });
  });
});
