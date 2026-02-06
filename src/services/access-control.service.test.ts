/**
 * Property-based tests for Dashboard Access Control
 * Feature: zalt-platform, Property 6: Dashboard Access Control
 * Validates: Requirements 3.2, 3.5
 */

import * as fc from 'fast-check';
import {
  AdminUser,
  AdminRole,
  AdminPermission,
  DashboardCapability,
  ROLE_PERMISSIONS,
  DASHBOARD_CAPABILITIES,
  hasPermission,
  hasRealmAccess,
  getAdminPermissions,
  getAccessibleRealms,
  getDashboardCapabilities,
  canPerformAction,
  getDashboardAccessContext
} from './access-control.service';

/**
 * Custom generators for realistic test data
 */
const adminRoleArb = fc.constantFrom<AdminRole>(
  'super_admin',
  'realm_admin',
  'realm_viewer',
  'analytics_viewer'
);

const realmIdArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'),
  { minLength: 3, maxLength: 30 }
).filter(s => /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$/.test(s) && s.length >= 3);

const adminUserArb = fc.record({
  id: fc.uuid(),
  email: fc.emailAddress(),
  role: adminRoleArb,
  realm_access: fc.array(realmIdArb, { minLength: 0, maxLength: 5 }),
  created_at: fc.date().map(d => d.toISOString()),
  updated_at: fc.date().map(d => d.toISOString())
});

const permissionArb = fc.constantFrom<AdminPermission>(
  'realm:read', 'realm:write', 'realm:delete',
  'user:read', 'user:write', 'user:delete',
  'session:read', 'session:revoke',
  'analytics:read',
  'settings:read', 'settings:write'
);

describe('Dashboard Access Control - Property Tests', () => {
  /**
   * Property 6: Dashboard Access Control
   * For any administrator login, the dashboard should display only the realm-specific
   * management capabilities that match the administrator's assigned permissions and realm access.
   * Validates: Requirements 3.2, 3.5
   */
  describe('Property 6: Dashboard Access Control', () => {
    it('should only grant permissions defined for the admin role', () => {
      fc.assert(
        fc.property(adminUserArb, (admin) => {
          const permissions = getAdminPermissions(admin);
          const expectedPermissions = ROLE_PERMISSIONS[admin.role];
          
          // All returned permissions should be in the role's permission set
          permissions.forEach(permission => {
            expect(expectedPermissions).toContain(permission);
          });
          
          // Should have exactly the permissions defined for the role
          expect(permissions.length).toBe(expectedPermissions.length);
          expect(new Set(permissions)).toEqual(new Set(expectedPermissions));
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should grant super_admin access to all realms', () => {
      fc.assert(
        fc.property(
          fc.array(realmIdArb, { minLength: 1, maxLength: 10 }),
          (allRealmIds) => {
            const superAdmin: AdminUser = {
              id: 'super-admin-id',
              email: 'super@hsdcore.com',
              role: 'super_admin',
              realm_access: [], // Empty, but should still have access to all
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
            };
            
            const accessibleRealms = getAccessibleRealms(superAdmin, allRealmIds);
            
            // Super admin should have access to all realms
            expect(accessibleRealms.length).toBe(allRealmIds.length);
            allRealmIds.forEach(realmId => {
              expect(accessibleRealms).toContain(realmId);
              expect(hasRealmAccess(superAdmin, realmId)).toBe(true);
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should restrict non-super_admin to only assigned realms', () => {
      fc.assert(
        fc.property(
          adminUserArb.filter(a => a.role !== 'super_admin'),
          fc.array(realmIdArb, { minLength: 1, maxLength: 10 }),
          (admin, allRealmIds) => {
            const accessibleRealms = getAccessibleRealms(admin, allRealmIds);
            
            // Should only have access to realms in realm_access that exist in allRealmIds
            const expectedRealms = admin.realm_access.filter(r => allRealmIds.includes(r));
            expect(accessibleRealms.length).toBe(expectedRealms.length);
            
            // Each accessible realm should be in admin's realm_access
            accessibleRealms.forEach(realmId => {
              expect(admin.realm_access).toContain(realmId);
            });
            
            // Realms not in realm_access should not be accessible
            allRealmIds.forEach(realmId => {
              if (!admin.realm_access.includes(realmId)) {
                expect(hasRealmAccess(admin, realmId)).toBe(false);
              }
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should only show capabilities matching admin permissions', () => {
      fc.assert(
        fc.property(adminUserArb, (admin) => {
          const capabilities = getDashboardCapabilities(admin);
          const permissions = getAdminPermissions(admin);
          
          // Each capability should require a permission the admin has
          capabilities.forEach(capability => {
            expect(permissions).toContain(capability.required_permission);
          });
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should filter realm-specific capabilities by realm access', () => {
      fc.assert(
        fc.property(
          adminUserArb.filter(a => a.role !== 'super_admin'),
          realmIdArb,
          (admin, realmId) => {
            const hasAccess = hasRealmAccess(admin, realmId);
            const capabilities = getDashboardCapabilities(admin, realmId);
            
            if (!hasAccess) {
              // If no realm access, should not have realm-specific capabilities
              const realmSpecificCaps = capabilities.filter(c => c.realm_specific);
              expect(realmSpecificCaps.length).toBe(0);
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should ensure canPerformAction respects both permission and realm access', () => {
      fc.assert(
        fc.property(
          adminUserArb,
          permissionArb,
          realmIdArb,
          (admin, permission, realmId) => {
            const canPerform = canPerformAction(admin, permission, realmId);
            const hasThisPermission = hasPermission(admin, permission);
            const hasThisRealmAccess = hasRealmAccess(admin, realmId);
            
            // Can only perform action if both permission AND realm access are granted
            if (canPerform) {
              expect(hasThisPermission).toBe(true);
              expect(hasThisRealmAccess).toBe(true);
            }
            
            // If missing either, should not be able to perform
            if (!hasThisPermission || !hasThisRealmAccess) {
              expect(canPerform).toBe(false);
            }
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should provide complete access context for dashboard rendering', () => {
      fc.assert(
        fc.property(
          adminUserArb,
          fc.array(realmIdArb, { minLength: 1, maxLength: 10 }),
          (admin, allRealmIds) => {
            const context = getDashboardAccessContext(admin, allRealmIds);
            
            // Context should contain the admin
            expect(context.admin).toEqual(admin);
            
            // Permissions should match role
            expect(context.permissions).toEqual(ROLE_PERMISSIONS[admin.role]);
            
            // Accessible realms should be correct
            if (admin.role === 'super_admin') {
              expect(context.accessibleRealms.length).toBe(allRealmIds.length);
            } else {
              context.accessibleRealms.forEach(realmId => {
                expect(admin.realm_access).toContain(realmId);
              });
            }
            
            // Realm capabilities should only exist for accessible realms
            context.realmCapabilities.forEach((caps, realmId) => {
              expect(context.accessibleRealms).toContain(realmId);
              // Each capability should require a permission the admin has
              caps.forEach(cap => {
                expect(context.permissions).toContain(cap.required_permission);
              });
            });
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should ensure role hierarchy is respected (super_admin has all permissions)', () => {
      fc.assert(
        fc.property(permissionArb, (permission) => {
          const superAdmin: AdminUser = {
            id: 'super-admin-id',
            email: 'super@hsdcore.com',
            role: 'super_admin',
            realm_access: [],
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          };
          
          // Super admin should have all permissions
          expect(hasPermission(superAdmin, permission)).toBe(true);
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should ensure analytics_viewer has minimal permissions', () => {
      fc.assert(
        fc.property(permissionArb, (permission) => {
          const analyticsViewer: AdminUser = {
            id: 'viewer-id',
            email: 'viewer@hsdcore.com',
            role: 'analytics_viewer',
            realm_access: ['test-realm'],
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          };
          
          const hasThisPermission = hasPermission(analyticsViewer, permission);
          
          // Analytics viewer should only have analytics:read
          if (permission === 'analytics:read') {
            expect(hasThisPermission).toBe(true);
          } else {
            expect(hasThisPermission).toBe(false);
          }
          
          return true;
        }),
        { numRuns: 100 }
      );
    });

    it('should ensure realm_viewer cannot modify data', () => {
      fc.assert(
        fc.property(
          fc.constantFrom<AdminPermission>(
            'realm:write', 'realm:delete',
            'user:write', 'user:delete',
            'session:revoke',
            'settings:write'
          ),
          (writePermission) => {
            const realmViewer: AdminUser = {
              id: 'viewer-id',
              email: 'viewer@hsdcore.com',
              role: 'realm_viewer',
              realm_access: ['test-realm'],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
            };
            
            // Realm viewer should not have any write/delete permissions
            expect(hasPermission(realmViewer, writePermission)).toBe(false);
            
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should ensure capabilities are consistent with permissions', () => {
      fc.assert(
        fc.property(adminUserArb, (admin) => {
          const capabilities = getDashboardCapabilities(admin);
          const permissions = getAdminPermissions(admin);
          
          // For each capability, verify the required permission is in admin's permissions
          capabilities.forEach(capability => {
            const hasRequiredPermission = permissions.includes(capability.required_permission);
            expect(hasRequiredPermission).toBe(true);
          });
          
          // Verify no capabilities are shown that require permissions the admin doesn't have
          DASHBOARD_CAPABILITIES.forEach(capability => {
            if (!permissions.includes(capability.required_permission)) {
              expect(capabilities).not.toContainEqual(capability);
            }
          });
          
          return true;
        }),
        { numRuns: 100 }
      );
    });
  });
});
