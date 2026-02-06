'use client';

import { useState } from 'react';
import { AdminRole, AdminPermission, ROLE_PERMISSIONS } from '@/types/auth';

interface RoleAccessControlProps {
  currentRole: AdminRole;
  currentRealmAccess: string[];
  availableRealms: { id: string; name: string }[];
  onRoleChange?: (role: AdminRole) => void;
  onRealmAccessChange?: (realmIds: string[]) => void;
  readOnly?: boolean;
}

/**
 * RoleAccessControl Component
 * Implements role-based access control UI
 * Validates: Requirements 3.5
 */
export default function RoleAccessControl({
  currentRole,
  currentRealmAccess,
  availableRealms,
  onRoleChange,
  onRealmAccessChange,
  readOnly = false
}: RoleAccessControlProps) {
  const [selectedRole, setSelectedRole] = useState<AdminRole>(currentRole);
  const [selectedRealms, setSelectedRealms] = useState<string[]>(currentRealmAccess);

  const roles: { value: AdminRole; label: string; description: string }[] = [
    { value: 'super_admin', label: 'Super Admin', description: 'Full access to all realms and features' },
    { value: 'realm_admin', label: 'Realm Admin', description: 'Full access to assigned realms' },
    { value: 'realm_viewer', label: 'Realm Viewer', description: 'Read-only access to assigned realms' },
    { value: 'analytics_viewer', label: 'Analytics Viewer', description: 'View analytics only' }
  ];

  const permissionGroups: { name: string; permissions: AdminPermission[] }[] = [
    { name: 'Realm Management', permissions: ['realm:read', 'realm:write', 'realm:delete'] },
    { name: 'User Management', permissions: ['user:read', 'user:write', 'user:delete'] },
    { name: 'Session Management', permissions: ['session:read', 'session:revoke'] },
    { name: 'Analytics', permissions: ['analytics:read'] },
    { name: 'Settings', permissions: ['settings:read', 'settings:write'] }
  ];

  const handleRoleChange = (role: AdminRole) => {
    setSelectedRole(role);
    onRoleChange?.(role);
  };

  const handleRealmToggle = (realmId: string) => {
    const newRealms = selectedRealms.includes(realmId)
      ? selectedRealms.filter(id => id !== realmId)
      : [...selectedRealms, realmId];
    setSelectedRealms(newRealms);
    onRealmAccessChange?.(newRealms);
  };

  const currentPermissions = ROLE_PERMISSIONS[selectedRole];

  return (
    <div className="space-y-6">
      {/* Role Selection */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Role Assignment</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {roles.map(role => (
            <button
              key={role.value}
              type="button"
              disabled={readOnly}
              onClick={() => handleRoleChange(role.value)}
              className={`p-4 border rounded-lg text-left transition ${
                selectedRole === role.value
                  ? 'border-hsd-primary bg-hsd-primary/5 ring-2 ring-hsd-primary'
                  : 'border-gray-200 hover:border-gray-300'
              } ${readOnly ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}`}
            >
              <div className="flex items-center justify-between">
                <span className="font-medium text-gray-900">{role.label}</span>
                {selectedRole === role.value && (
                  <span className="text-hsd-primary">✓</span>
                )}
              </div>
              <p className="text-sm text-gray-500 mt-1">{role.description}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Realm Access (only for non-super_admin) */}
      {selectedRole !== 'super_admin' && (
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Realm Access</h3>
          <p className="text-sm text-gray-500 mb-4">
            Select which realms this user can access
          </p>
          <div className="space-y-2">
            {availableRealms.map(realm => (
              <label
                key={realm.id}
                className={`flex items-center p-3 border rounded-lg ${
                  readOnly ? 'cursor-not-allowed' : 'cursor-pointer hover:bg-gray-50'
                }`}
              >
                <input
                  type="checkbox"
                  disabled={readOnly}
                  checked={selectedRealms.includes(realm.id)}
                  onChange={() => handleRealmToggle(realm.id)}
                  className="h-4 w-4 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
                />
                <div className="ml-3">
                  <span className="font-medium text-gray-900">{realm.name}</span>
                  <span className="text-sm text-gray-500 ml-2">({realm.id})</span>
                </div>
              </label>
            ))}
            {availableRealms.length === 0 && (
              <p className="text-gray-500 text-sm">No realms available</p>
            )}
          </div>
        </div>
      )}

      {/* Permission Overview */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Permission Overview</h3>
        <p className="text-sm text-gray-500 mb-4">
          Permissions granted by the {roles.find(r => r.value === selectedRole)?.label} role
        </p>
        <div className="space-y-4">
          {permissionGroups.map(group => (
            <div key={group.name}>
              <h4 className="text-sm font-medium text-gray-700 mb-2">{group.name}</h4>
              <div className="flex flex-wrap gap-2">
                {group.permissions.map(permission => {
                  const hasPermission = currentPermissions.includes(permission);
                  return (
                    <span
                      key={permission}
                      className={`px-2 py-1 text-xs rounded ${
                        hasPermission
                          ? 'bg-green-100 text-green-800'
                          : 'bg-gray-100 text-gray-400'
                      }`}
                    >
                      {permission.replace(':', ' ')}
                      {hasPermission && ' ✓'}
                    </span>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
