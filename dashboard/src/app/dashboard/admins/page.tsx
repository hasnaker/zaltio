'use client';

import { useState, useEffect } from 'react';
import { AdminUser, AdminRole, ROLE_PERMISSIONS } from '@/types/auth';
import { Realm } from '@/types/realm';
import RoleAccessControl from '@/components/RoleAccessControl';

/**
 * Admin Management Page
 * Implements role-based access control UI
 * Validates: Requirements 3.5
 */
export default function AdminsPage() {
  const [admins, setAdmins] = useState<AdminUser[]>([]);
  const [realms, setRealms] = useState<Realm[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingAdmin, setEditingAdmin] = useState<AdminUser | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    Promise.all([
      fetch('/api/admins').then(res => res.json()),
      fetch('/api/realms').then(res => res.json())
    ])
      .then(([adminData, realmData]) => {
        setAdmins(adminData.admins || getMockAdmins());
        setRealms(realmData.realms || []);
        setLoading(false);
      })
      .catch(() => {
        setAdmins(getMockAdmins());
        setLoading(false);
      });
  }, []);

  const getMockAdmins = (): AdminUser[] => [
    {
      id: 'admin-1',
      email: 'superadmin@hsdcore.com',
      role: 'super_admin',
      realm_access: [],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-15T00:00:00Z',
    },
    {
      id: 'admin-2',
      email: 'realmadmin@hsdcore.com',
      role: 'realm_admin',
      realm_access: ['realm-1', 'realm-2'],
      created_at: '2024-01-05T00:00:00Z',
      updated_at: '2024-01-10T00:00:00Z',
    },
    {
      id: 'admin-3',
      email: 'viewer@hsdcore.com',
      role: 'realm_viewer',
      realm_access: ['realm-1'],
      created_at: '2024-01-10T00:00:00Z',
      updated_at: '2024-01-10T00:00:00Z',
    },
  ];

  const filteredAdmins = admins.filter(admin =>
    admin.email.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getRoleBadge = (role: AdminRole) => {
    const styles: Record<AdminRole, string> = {
      super_admin: 'bg-purple-100 text-purple-800',
      realm_admin: 'bg-blue-100 text-blue-800',
      realm_viewer: 'bg-green-100 text-green-800',
      analytics_viewer: 'bg-gray-100 text-gray-800',
    };
    return (
      <span className={`px-2 py-1 text-xs rounded ${styles[role]}`}>
        {role.replace('_', ' ')}
      </span>
    );
  };

  const handleEdit = (admin: AdminUser) => {
    setEditingAdmin(admin);
    setShowModal(true);
  };

  const handleDelete = async (adminId: string) => {
    if (!confirm('Are you sure you want to remove this admin?')) return;
    
    try {
      await fetch(`/api/admins/${adminId}`, { method: 'DELETE' });
      setAdmins(admins.filter(a => a.id !== adminId));
    } catch (error) {
      console.error('Failed to delete admin:', error);
    }
  };

  const handleSave = async (updatedAdmin: AdminUser) => {
    try {
      const response = await fetch(`/api/admins/${updatedAdmin.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updatedAdmin),
      });
      
      if (response.ok) {
        setAdmins(admins.map(a => a.id === updatedAdmin.id ? updatedAdmin : a));
      }
    } catch (error) {
      console.error('Failed to update admin:', error);
    }
    setShowModal(false);
    setEditingAdmin(null);
  };

  const handleCreate = () => {
    setEditingAdmin({
      id: '',
      email: '',
      role: 'realm_viewer',
      realm_access: [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    setShowModal(true);
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Admin Management</h1>
        <button
          onClick={handleCreate}
          className="bg-hsd-primary text-white px-4 py-2 rounded-md hover:bg-hsd-secondary transition"
        >
          + Add Admin
        </button>
      </div>

      {/* Search */}
      <div className="mb-6">
        <input
          type="text"
          placeholder="Search admins..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full max-w-md px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
        />
      </div>

      {/* Role Legend */}
      <div className="bg-white rounded-lg shadow p-4 mb-6">
        <h3 className="text-sm font-medium text-gray-700 mb-3">Role Permissions</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {(['super_admin', 'realm_admin', 'realm_viewer', 'analytics_viewer'] as AdminRole[]).map(role => (
            <div key={role} className="text-sm">
              {getRoleBadge(role)}
              <p className="text-xs text-gray-500 mt-1">
                {ROLE_PERMISSIONS[role].length} permissions
              </p>
            </div>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="bg-white rounded-lg shadow">
          <div className="p-6 animate-pulse">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center space-x-4 mb-4">
                <div className="h-10 w-10 bg-gray-200 rounded-full"></div>
                <div className="flex-1">
                  <div className="h-4 bg-gray-200 rounded w-1/4 mb-2"></div>
                  <div className="h-3 bg-gray-200 rounded w-1/3"></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Admin
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Role
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Realm Access
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Created
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredAdmins.map((admin) => (
                <tr key={admin.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="h-10 w-10 bg-hsd-primary rounded-full flex items-center justify-center text-white font-bold">
                        {admin.email.charAt(0).toUpperCase()}
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-gray-900">{admin.email}</div>
                        <div className="text-sm text-gray-500">{admin.id}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {getRoleBadge(admin.role)}
                  </td>
                  <td className="px-6 py-4">
                    {admin.role === 'super_admin' ? (
                      <span className="text-sm text-gray-500">All realms</span>
                    ) : admin.realm_access.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {admin.realm_access.map(realmId => {
                          const realm = realms.find(r => r.id === realmId);
                          return (
                            <span key={realmId} className="px-2 py-1 text-xs bg-gray-100 rounded">
                              {realm?.name || realmId}
                            </span>
                          );
                        })}
                      </div>
                    ) : (
                      <span className="text-sm text-gray-400">No realms assigned</span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(admin.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleEdit(admin)}
                      className="text-hsd-primary hover:text-hsd-secondary mr-4"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(admin.id)}
                      className="text-red-600 hover:text-red-800"
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Edit Modal */}
      {showModal && editingAdmin && (
        <AdminEditModal
          admin={editingAdmin}
          realms={realms}
          onClose={() => {
            setShowModal(false);
            setEditingAdmin(null);
          }}
          onSave={handleSave}
        />
      )}
    </div>
  );
}

interface AdminEditModalProps {
  admin: AdminUser;
  realms: Realm[];
  onClose: () => void;
  onSave: (admin: AdminUser) => void;
}

function AdminEditModal({ admin, realms, onClose, onSave }: AdminEditModalProps) {
  const [formData, setFormData] = useState({
    email: admin.email,
    role: admin.role,
    realm_access: admin.realm_access,
  });
  const [saving, setSaving] = useState(false);
  const isNew = !admin.id;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    
    const updatedAdmin: AdminUser = {
      ...admin,
      id: admin.id || `admin-${Date.now()}`,
      email: formData.email,
      role: formData.role,
      realm_access: formData.role === 'super_admin' ? [] : formData.realm_access,
      updated_at: new Date().toISOString(),
    };
    
    onSave(updatedAdmin);
    setSaving(false);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 overflow-auto py-8">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4">
        <div className="flex justify-between items-center p-6 border-b">
          <h2 className="text-xl font-bold text-gray-900">
            {isNew ? 'Add Admin' : 'Edit Admin'}
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            ✕
          </button>
        </div>
        
        <form onSubmit={handleSubmit}>
          <div className="p-6 space-y-6 max-h-[60vh] overflow-auto">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input
                type="email"
                required
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                placeholder="admin@example.com"
              />
            </div>
            
            <RoleAccessControl
              currentRole={formData.role}
              currentRealmAccess={formData.realm_access}
              availableRealms={realms.map(r => ({ id: r.id, name: r.name }))}
              onRoleChange={(role) => setFormData({ ...formData, role })}
              onRealmAccessChange={(realm_access) => setFormData({ ...formData, realm_access })}
            />
          </div>
          
          <div className="flex justify-end space-x-3 p-6 border-t bg-gray-50">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 bg-hsd-primary text-white rounded-md hover:bg-hsd-secondary disabled:opacity-50"
            >
              {saving ? 'Saving...' : isNew ? 'Add Admin' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
