'use client';

import { useState, useEffect } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Realm } from '@/types/realm';

type TabType = 'settings' | 'users' | 'security' | 'integrations';

interface RealmUser {
  id: string;
  email: string;
  email_verified: boolean;
  status: 'active' | 'suspended' | 'pending_verification';
  created_at: string;
  last_login: string;
}

/**
 * Edit Realm Page with tabbed interface
 * Validates: Requirements 3.2, 3.5
 */
export default function EditRealmPage() {
  const router = useRouter();
  const params = useParams();
  const realmId = params.id as string;
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [realm, setRealm] = useState<Realm | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('settings');
  const [realmUsers, setRealmUsers] = useState<RealmUser[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);

  useEffect(() => {
    fetch(`/api/realms/${realmId}`)
      .then(res => res.json())
      .then(data => {
        setRealm(data.realm);
        setLoading(false);
      })
      .catch(() => {
        setError('Failed to load realm');
        setLoading(false);
      });
  }, [realmId]);

  useEffect(() => {
    if (activeTab === 'users' && realmUsers.length === 0) {
      setUsersLoading(true);
      fetch(`/api/users?realmId=${realmId}`)
        .then(res => res.json())
        .then(data => {
          setRealmUsers(data.users || []);
          setUsersLoading(false);
        })
        .catch(() => setUsersLoading(false));
    }
  }, [activeTab, realmId, realmUsers.length]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!realm) return;
    
    setError('');
    setSuccess('');
    setSaving(true);

    try {
      const response = await fetch(`/api/realms/${realmId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(realm),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to update realm');
      }

      setSuccess('Realm settings saved successfully');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update realm');
    } finally {
      setSaving(false);
    }
  };

  const tabs: { id: TabType; label: string; icon: string }[] = [
    { id: 'settings', label: 'General Settings', icon: '⚙️' },
    { id: 'users', label: 'Users', icon: '👥' },
    { id: 'security', label: 'Security', icon: '🔒' },
    { id: 'integrations', label: 'Integrations', icon: '🔗' },
  ];

  if (loading) {
    return (
      <div className="max-w-4xl animate-pulse">
        <div className="h-8 bg-gray-200 rounded w-1/3 mb-6"></div>
        <div className="bg-white rounded-lg shadow p-6">
          <div className="space-y-4">
            <div className="h-4 bg-gray-200 rounded w-1/4"></div>
            <div className="h-10 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  if (!realm) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold text-gray-900">Realm not found</h2>
        <button
          onClick={() => router.push('/dashboard/realms')}
          className="mt-4 text-hsd-primary hover:underline"
        >
          Back to Realms
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <div className="h-12 w-12 bg-hsd-primary rounded-lg flex items-center justify-center text-white text-xl font-bold mr-4">
            {realm.name.charAt(0).toUpperCase()}
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{realm.name}</h1>
            <p className="text-sm text-gray-500">{realm.domain}</p>
          </div>
        </div>
        <button
          onClick={() => router.push('/dashboard/realms')}
          className="text-gray-500 hover:text-gray-700"
        >
          ← Back to Realms
        </button>
      </div>

      {/* Alerts */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md mb-6">
          {error}
        </div>
      )}
      {success && (
        <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-md mb-6">
          {success}
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="flex space-x-8">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-hsd-primary text-hsd-primary'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <span className="mr-2">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'settings' && (
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Basic Information */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Basic Information</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Realm ID</label>
                <input
                  type="text"
                  disabled
                  value={realm.id}
                  className="w-full px-4 py-2 border border-gray-200 rounded-md bg-gray-50 text-gray-500"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Realm Name *</label>
                  <input
                    type="text"
                    required
                    value={realm.name}
                    onChange={(e) => setRealm({ ...realm, name: e.target.value })}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Domain *</label>
                  <input
                    type="text"
                    required
                    value={realm.domain}
                    onChange={(e) => setRealm({ ...realm, domain: e.target.value })}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Session Settings */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Session Settings</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Session Timeout (seconds)
                </label>
                <input
                  type="number"
                  min="300"
                  max="86400"
                  value={realm.settings.session_timeout}
                  onChange={(e) => setRealm({
                    ...realm,
                    settings: { ...realm.settings, session_timeout: parseInt(e.target.value) }
                  })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                />
                <p className="text-xs text-gray-500 mt-1">
                  {Math.floor(realm.settings.session_timeout / 60)} minutes / {Math.floor(realm.settings.session_timeout / 3600)} hours
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Allowed Origins</label>
                <input
                  type="text"
                  value={realm.settings.allowed_origins.join(', ')}
                  onChange={(e) => setRealm({
                    ...realm,
                    settings: {
                      ...realm.settings,
                      allowed_origins: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                    }
                  })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                  placeholder="https://myapp.com, https://admin.myapp.com"
                />
              </div>
            </div>
          </div>

          {/* Authentication Providers */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Authentication Providers</h2>
            <div className="space-y-4">
              {realm.auth_providers.map((provider, index) => (
                <div key={provider.type} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div>
                    <h3 className="font-medium text-gray-900 capitalize">{provider.type.replace('_', '/')}</h3>
                    <p className="text-sm text-gray-500">
                      {provider.type === 'email_password' && 'Traditional email and password authentication'}
                      {provider.type === 'oauth' && 'Social login with Google, GitHub, etc.'}
                      {provider.type === 'sso' && 'Enterprise Single Sign-On integration'}
                    </p>
                  </div>
                  <input
                    type="checkbox"
                    checked={provider.enabled}
                    onChange={(e) => {
                      const newProviders = [...realm.auth_providers];
                      newProviders[index] = { ...provider, enabled: e.target.checked };
                      setRealm({ ...realm, auth_providers: newProviders });
                    }}
                    className="h-5 w-5 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-4">
            <button
              type="button"
              onClick={() => router.back()}
              className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 bg-hsd-primary text-white rounded-md hover:bg-hsd-secondary transition disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      )}

      {activeTab === 'users' && (
        <div className="bg-white rounded-lg shadow">
          <div className="p-4 border-b border-gray-200 flex justify-between items-center">
            <h2 className="text-lg font-semibold text-gray-900">Realm Users</h2>
            <span className="text-sm text-gray-500">{realmUsers.length} users</span>
          </div>
          {usersLoading ? (
            <div className="p-6 animate-pulse">
              {[1, 2, 3].map(i => (
                <div key={i} className="flex items-center space-x-4 mb-4">
                  <div className="h-10 w-10 bg-gray-200 rounded-full"></div>
                  <div className="flex-1">
                    <div className="h-4 bg-gray-200 rounded w-1/4 mb-2"></div>
                    <div className="h-3 bg-gray-200 rounded w-1/3"></div>
                  </div>
                </div>
              ))}
            </div>
          ) : realmUsers.length === 0 ? (
            <div className="p-12 text-center">
              <span className="text-4xl">👥</span>
              <h3 className="mt-4 text-lg font-medium text-gray-900">No users in this realm</h3>
              <p className="mt-2 text-gray-500">Users will appear here once they register</p>
            </div>
          ) : (
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">User</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Login</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {realmUsers.map(user => (
                  <tr key={user.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <div className="h-8 w-8 bg-gray-300 rounded-full flex items-center justify-center text-white text-sm font-bold">
                          {user.email.charAt(0).toUpperCase()}
                        </div>
                        <div className="ml-3">
                          <p className="text-sm font-medium text-gray-900">{user.email}</p>
                          <p className="text-xs text-gray-500">
                            {user.email_verified ? '✓ Verified' : '⚠ Unverified'}
                          </p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 text-xs rounded ${
                        user.status === 'active' ? 'bg-green-100 text-green-800' :
                        user.status === 'suspended' ? 'bg-red-100 text-red-800' :
                        'bg-yellow-100 text-yellow-800'
                      }`}>
                        {user.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === 'security' && (
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* MFA Settings */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Multi-Factor Authentication</h2>
            <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
              <div>
                <h3 className="font-medium text-gray-900">Require MFA</h3>
                <p className="text-sm text-gray-500">Force all users to enable two-factor authentication</p>
              </div>
              <input
                type="checkbox"
                checked={realm.settings.mfa_required}
                onChange={(e) => setRealm({
                  ...realm,
                  settings: { ...realm.settings, mfa_required: e.target.checked }
                })}
                className="h-5 w-5 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
              />
            </div>
          </div>

          {/* Password Policy */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Password Policy</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Minimum Length</label>
                <input
                  type="number"
                  min="6"
                  max="128"
                  value={realm.settings.password_policy.min_length}
                  onChange={(e) => setRealm({
                    ...realm,
                    settings: {
                      ...realm.settings,
                      password_policy: {
                        ...realm.settings.password_policy,
                        min_length: parseInt(e.target.value)
                      }
                    }
                  })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                {[
                  { key: 'require_uppercase', label: 'Require Uppercase' },
                  { key: 'require_lowercase', label: 'Require Lowercase' },
                  { key: 'require_numbers', label: 'Require Numbers' },
                  { key: 'require_special_chars', label: 'Require Special Characters' },
                ].map(({ key, label }) => (
                  <label key={key} className="flex items-center p-3 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50">
                    <input
                      type="checkbox"
                      checked={realm.settings.password_policy[key as keyof typeof realm.settings.password_policy] as boolean}
                      onChange={(e) => setRealm({
                        ...realm,
                        settings: {
                          ...realm.settings,
                          password_policy: {
                            ...realm.settings.password_policy,
                            [key]: e.target.checked
                          }
                        }
                      })}
                      className="h-4 w-4 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
                    />
                    <span className="ml-2 text-sm text-gray-700">{label}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 bg-hsd-primary text-white rounded-md hover:bg-hsd-secondary transition disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save Security Settings'}
            </button>
          </div>
        </form>
      )}

      {activeTab === 'integrations' && (
        <div className="space-y-6">
          {/* API Keys */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">API Configuration</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">API Endpoint</label>
                <div className="flex">
                  <input
                    type="text"
                    readOnly
                    value={`https://api.auth.hsdcore.com/v1/realms/${realm.id}`}
                    className="flex-1 px-4 py-2 border border-gray-200 rounded-l-md bg-gray-50 text-gray-600"
                  />
                  <button
                    type="button"
                    onClick={() => navigator.clipboard.writeText(`https://api.auth.hsdcore.com/v1/realms/${realm.id}`)}
                    className="px-4 py-2 bg-gray-100 border border-l-0 border-gray-200 rounded-r-md hover:bg-gray-200"
                  >
                    Copy
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Realm ID</label>
                <div className="flex">
                  <input
                    type="text"
                    readOnly
                    value={realm.id}
                    className="flex-1 px-4 py-2 border border-gray-200 rounded-l-md bg-gray-50 text-gray-600"
                  />
                  <button
                    type="button"
                    onClick={() => navigator.clipboard.writeText(realm.id)}
                    className="px-4 py-2 bg-gray-100 border border-l-0 border-gray-200 rounded-r-md hover:bg-gray-200"
                  >
                    Copy
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* SDK Integration */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">SDK Integration</h2>
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-2">JavaScript/TypeScript</h3>
                <pre className="bg-gray-900 text-gray-100 p-4 rounded-md text-sm overflow-x-auto">
{`import { ZaltAuth } from '@zalt/auth-sdk';

const auth = new ZaltAuth({
  realmId: '${realm.id}',
  apiUrl: 'https://api.zalt.io'
});`}
                </pre>
              </div>
              <div>
                <h3 className="text-sm font-medium text-gray-700 mb-2">Python</h3>
                <pre className="bg-gray-900 text-gray-100 p-4 rounded-md text-sm overflow-x-auto">
{`from zalt_auth import ZaltAuth

auth = ZaltAuth(
    realm_id='${realm.id}',
    api_url='https://api.zalt.io'
)`}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
