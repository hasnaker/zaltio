'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { DEFAULT_PASSWORD_POLICY, DEFAULT_REALM_SETTINGS } from '@/types/realm';

export default function NewRealmPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  const [formData, setFormData] = useState({
    name: '',
    domain: '',
    sessionTimeout: DEFAULT_REALM_SETTINGS.session_timeout,
    mfaRequired: DEFAULT_REALM_SETTINGS.mfa_required,
    allowedOrigins: '',
    passwordMinLength: DEFAULT_PASSWORD_POLICY.min_length,
    passwordRequireUppercase: DEFAULT_PASSWORD_POLICY.require_uppercase,
    passwordRequireLowercase: DEFAULT_PASSWORD_POLICY.require_lowercase,
    passwordRequireNumbers: DEFAULT_PASSWORD_POLICY.require_numbers,
    passwordRequireSpecial: DEFAULT_PASSWORD_POLICY.require_special_chars,
    enableEmailPassword: true,
    enableOAuth: false,
    enableSSO: false,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/realms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.name,
          domain: formData.domain,
          settings: {
            password_policy: {
              min_length: formData.passwordMinLength,
              require_uppercase: formData.passwordRequireUppercase,
              require_lowercase: formData.passwordRequireLowercase,
              require_numbers: formData.passwordRequireNumbers,
              require_special_chars: formData.passwordRequireSpecial,
            },
            session_timeout: formData.sessionTimeout,
            mfa_required: formData.mfaRequired,
            allowed_origins: formData.allowedOrigins.split(',').map(s => s.trim()).filter(Boolean),
          },
          auth_providers: [
            { type: 'email_password', enabled: formData.enableEmailPassword, config: {} },
            { type: 'oauth', enabled: formData.enableOAuth, config: {} },
            { type: 'sso', enabled: formData.enableSSO, config: {} },
          ],
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to create realm');
      }

      router.push('/dashboard/realms');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create realm');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Create New Realm</h1>

      <form onSubmit={handleSubmit} className="space-y-8">
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md">
            {error}
          </div>
        )}

        {/* Basic Information */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Basic Information</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Realm Name *
              </label>
              <input
                type="text"
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                placeholder="My Application"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Domain *
              </label>
              <input
                type="text"
                required
                value={formData.domain}
                onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                placeholder="myapp.hsdcore.com"
              />
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
                value={formData.sessionTimeout}
                onChange={(e) => setFormData({ ...formData, sessionTimeout: parseInt(e.target.value) })}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
              />
            </div>
            <div className="flex items-center">
              <input
                type="checkbox"
                id="mfaRequired"
                checked={formData.mfaRequired}
                onChange={(e) => setFormData({ ...formData, mfaRequired: e.target.checked })}
                className="h-4 w-4 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
              />
              <label htmlFor="mfaRequired" className="ml-2 text-sm text-gray-700">
                Require Multi-Factor Authentication
              </label>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Allowed Origins (comma-separated)
              </label>
              <input
                type="text"
                value={formData.allowedOrigins}
                onChange={(e) => setFormData({ ...formData, allowedOrigins: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
                placeholder="https://myapp.com, https://admin.myapp.com"
              />
            </div>
          </div>
        </div>

        {/* Password Policy */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Password Policy</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Minimum Length
              </label>
              <input
                type="number"
                min="6"
                max="128"
                value={formData.passwordMinLength}
                onChange={(e) => setFormData({ ...formData, passwordMinLength: parseInt(e.target.value) })}
                className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-hsd-primary focus:border-transparent outline-none"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="requireUppercase"
                  checked={formData.passwordRequireUppercase}
                  onChange={(e) => setFormData({ ...formData, passwordRequireUppercase: e.target.checked })}
                  className="h-4 w-4 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
                />
                <label htmlFor="requireUppercase" className="ml-2 text-sm text-gray-700">
                  Require Uppercase
                </label>
              </div>
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="requireLowercase"
                  checked={formData.passwordRequireLowercase}
                  onChange={(e) => setFormData({ ...formData, passwordRequireLowercase: e.target.checked })}
                  className="h-4 w-4 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
                />
                <label htmlFor="requireLowercase" className="ml-2 text-sm text-gray-700">
                  Require Lowercase
                </label>
              </div>
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="requireNumbers"
                  checked={formData.passwordRequireNumbers}
                  onChange={(e) => setFormData({ ...formData, passwordRequireNumbers: e.target.checked })}
                  className="h-4 w-4 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
                />
                <label htmlFor="requireNumbers" className="ml-2 text-sm text-gray-700">
                  Require Numbers
                </label>
              </div>
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="requireSpecial"
                  checked={formData.passwordRequireSpecial}
                  onChange={(e) => setFormData({ ...formData, passwordRequireSpecial: e.target.checked })}
                  className="h-4 w-4 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
                />
                <label htmlFor="requireSpecial" className="ml-2 text-sm text-gray-700">
                  Require Special Characters
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Authentication Providers */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Authentication Providers</h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
              <div>
                <h3 className="font-medium text-gray-900">Email/Password</h3>
                <p className="text-sm text-gray-500">Traditional email and password authentication</p>
              </div>
              <input
                type="checkbox"
                checked={formData.enableEmailPassword}
                onChange={(e) => setFormData({ ...formData, enableEmailPassword: e.target.checked })}
                className="h-5 w-5 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
              />
            </div>
            <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
              <div>
                <h3 className="font-medium text-gray-900">OAuth 2.0</h3>
                <p className="text-sm text-gray-500">Social login with Google, GitHub, etc.</p>
              </div>
              <input
                type="checkbox"
                checked={formData.enableOAuth}
                onChange={(e) => setFormData({ ...formData, enableOAuth: e.target.checked })}
                className="h-5 w-5 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
              />
            </div>
            <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
              <div>
                <h3 className="font-medium text-gray-900">SSO</h3>
                <p className="text-sm text-gray-500">Enterprise Single Sign-On integration</p>
              </div>
              <input
                type="checkbox"
                checked={formData.enableSSO}
                onChange={(e) => setFormData({ ...formData, enableSSO: e.target.checked })}
                className="h-5 w-5 text-hsd-primary focus:ring-hsd-primary border-gray-300 rounded"
              />
            </div>
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
            disabled={loading}
            className="px-4 py-2 bg-hsd-primary text-white rounded-md hover:bg-hsd-secondary transition disabled:opacity-50"
          >
            {loading ? 'Creating...' : 'Create Realm'}
          </button>
        </div>
      </form>
    </div>
  );
}
