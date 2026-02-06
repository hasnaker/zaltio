'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Settings, Save, Globe, Shield, Mail, Palette, 
  Bell, Key, Users, AlertTriangle, Check, RefreshCw
} from 'lucide-react';

interface RealmSettings {
  id: string;
  name: string;
  slug: string;
  domain: string;
  allowedOrigins: string[];
  mfaPolicy: {
    required: boolean;
    methods: string[];
    gracePeriodDays: number;
  };
  sessionPolicy: {
    maxConcurrentSessions: number;
    sessionTimeoutMinutes: number;
    rememberMeDays: number;
  };
  passwordPolicy: {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
    checkBreachDatabase: boolean;
  };
  branding: {
    primaryColor: string;
    logoUrl: string;
    faviconUrl: string;
  };
  emailSettings: {
    fromName: string;
    fromEmail: string;
    replyTo: string;
  };
}

const defaultSettings: RealmSettings = {
  id: 'realm_abc123',
  name: 'My Application',
  slug: 'my-app',
  domain: 'app.example.com',
  allowedOrigins: ['https://app.example.com', 'http://localhost:3000'],
  mfaPolicy: {
    required: false,
    methods: ['totp', 'webauthn'],
    gracePeriodDays: 7,
  },
  sessionPolicy: {
    maxConcurrentSessions: 5,
    sessionTimeoutMinutes: 60,
    rememberMeDays: 30,
  },
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: false,
    checkBreachDatabase: true,
  },
  branding: {
    primaryColor: '#10b981',
    logoUrl: '',
    faviconUrl: '',
  },
  emailSettings: {
    fromName: 'My App',
    fromEmail: 'noreply@example.com',
    replyTo: 'support@example.com',
  },
};

type Tab = 'general' | 'security' | 'branding' | 'email';

export default function SettingsPage() {
  const [settings, setSettings] = useState<RealmSettings>(defaultSettings);
  const [activeTab, setActiveTab] = useState<Tab>('general');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [newOrigin, setNewOrigin] = useState('');

  const tabs: { id: Tab; name: string; icon: React.ElementType }[] = [
    { id: 'general', name: 'General', icon: Settings },
    { id: 'security', name: 'Security', icon: Shield },
    { id: 'branding', name: 'Branding', icon: Palette },
    { id: 'email', name: 'Email', icon: Mail },
  ];

  const saveSettings = async () => {
    setSaving(true);
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const addOrigin = () => {
    if (newOrigin && !settings.allowedOrigins.includes(newOrigin)) {
      setSettings({
        ...settings,
        allowedOrigins: [...settings.allowedOrigins, newOrigin],
      });
      setNewOrigin('');
    }
  };

  const removeOrigin = (origin: string) => {
    setSettings({
      ...settings,
      allowedOrigins: settings.allowedOrigins.filter(o => o !== origin),
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Realm Settings</h1>
          <p className="text-neutral-400 mt-1">Configure your authentication realm</p>
        </div>
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={saveSettings}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium disabled:opacity-50"
        >
          {saving ? (
            <RefreshCw size={18} className="animate-spin" />
          ) : saved ? (
            <Check size={18} />
          ) : (
            <Save size={18} />
          )}
          {saving ? 'Saving...' : saved ? 'Saved!' : 'Save Changes'}
        </motion.button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-emerald-500/10 pb-4">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
              activeTab === tab.id
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                : 'text-neutral-400 hover:text-white hover:bg-neutral-800'
            }`}
          >
            <tab.icon size={16} />
            {tab.name}
          </button>
        ))}
      </div>

      {/* General Tab */}
      {activeTab === 'general' && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Globe size={20} className="text-emerald-500" />
              Basic Information
            </h2>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-neutral-400 mb-2">Realm Name</label>
                <input
                  type="text"
                  value={settings.name}
                  onChange={(e) => setSettings({ ...settings, name: e.target.value })}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm text-neutral-400 mb-2">Slug</label>
                <input
                  type="text"
                  value={settings.slug}
                  onChange={(e) => setSettings({ ...settings, slug: e.target.value })}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-sm text-neutral-400 mb-2">Custom Domain</label>
                <input
                  type="text"
                  value={settings.domain}
                  onChange={(e) => setSettings({ ...settings, domain: e.target.value })}
                  placeholder="auth.yourdomain.com"
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>
          </div>

          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Key size={20} className="text-emerald-500" />
              Allowed Origins (CORS)
            </h2>
            <div className="flex gap-2">
              <input
                type="text"
                value={newOrigin}
                onChange={(e) => setNewOrigin(e.target.value)}
                placeholder="https://example.com"
                className="flex-1 px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
              />
              <button
                onClick={addOrigin}
                className="px-4 py-2 bg-emerald-500/10 text-emerald-400 rounded-lg hover:bg-emerald-500/20"
              >
                Add
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {settings.allowedOrigins.map((origin) => (
                <span
                  key={origin}
                  className="flex items-center gap-2 px-3 py-1 bg-neutral-800 text-neutral-300 rounded-lg text-sm"
                >
                  {origin}
                  <button
                    onClick={() => removeOrigin(origin)}
                    className="text-neutral-500 hover:text-red-400"
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          </div>
        </motion.div>
      )}

      {/* Security Tab */}
      {activeTab === 'security' && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* MFA Policy */}
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Shield size={20} className="text-emerald-500" />
              MFA Policy
            </h2>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings.mfaPolicy.required}
                onChange={(e) => setSettings({
                  ...settings,
                  mfaPolicy: { ...settings.mfaPolicy, required: e.target.checked }
                })}
                className="w-5 h-5 rounded border-neutral-600 bg-neutral-800 text-emerald-500 focus:ring-emerald-500"
              />
              <span className="text-white">Require MFA for all users</span>
            </label>
            <div>
              <label className="block text-sm text-neutral-400 mb-2">Allowed MFA Methods</label>
              <div className="flex gap-4">
                {['totp', 'webauthn'].map((method) => (
                  <label key={method} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={settings.mfaPolicy.methods.includes(method)}
                      onChange={(e) => {
                        const methods = e.target.checked
                          ? [...settings.mfaPolicy.methods, method]
                          : settings.mfaPolicy.methods.filter(m => m !== method);
                        setSettings({
                          ...settings,
                          mfaPolicy: { ...settings.mfaPolicy, methods }
                        });
                      }}
                      className="rounded border-neutral-600 bg-neutral-800 text-emerald-500 focus:ring-emerald-500"
                    />
                    <span className="text-neutral-300 capitalize">{method === 'totp' ? 'TOTP (Authenticator)' : 'WebAuthn (Passkeys)'}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle size={16} className="text-amber-500 mt-0.5" />
              <p className="text-sm text-amber-400">
                SMS MFA is disabled by default due to SS7 vulnerabilities. Contact support to enable.
              </p>
            </div>
          </div>

          {/* Session Policy */}
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Users size={20} className="text-emerald-500" />
              Session Policy
            </h2>
            <div className="grid md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm text-neutral-400 mb-2">Max Concurrent Sessions</label>
                <input
                  type="number"
                  value={settings.sessionPolicy.maxConcurrentSessions}
                  onChange={(e) => setSettings({
                    ...settings,
                    sessionPolicy: { ...settings.sessionPolicy, maxConcurrentSessions: parseInt(e.target.value) }
                  })}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm text-neutral-400 mb-2">Session Timeout (minutes)</label>
                <input
                  type="number"
                  value={settings.sessionPolicy.sessionTimeoutMinutes}
                  onChange={(e) => setSettings({
                    ...settings,
                    sessionPolicy: { ...settings.sessionPolicy, sessionTimeoutMinutes: parseInt(e.target.value) }
                  })}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm text-neutral-400 mb-2">Remember Me (days)</label>
                <input
                  type="number"
                  value={settings.sessionPolicy.rememberMeDays}
                  onChange={(e) => setSettings({
                    ...settings,
                    sessionPolicy: { ...settings.sessionPolicy, rememberMeDays: parseInt(e.target.value) }
                  })}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* Password Policy */}
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Key size={20} className="text-emerald-500" />
              Password Policy
            </h2>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-neutral-400 mb-2">Minimum Length</label>
                <input
                  type="number"
                  value={settings.passwordPolicy.minLength}
                  onChange={(e) => setSettings({
                    ...settings,
                    passwordPolicy: { ...settings.passwordPolicy, minLength: parseInt(e.target.value) }
                  })}
                  min={8}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>
            <div className="space-y-2">
              {[
                { key: 'requireUppercase', label: 'Require uppercase letter' },
                { key: 'requireLowercase', label: 'Require lowercase letter' },
                { key: 'requireNumbers', label: 'Require number' },
                { key: 'requireSpecialChars', label: 'Require special character' },
                { key: 'checkBreachDatabase', label: 'Check against breach database (HIBP)' },
              ].map((item) => (
                <label key={item.key} className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={settings.passwordPolicy[item.key as keyof typeof settings.passwordPolicy] as boolean}
                    onChange={(e) => setSettings({
                      ...settings,
                      passwordPolicy: { ...settings.passwordPolicy, [item.key]: e.target.checked }
                    })}
                    className="rounded border-neutral-600 bg-neutral-800 text-emerald-500 focus:ring-emerald-500"
                  />
                  <span className="text-neutral-300">{item.label}</span>
                </label>
              ))}
            </div>
          </div>
        </motion.div>
      )}

      {/* Branding Tab */}
      {activeTab === 'branding' && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Palette size={20} className="text-emerald-500" />
              Brand Colors
            </h2>
            <div>
              <label className="block text-sm text-neutral-400 mb-2">Primary Color</label>
              <div className="flex items-center gap-3">
                <input
                  type="color"
                  value={settings.branding.primaryColor}
                  onChange={(e) => setSettings({
                    ...settings,
                    branding: { ...settings.branding, primaryColor: e.target.value }
                  })}
                  className="w-12 h-12 rounded-lg cursor-pointer border-0"
                />
                <input
                  type="text"
                  value={settings.branding.primaryColor}
                  onChange={(e) => setSettings({
                    ...settings,
                    branding: { ...settings.branding, primaryColor: e.target.value }
                  })}
                  className="px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white font-mono focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm text-neutral-400 mb-2">Logo URL</label>
              <input
                type="text"
                value={settings.branding.logoUrl}
                onChange={(e) => setSettings({
                  ...settings,
                  branding: { ...settings.branding, logoUrl: e.target.value }
                })}
                placeholder="https://example.com/logo.svg"
                className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
              />
            </div>
          </div>
        </motion.div>
      )}

      {/* Email Tab */}
      {activeTab === 'email' && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Mail size={20} className="text-emerald-500" />
              Email Settings
            </h2>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-neutral-400 mb-2">From Name</label>
                <input
                  type="text"
                  value={settings.emailSettings.fromName}
                  onChange={(e) => setSettings({
                    ...settings,
                    emailSettings: { ...settings.emailSettings, fromName: e.target.value }
                  })}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm text-neutral-400 mb-2">From Email</label>
                <input
                  type="email"
                  value={settings.emailSettings.fromEmail}
                  onChange={(e) => setSettings({
                    ...settings,
                    emailSettings: { ...settings.emailSettings, fromEmail: e.target.value }
                  })}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-sm text-neutral-400 mb-2">Reply-To Email</label>
                <input
                  type="email"
                  value={settings.emailSettings.replyTo}
                  onChange={(e) => setSettings({
                    ...settings,
                    emailSettings: { ...settings.emailSettings, replyTo: e.target.value }
                  })}
                  className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
