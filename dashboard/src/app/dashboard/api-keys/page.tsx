'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Key, Plus, Copy, Eye, EyeOff, Trash2, RefreshCw, 
  CheckCircle, AlertTriangle, Clock, Shield
} from 'lucide-react';

interface APIKey {
  id: string;
  name: string;
  key: string;
  prefix: string;
  type: 'publishable' | 'secret';
  createdAt: string;
  lastUsed: string | null;
  expiresAt: string | null;
  scopes: string[];
}

export default function APIKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyType, setNewKeyType] = useState<'publishable' | 'secret'>('publishable');
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>(['read:users']);
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    fetchKeys();
  }, []);

  const fetchKeys = async () => {
    try {
      const res = await fetch('/api/dashboard/api-keys');
      if (res.ok) {
        const data = await res.json();
        setKeys(data.keys || []);
      }
    } catch (error) {
      console.error('Failed to fetch API keys:', error);
    } finally {
      setLoading(false);
    }
  };

  const createKey = async () => {
    try {
      const res = await fetch('/api/dashboard/api-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName, type: newKeyType, scopes: newKeyScopes }),
      });
      if (res.ok) {
        const data = await res.json();
        setCreatedKey(data.key);
        fetchKeys();
      }
    } catch (error) {
      console.error('Failed to create API key:', error);
    }
  };

  const revokeKey = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) return;
    try {
      await fetch(`/api/dashboard/api-keys/${id}`, { method: 'DELETE' });
      fetchKeys();
    } catch (error) {
      console.error('Failed to revoke API key:', error);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const toggleKeyVisibility = (id: string) => {
    setVisibleKeys(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const availableScopes = [
    { id: 'read:users', label: 'Read Users', description: 'View user information' },
    { id: 'write:users', label: 'Write Users', description: 'Create and update users' },
    { id: 'delete:users', label: 'Delete Users', description: 'Delete user accounts' },
    { id: 'read:sessions', label: 'Read Sessions', description: 'View active sessions' },
    { id: 'write:sessions', label: 'Write Sessions', description: 'Manage sessions' },
    { id: 'read:analytics', label: 'Read Analytics', description: 'View analytics data' },
    { id: 'admin:all', label: 'Admin Access', description: 'Full administrative access' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">API Keys</h1>
          <p className="text-neutral-400 mt-1">Manage your API keys for programmatic access</p>
        </div>
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium"
        >
          <Plus size={18} />
          Create API Key
        </motion.button>
      </div>

      {/* Security Notice */}
      <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4 flex items-start gap-3">
        <AlertTriangle size={20} className="text-amber-500 mt-0.5" />
        <div>
          <p className="text-amber-400 font-medium">Keep your secret keys safe</p>
          <p className="text-amber-400/70 text-sm mt-1">
            Secret keys can access your account. Never share them or commit them to version control.
            Use environment variables instead.
          </p>
        </div>
      </div>

      {/* Keys List */}
      <div className="space-y-4">
        {loading ? (
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-8 text-center">
            <RefreshCw size={24} className="text-emerald-500 animate-spin mx-auto" />
            <p className="text-neutral-400 mt-2">Loading API keys...</p>
          </div>
        ) : keys.length === 0 ? (
          <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-8 text-center">
            <Key size={48} className="text-neutral-600 mx-auto mb-4" />
            <h3 className="text-white font-medium">No API keys yet</h3>
            <p className="text-neutral-400 text-sm mt-1">Create your first API key to get started</p>
          </div>
        ) : (
          keys.map((key) => (
            <motion.div
              key={key.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-4">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                    key.type === 'secret' ? 'bg-red-500/10' : 'bg-emerald-500/10'
                  }`}>
                    <Key size={20} className={key.type === 'secret' ? 'text-red-400' : 'text-emerald-400'} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-white font-medium">{key.name}</h3>
                      <span className={`px-2 py-0.5 rounded text-xs font-mono ${
                        key.type === 'secret' 
                          ? 'bg-red-500/20 text-red-400' 
                          : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {key.type}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      <code className="text-sm text-neutral-400 font-mono bg-neutral-800 px-2 py-1 rounded">
                        {visibleKeys.has(key.id) ? key.key : `${key.prefix}${'•'.repeat(32)}`}
                      </code>
                      <button
                        onClick={() => toggleKeyVisibility(key.id)}
                        className="p-1 text-neutral-500 hover:text-white"
                      >
                        {visibleKeys.has(key.id) ? <EyeOff size={14} /> : <Eye size={14} />}
                      </button>
                      <button
                        onClick={() => copyToClipboard(key.key, key.id)}
                        className="p-1 text-neutral-500 hover:text-emerald-400"
                      >
                        {copiedId === key.id ? <CheckCircle size={14} className="text-emerald-400" /> : <Copy size={14} />}
                      </button>
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-xs text-neutral-500">
                      <span className="flex items-center gap-1">
                        <Clock size={12} />
                        Created {new Date(key.createdAt).toLocaleDateString()}
                      </span>
                      {key.lastUsed && (
                        <span>Last used {new Date(key.lastUsed).toLocaleDateString()}</span>
                      )}
                    </div>
                    {key.scopes.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {key.scopes.map(scope => (
                          <span key={scope} className="px-2 py-0.5 bg-neutral-800 text-neutral-400 text-xs rounded">
                            {scope}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => revokeKey(key.id)}
                  className="p-2 text-neutral-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                >
                  <Trash2 size={18} />
                </button>
              </div>
            </motion.div>
          ))
        )}
      </div>

      {/* Create Modal */}
      <AnimatePresence>
        {showCreateModal && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => { setShowCreateModal(false); setCreatedKey(null); }}
              className="fixed inset-0 bg-black/60 z-50"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4"
            >
              <div className="bg-neutral-900 border border-emerald-500/20 rounded-xl w-full max-w-lg p-6" onClick={e => e.stopPropagation()}>
                {createdKey ? (
                  <div className="text-center">
                    <div className="w-16 h-16 bg-emerald-500/10 rounded-full flex items-center justify-center mx-auto mb-4">
                      <CheckCircle size={32} className="text-emerald-400" />
                    </div>
                    <h2 className="text-xl font-bold text-white mb-2">API Key Created</h2>
                    <p className="text-neutral-400 text-sm mb-4">
                      Copy your API key now. You won't be able to see it again!
                    </p>
                    <div className="bg-neutral-800 rounded-lg p-4 mb-4">
                      <code className="text-emerald-400 font-mono text-sm break-all">{createdKey}</code>
                    </div>
                    <div className="flex gap-3">
                      <button
                        onClick={() => copyToClipboard(createdKey, 'new')}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium"
                      >
                        {copiedId === 'new' ? <CheckCircle size={18} /> : <Copy size={18} />}
                        {copiedId === 'new' ? 'Copied!' : 'Copy Key'}
                      </button>
                      <button
                        onClick={() => { setShowCreateModal(false); setCreatedKey(null); }}
                        className="px-4 py-2 border border-neutral-700 text-neutral-300 rounded-lg"
                      >
                        Done
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <h2 className="text-xl font-bold text-white mb-4">Create API Key</h2>
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm text-neutral-400 mb-2">Key Name</label>
                        <input
                          type="text"
                          value={newKeyName}
                          onChange={(e) => setNewKeyName(e.target.value)}
                          placeholder="e.g., Production Backend"
                          className="w-full px-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
                        />
                      </div>
                      <div>
                        <label className="block text-sm text-neutral-400 mb-2">Key Type</label>
                        <div className="grid grid-cols-2 gap-3">
                          {(['publishable', 'secret'] as const).map(type => (
                            <button
                              key={type}
                              onClick={() => setNewKeyType(type)}
                              className={`p-3 rounded-lg border text-left transition-colors ${
                                newKeyType === type
                                  ? 'border-emerald-500 bg-emerald-500/10'
                                  : 'border-neutral-700 hover:border-neutral-600'
                              }`}
                            >
                              <div className="flex items-center gap-2">
                                <Shield size={16} className={newKeyType === type ? 'text-emerald-400' : 'text-neutral-500'} />
                                <span className={`font-medium capitalize ${newKeyType === type ? 'text-white' : 'text-neutral-400'}`}>
                                  {type}
                                </span>
                              </div>
                              <p className="text-xs text-neutral-500 mt-1">
                                {type === 'publishable' ? 'Safe for client-side' : 'Server-side only'}
                              </p>
                            </button>
                          ))}
                        </div>
                      </div>
                      <div>
                        <label className="block text-sm text-neutral-400 mb-2">Scopes</label>
                        <div className="space-y-2 max-h-48 overflow-y-auto">
                          {availableScopes.map(scope => (
                            <label
                              key={scope.id}
                              className="flex items-start gap-3 p-2 rounded-lg hover:bg-neutral-800 cursor-pointer"
                            >
                              <input
                                type="checkbox"
                                checked={newKeyScopes.includes(scope.id)}
                                onChange={(e) => {
                                  if (e.target.checked) {
                                    setNewKeyScopes([...newKeyScopes, scope.id]);
                                  } else {
                                    setNewKeyScopes(newKeyScopes.filter(s => s !== scope.id));
                                  }
                                }}
                                className="mt-1 rounded border-neutral-600 bg-neutral-800 text-emerald-500 focus:ring-emerald-500"
                              />
                              <div>
                                <p className="text-sm text-white">{scope.label}</p>
                                <p className="text-xs text-neutral-500">{scope.description}</p>
                              </div>
                            </label>
                          ))}
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-3 mt-6">
                      <button
                        onClick={() => setShowCreateModal(false)}
                        className="flex-1 px-4 py-2 border border-neutral-700 text-neutral-300 rounded-lg"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={createKey}
                        disabled={!newKeyName}
                        className="flex-1 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium disabled:opacity-50"
                      >
                        Create Key
                      </button>
                    </div>
                  </>
                )}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
