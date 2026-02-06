'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Webhook, Plus, Trash2, Edit2, Play, CheckCircle, 
  XCircle, Clock, RefreshCw, Copy, Eye, EyeOff,
  AlertTriangle, ExternalLink
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  secret: string;
  createdAt: string;
  lastDelivery?: {
    timestamp: string;
    status: 'success' | 'failed';
    responseCode?: number;
    duration?: number;
  };
  deliveryStats: {
    total: number;
    successful: number;
    failed: number;
  };
}

interface DeliveryLog {
  id: string;
  webhookId: string;
  event: string;
  timestamp: string;
  status: 'success' | 'failed' | 'pending';
  responseCode?: number;
  duration?: number;
  requestBody?: string;
  responseBody?: string;
  error?: string;
}

// ============================================================================
// Event Types
// ============================================================================

const EVENT_TYPES = [
  { value: 'user.created', label: 'User Created', description: 'When a new user registers' },
  { value: 'user.updated', label: 'User Updated', description: 'When user profile is updated' },
  { value: 'user.deleted', label: 'User Deleted', description: 'When a user is deleted' },
  { value: 'session.created', label: 'Session Created', description: 'When a user logs in' },
  { value: 'session.revoked', label: 'Session Revoked', description: 'When a session is terminated' },
  { value: 'mfa.enabled', label: 'MFA Enabled', description: 'When MFA is enabled for a user' },
  { value: 'mfa.disabled', label: 'MFA Disabled', description: 'When MFA is disabled' },
  { value: 'password.changed', label: 'Password Changed', description: 'When password is changed' },
  { value: 'password.reset', label: 'Password Reset', description: 'When password is reset' },
  { value: 'member.invited', label: 'Member Invited', description: 'When a member is invited to tenant' },
  { value: 'member.joined', label: 'Member Joined', description: 'When invitation is accepted' },
  { value: 'member.removed', label: 'Member Removed', description: 'When a member is removed' },
  { value: 'role.changed', label: 'Role Changed', description: 'When member role is changed' },
];

// ============================================================================
// Mock Data (Replace with API calls)
// ============================================================================

const mockWebhooks: WebhookConfig[] = [
  {
    id: 'wh_1',
    name: 'User Events',
    url: 'https://api.clinisyn.com/webhooks/zalt',
    events: ['user.created', 'user.updated', 'user.deleted'],
    enabled: true,
    secret: 'whsec_abc123def456',
    createdAt: '2026-01-15T10:00:00Z',
    lastDelivery: {
      timestamp: '2026-02-01T09:45:00Z',
      status: 'success',
      responseCode: 200,
      duration: 145
    },
    deliveryStats: { total: 1250, successful: 1245, failed: 5 }
  },
  {
    id: 'wh_2',
    name: 'Security Events',
    url: 'https://api.clinisyn.com/webhooks/security',
    events: ['session.created', 'session.revoked', 'mfa.enabled', 'mfa.disabled'],
    enabled: true,
    secret: 'whsec_xyz789ghi012',
    createdAt: '2026-01-20T14:30:00Z',
    lastDelivery: {
      timestamp: '2026-02-01T09:30:00Z',
      status: 'success',
      responseCode: 200,
      duration: 89
    },
    deliveryStats: { total: 3420, successful: 3418, failed: 2 }
  }
];

const mockDeliveryLogs: DeliveryLog[] = [
  {
    id: 'dl_1',
    webhookId: 'wh_1',
    event: 'user.created',
    timestamp: '2026-02-01T09:45:00Z',
    status: 'success',
    responseCode: 200,
    duration: 145,
    requestBody: '{"event":"user.created","data":{"id":"user_123","email":"test@example.com"}}',
    responseBody: '{"received":true}'
  },
  {
    id: 'dl_2',
    webhookId: 'wh_2',
    event: 'session.created',
    timestamp: '2026-02-01T09:30:00Z',
    status: 'success',
    responseCode: 200,
    duration: 89
  },
  {
    id: 'dl_3',
    webhookId: 'wh_1',
    event: 'user.updated',
    timestamp: '2026-02-01T09:15:00Z',
    status: 'failed',
    responseCode: 500,
    duration: 2500,
    error: 'Internal Server Error'
  }
];

// ============================================================================
// Components
// ============================================================================

function WebhookCard({ 
  webhook, 
  onEdit, 
  onDelete, 
  onTest, 
  onToggle,
  onViewLogs 
}: { 
  webhook: WebhookConfig;
  onEdit: () => void;
  onDelete: () => void;
  onTest: () => void;
  onToggle: () => void;
  onViewLogs: () => void;
}) {
  const [showSecret, setShowSecret] = useState(false);
  const [copied, setCopied] = useState(false);

  const copySecret = () => {
    navigator.clipboard.writeText(webhook.secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const successRate = webhook.deliveryStats.total > 0 
    ? ((webhook.deliveryStats.successful / webhook.deliveryStats.total) * 100).toFixed(1)
    : '100';

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-neutral-900 border border-emerald-500/10 rounded-xl p-6"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${webhook.enabled ? 'bg-emerald-500/10' : 'bg-neutral-800'}`}>
            <Webhook className={webhook.enabled ? 'text-emerald-400' : 'text-neutral-500'} size={20} />
          </div>
          <div>
            <h3 className="text-white font-medium">{webhook.name}</h3>
            <p className="text-sm text-neutral-500 truncate max-w-xs">{webhook.url}</p>
          </div>
        </div>
        <button
          onClick={onToggle}
          className={`relative w-12 h-6 rounded-full transition-colors ${
            webhook.enabled ? 'bg-emerald-500' : 'bg-neutral-700'
          }`}
        >
          <span className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${
            webhook.enabled ? 'left-7' : 'left-1'
          }`} />
        </button>
      </div>

      {/* Events */}
      <div className="mb-4">
        <p className="text-xs text-neutral-500 mb-2">Events</p>
        <div className="flex flex-wrap gap-1">
          {webhook.events.map(event => (
            <span 
              key={event}
              className="px-2 py-0.5 text-xs bg-neutral-800 text-neutral-300 rounded"
            >
              {event}
            </span>
          ))}
        </div>
      </div>

      {/* Secret */}
      <div className="mb-4">
        <p className="text-xs text-neutral-500 mb-2">Signing Secret</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 px-3 py-1.5 bg-neutral-800 rounded text-sm text-neutral-300 font-mono">
            {showSecret ? webhook.secret : '••••••••••••••••'}
          </code>
          <button
            onClick={() => setShowSecret(!showSecret)}
            className="p-1.5 text-neutral-500 hover:text-white"
          >
            {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
          <button
            onClick={copySecret}
            className="p-1.5 text-neutral-500 hover:text-white"
          >
            {copied ? <CheckCircle size={16} className="text-emerald-400" /> : <Copy size={16} />}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4 mb-4 p-3 bg-neutral-800/50 rounded-lg">
        <div>
          <p className="text-xs text-neutral-500">Total</p>
          <p className="text-lg font-semibold text-white">{webhook.deliveryStats.total.toLocaleString()}</p>
        </div>
        <div>
          <p className="text-xs text-neutral-500">Success Rate</p>
          <p className={`text-lg font-semibold ${parseFloat(successRate) >= 99 ? 'text-emerald-400' : 'text-yellow-400'}`}>
            {successRate}%
          </p>
        </div>
        <div>
          <p className="text-xs text-neutral-500">Last Delivery</p>
          {webhook.lastDelivery ? (
            <div className="flex items-center gap-1">
              {webhook.lastDelivery.status === 'success' ? (
                <CheckCircle size={14} className="text-emerald-400" />
              ) : (
                <XCircle size={14} className="text-red-400" />
              )}
              <span className="text-sm text-neutral-300">{webhook.lastDelivery.duration}ms</span>
            </div>
          ) : (
            <span className="text-sm text-neutral-500">Never</span>
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2">
        <button
          onClick={onTest}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-500/10 text-emerald-400 rounded-lg hover:bg-emerald-500/20 transition-colors text-sm"
        >
          <Play size={14} />
          Test
        </button>
        <button
          onClick={onViewLogs}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-neutral-800 text-neutral-300 rounded-lg hover:bg-neutral-700 transition-colors text-sm"
        >
          <Clock size={14} />
          Logs
        </button>
        <button
          onClick={onEdit}
          className="p-1.5 text-neutral-500 hover:text-white"
        >
          <Edit2 size={16} />
        </button>
        <button
          onClick={onDelete}
          className="p-1.5 text-neutral-500 hover:text-red-400"
        >
          <Trash2 size={16} />
        </button>
      </div>
    </motion.div>
  );
}

function WebhookModal({ 
  webhook, 
  onClose, 
  onSave 
}: { 
  webhook?: WebhookConfig;
  onClose: () => void;
  onSave: (data: Partial<WebhookConfig>) => void;
}) {
  const [name, setName] = useState(webhook?.name || '');
  const [url, setUrl] = useState(webhook?.url || '');
  const [events, setEvents] = useState<string[]>(webhook?.events || []);
  const [urlError, setUrlError] = useState('');

  const validateUrl = (value: string) => {
    if (!value.startsWith('https://')) {
      setUrlError('URL must use HTTPS');
      return false;
    }
    setUrlError('');
    return true;
  };

  const handleSave = () => {
    if (!validateUrl(url)) return;
    if (!name || !url || events.length === 0) return;
    
    onSave({ name, url, events });
  };

  const toggleEvent = (event: string) => {
    setEvents(prev => 
      prev.includes(event) 
        ? prev.filter(e => e !== event)
        : [...prev, event]
    );
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        onClick={e => e.stopPropagation()}
        className="bg-neutral-900 border border-emerald-500/20 rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto"
      >
        <div className="p-6 border-b border-emerald-500/10">
          <h2 className="text-xl font-semibold text-white">
            {webhook ? 'Edit Webhook' : 'Create Webhook'}
          </h2>
        </div>

        <div className="p-6 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-sm text-neutral-400 mb-1.5">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g., User Events"
              className="w-full px-4 py-2.5 bg-neutral-800 border border-neutral-700 rounded-lg text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>

          {/* URL */}
          <div>
            <label className="block text-sm text-neutral-400 mb-1.5">Endpoint URL</label>
            <input
              type="url"
              value={url}
              onChange={e => {
                setUrl(e.target.value);
                validateUrl(e.target.value);
              }}
              placeholder="https://api.example.com/webhooks"
              className={`w-full px-4 py-2.5 bg-neutral-800 border rounded-lg text-white placeholder-neutral-500 focus:outline-none ${
                urlError ? 'border-red-500' : 'border-neutral-700 focus:border-emerald-500'
              }`}
            />
            {urlError && (
              <p className="mt-1 text-sm text-red-400 flex items-center gap-1">
                <AlertTriangle size={14} />
                {urlError}
              </p>
            )}
          </div>

          {/* Events */}
          <div>
            <label className="block text-sm text-neutral-400 mb-1.5">Events</label>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {EVENT_TYPES.map(event => (
                <label
                  key={event.value}
                  className={`flex items-start gap-3 p-3 rounded-lg cursor-pointer transition-colors ${
                    events.includes(event.value)
                      ? 'bg-emerald-500/10 border border-emerald-500/20'
                      : 'bg-neutral-800 border border-transparent hover:border-neutral-700'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={events.includes(event.value)}
                    onChange={() => toggleEvent(event.value)}
                    className="mt-0.5 accent-emerald-500"
                  />
                  <div>
                    <p className="text-sm text-white">{event.label}</p>
                    <p className="text-xs text-neutral-500">{event.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="p-6 border-t border-emerald-500/10 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-neutral-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={!name || !url || events.length === 0 || !!urlError}
            className="px-4 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {webhook ? 'Save Changes' : 'Create Webhook'}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

function DeliveryLogsModal({ 
  webhook, 
  logs, 
  onClose 
}: { 
  webhook: WebhookConfig;
  logs: DeliveryLog[];
  onClose: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        onClick={e => e.stopPropagation()}
        className="bg-neutral-900 border border-emerald-500/20 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-hidden"
      >
        <div className="p-6 border-b border-emerald-500/10 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-white">Delivery Logs</h2>
            <p className="text-sm text-neutral-500">{webhook.name}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-neutral-500 hover:text-white"
          >
            <XCircle size={20} />
          </button>
        </div>

        <div className="overflow-y-auto max-h-[60vh]">
          {logs.length === 0 ? (
            <div className="p-8 text-center text-neutral-500">
              No delivery logs yet
            </div>
          ) : (
            <div className="divide-y divide-neutral-800">
              {logs.map(log => (
                <div key={log.id} className="p-4 hover:bg-neutral-800/50">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {log.status === 'success' ? (
                        <CheckCircle size={16} className="text-emerald-400" />
                      ) : log.status === 'failed' ? (
                        <XCircle size={16} className="text-red-400" />
                      ) : (
                        <Clock size={16} className="text-yellow-400" />
                      )}
                      <span className="text-sm font-medium text-white">{log.event}</span>
                    </div>
                    <span className="text-xs text-neutral-500">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-neutral-400">
                    {log.responseCode && (
                      <span className={log.responseCode < 400 ? 'text-emerald-400' : 'text-red-400'}>
                        HTTP {log.responseCode}
                      </span>
                    )}
                    {log.duration && <span>{log.duration}ms</span>}
                    {log.error && <span className="text-red-400">{log.error}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}

// ============================================================================
// Main Page
// ============================================================================

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>(mockWebhooks);
  const [deliveryLogs] = useState<DeliveryLog[]>(mockDeliveryLogs);
  const [showModal, setShowModal] = useState(false);
  const [editingWebhook, setEditingWebhook] = useState<WebhookConfig | undefined>();
  const [showLogsFor, setShowLogsFor] = useState<WebhookConfig | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  const handleCreate = () => {
    setEditingWebhook(undefined);
    setShowModal(true);
  };

  const handleEdit = (webhook: WebhookConfig) => {
    setEditingWebhook(webhook);
    setShowModal(true);
  };

  const handleSave = (data: Partial<WebhookConfig>) => {
    if (editingWebhook) {
      setWebhooks(prev => prev.map(w => 
        w.id === editingWebhook.id ? { ...w, ...data } : w
      ));
    } else {
      const newWebhook: WebhookConfig = {
        id: `wh_${Date.now()}`,
        name: data.name!,
        url: data.url!,
        events: data.events!,
        enabled: true,
        secret: `whsec_${Math.random().toString(36).substring(2, 18)}`,
        createdAt: new Date().toISOString(),
        deliveryStats: { total: 0, successful: 0, failed: 0 }
      };
      setWebhooks(prev => [...prev, newWebhook]);
    }
    setShowModal(false);
  };

  const handleDelete = (id: string) => {
    if (confirm('Are you sure you want to delete this webhook?')) {
      setWebhooks(prev => prev.filter(w => w.id !== id));
    }
  };

  const handleToggle = (id: string) => {
    setWebhooks(prev => prev.map(w => 
      w.id === id ? { ...w, enabled: !w.enabled } : w
    ));
  };

  const handleTest = async (webhook: WebhookConfig) => {
    setTesting(webhook.id);
    // Simulate test request
    await new Promise(resolve => setTimeout(resolve, 1500));
    setTesting(null);
    // Show success toast (in real app)
    alert('Test webhook sent successfully!');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Webhooks</h1>
          <p className="text-neutral-500">Receive real-time notifications for events</p>
        </div>
        <button
          onClick={handleCreate}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 transition-colors"
        >
          <Plus size={18} />
          Add Webhook
        </button>
      </div>

      {/* Documentation Link */}
      <div className="p-4 bg-neutral-900 border border-emerald-500/10 rounded-xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 rounded-lg">
            <Webhook className="text-emerald-400" size={20} />
          </div>
          <div>
            <p className="text-white font-medium">Webhook Documentation</p>
            <p className="text-sm text-neutral-500">Learn how to verify webhook signatures and handle events</p>
          </div>
        </div>
        <a
          href="/docs/configuration/webhooks"
          className="flex items-center gap-1.5 px-3 py-1.5 text-emerald-400 hover:text-emerald-300 transition-colors text-sm"
        >
          View Docs
          <ExternalLink size={14} />
        </a>
      </div>

      {/* Webhooks Grid */}
      {webhooks.length === 0 ? (
        <div className="text-center py-12">
          <Webhook className="mx-auto text-neutral-600 mb-4" size={48} />
          <h3 className="text-lg font-medium text-white mb-2">No webhooks configured</h3>
          <p className="text-neutral-500 mb-4">Create your first webhook to receive event notifications</p>
          <button
            onClick={handleCreate}
            className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 transition-colors"
          >
            <Plus size={18} />
            Add Webhook
          </button>
        </div>
      ) : (
        <div className="grid gap-6 md:grid-cols-2">
          {webhooks.map(webhook => (
            <WebhookCard
              key={webhook.id}
              webhook={webhook}
              onEdit={() => handleEdit(webhook)}
              onDelete={() => handleDelete(webhook.id)}
              onTest={() => handleTest(webhook)}
              onToggle={() => handleToggle(webhook.id)}
              onViewLogs={() => setShowLogsFor(webhook)}
            />
          ))}
        </div>
      )}

      {/* Modals */}
      <AnimatePresence>
        {showModal && (
          <WebhookModal
            webhook={editingWebhook}
            onClose={() => setShowModal(false)}
            onSave={handleSave}
          />
        )}
        {showLogsFor && (
          <DeliveryLogsModal
            webhook={showLogsFor}
            logs={deliveryLogs.filter(l => l.webhookId === showLogsFor.id)}
            onClose={() => setShowLogsFor(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
