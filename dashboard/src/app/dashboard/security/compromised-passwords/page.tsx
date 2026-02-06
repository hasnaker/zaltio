'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';
import { 
  Shield, AlertTriangle, Users, RefreshCw, 
  Search, Filter, ChevronRight, CheckCircle, 
  XCircle, Clock, AlertCircle, Key, Mail,
  ShieldAlert, ShieldCheck, RotateCcw, Loader2
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

interface CompromisedUser {
  id: string;
  email: string;
  name?: string;
  status: 'compromised' | 'pending_reset' | 'resolved';
  breachCount: number;
  lastChecked: string;
  compromisedAt: string;
  resetRequestedAt?: string;
  resetCompletedAt?: string;
}

interface CompromisedPasswordStats {
  totalUsers: number;
  compromisedCount: number;
  pendingResets: number;
  resolvedCount: number;
  lastBreachCheckAt: string;
}

interface CompromisedPasswordsData {
  stats: CompromisedPasswordStats;
  users: CompromisedUser[];
}

// ============================================================================
// Helper Functions
// ============================================================================

function getStatusColor(status: string): string {
  switch (status) {
    case 'compromised': return 'text-red-400';
    case 'pending_reset': return 'text-yellow-400';
    case 'resolved': return 'text-emerald-400';
    default: return 'text-neutral-400';
  }
}

function getStatusBg(status: string): string {
  switch (status) {
    case 'compromised': return 'bg-red-500/10 border-red-500/20';
    case 'pending_reset': return 'bg-yellow-500/10 border-yellow-500/20';
    case 'resolved': return 'bg-emerald-500/10 border-emerald-500/20';
    default: return 'bg-neutral-500/10 border-neutral-500/20';
  }
}

function getStatusIcon(status: string) {
  switch (status) {
    case 'compromised': return ShieldAlert;
    case 'pending_reset': return Clock;
    case 'resolved': return ShieldCheck;
    default: return Shield;
  }
}

function getStatusLabel(status: string): string {
  switch (status) {
    case 'compromised': return 'Compromised';
    case 'pending_reset': return 'Pending Reset';
    case 'resolved': return 'Resolved';
    default: return status;
  }
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

// ============================================================================
// Components
// ============================================================================

function ConfirmationModal({ 
  isOpen, 
  onClose, 
  onConfirm, 
  title, 
  message, 
  confirmText,
  isLoading,
  variant = 'danger'
}: {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmText: string;
  isLoading?: boolean;
  variant?: 'danger' | 'warning';
}) {
  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
          className="bg-neutral-900 border border-emerald-500/20 rounded-lg p-6 max-w-md w-full"
        >
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
              variant === 'danger' ? 'bg-red-500/10 border border-red-500/20' : 'bg-yellow-500/10 border border-yellow-500/20'
            }`}>
              <AlertTriangle className={variant === 'danger' ? 'text-red-400' : 'text-yellow-400'} size={20} />
            </div>
            <h3 className="font-outfit text-lg font-semibold text-white">{title}</h3>
          </div>
          <p className="text-neutral-400 text-sm mb-6">{message}</p>
          <div className="flex gap-3 justify-end">
            <button
              onClick={onClose}
              disabled={isLoading}
              className="px-4 py-2 text-sm text-neutral-400 hover:text-white hover:bg-neutral-800 rounded-lg transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              onClick={onConfirm}
              disabled={isLoading}
              className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 ${
                variant === 'danger' 
                  ? 'bg-red-500 text-white hover:bg-red-600' 
                  : 'bg-yellow-500 text-neutral-950 hover:bg-yellow-400'
              }`}
            >
              {isLoading && <Loader2 size={14} className="animate-spin" />}
              {confirmText}
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

function Toast({ 
  message, 
  type, 
  onClose 
}: { 
  message: string; 
  type: 'success' | 'error'; 
  onClose: () => void;
}) {
  useEffect(() => {
    const timer = setTimeout(onClose, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 50 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 50 }}
      className={`fixed bottom-4 right-4 z-50 px-4 py-3 rounded-lg border flex items-center gap-3 ${
        type === 'success' 
          ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
          : 'bg-red-500/10 border-red-500/20 text-red-400'
      }`}
    >
      {type === 'success' ? <CheckCircle size={18} /> : <XCircle size={18} />}
      <span className="text-sm">{message}</span>
      <button onClick={onClose} className="ml-2 hover:opacity-70">
        <XCircle size={16} />
      </button>
    </motion.div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function CompromisedPasswordsPage() {
  const [data, setData] = useState<CompromisedPasswordsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  
  // Modal states
  const [forceResetModal, setForceResetModal] = useState<{ isOpen: boolean; user: CompromisedUser | null }>({ isOpen: false, user: null });
  const [massResetModal, setMassResetModal] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  
  // Toast state
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setRefreshing(true);
      const params = new URLSearchParams({ status: statusFilter });
      
      const response = await fetch(`/api/dashboard/security/compromised-passwords?${params}`);
      if (!response.ok) {
        throw new Error('Failed to fetch compromised password data');
      }
      const result = await response.json();
      setData(result);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Filter users based on search
  const filteredUsers = data?.users.filter(user => 
    !searchQuery || 
    user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    user.name?.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  // Handle force password reset for individual user
  const handleForceReset = async () => {
    if (!forceResetModal.user) return;
    
    setActionLoading(true);
    try {
      const response = await fetch('/api/dashboard/security/compromised-passwords', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: forceResetModal.user.id,
          reason: 'Admin forced password reset',
          revokeSessions: true,
          notifyUser: true,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to force password reset');
      }

      const result = await response.json();
      setToast({ message: result.message || 'Password reset forced successfully', type: 'success' });
      setForceResetModal({ isOpen: false, user: null });
      fetchData(); // Refresh data
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : 'Failed to force password reset', type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  // Handle mass password reset
  const handleMassReset = async () => {
    setActionLoading(true);
    try {
      const response = await fetch('/api/dashboard/security/compromised-passwords/all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: 'Security incident - mass password reset',
          revokeSessions: true,
          confirm: true,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to perform mass password reset');
      }

      const result = await response.json();
      setToast({ 
        message: `Mass password reset completed. ${result.affectedUsers} users affected.`, 
        type: 'success' 
      });
      setMassResetModal(false);
      fetchData(); // Refresh data
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : 'Failed to perform mass password reset', type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  const hasData = data && (data.stats.compromisedCount > 0 || data.stats.pendingResets > 0 || data.stats.resolvedCount > 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="font-outfit text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="text-red-500" size={28} />
            Compromised Passwords
          </h1>
          <p className="text-neutral-400 text-sm mt-1">
            Monitor and manage users with compromised passwords detected via HaveIBeenPwned.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setMassResetModal(true)}
            className="px-4 py-2 text-sm font-medium bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors flex items-center gap-2"
          >
            <RotateCcw size={16} />
            Mass Password Reset
          </button>
          <button
            onClick={fetchData}
            disabled={refreshing}
            className="p-2 text-neutral-400 hover:text-white hover:bg-neutral-800 rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={18} className={refreshing ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Error State */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 flex items-center gap-3"
        >
          <AlertCircle className="text-red-400" size={20} />
          <span className="text-red-400 text-sm">{error}</span>
        </motion.div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-5 animate-pulse">
              <div className="h-4 bg-neutral-800 rounded w-1/2 mb-4" />
              <div className="h-8 bg-neutral-800 rounded w-2/3" />
            </div>
          ))}
        </div>
      )}

      {/* Stats Grid */}
      {!loading && data && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { 
              label: 'Total Users', 
              value: data.stats.totalUsers.toLocaleString(), 
              icon: Users,
              color: 'text-emerald-500'
            },
            { 
              label: 'Compromised', 
              value: data.stats.compromisedCount.toLocaleString(), 
              icon: ShieldAlert,
              color: 'text-red-500'
            },
            { 
              label: 'Pending Resets', 
              value: data.stats.pendingResets.toLocaleString(), 
              icon: Clock,
              color: 'text-yellow-500'
            },
            { 
              label: 'Resolved', 
              value: data.stats.resolvedCount.toLocaleString(), 
              icon: ShieldCheck,
              color: 'text-emerald-500'
            },
          ].map((stat, index) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-5"
            >
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-xs text-neutral-500 uppercase tracking-wider">{stat.label}</p>
                  <p className="text-2xl font-outfit font-bold text-white mt-1">{stat.value}</p>
                </div>
                <div className="w-10 h-10 rounded border border-emerald-500/20 bg-emerald-500/5 flex items-center justify-center">
                  <stat.icon size={18} className={stat.color} />
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Last Breach Check Info */}
      {!loading && data && (
        <div className="bg-neutral-900/50 border border-emerald-500/10 rounded-lg px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2 text-sm text-neutral-400">
            <Clock size={14} />
            <span>Last breach check: {formatTimestamp(data.stats.lastBreachCheckAt)}</span>
          </div>
          <Link 
            href="/docs/security/breach-detection"
            className="text-sm text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
          >
            Learn more <ChevronRight size={14} />
          </Link>
        </div>
      )}

      {/* Filters */}
      {!loading && hasData && (
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" size={16} />
            <input
              type="text"
              placeholder="Search by email or name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2.5 bg-neutral-900 border border-emerald-500/10 rounded-lg text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-emerald-500/30"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter size={16} className="text-neutral-500" />
            {['all', 'compromised', 'pending_reset', 'resolved'].map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                  statusFilter === status
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : 'text-neutral-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                {status === 'all' ? 'All' : getStatusLabel(status)}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Empty State */}
      {!loading && !hasData && !error && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-neutral-900 border border-emerald-500/20 rounded-lg p-12 text-center"
        >
          <div className="w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto mb-6">
            <ShieldCheck size={28} className="text-emerald-500" />
          </div>
          <h3 className="font-outfit text-xl font-bold text-white mb-2">No compromised passwords</h3>
          <p className="text-neutral-400 text-sm mb-8 max-w-md mx-auto">
            Great news! No users currently have compromised passwords. 
            The system continuously monitors passwords against the HaveIBeenPwned database.
          </p>
          <Link
            href="/docs/security/breach-detection"
            className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-500 text-neutral-950 font-semibold rounded-lg hover:bg-emerald-400 transition-colors"
          >
            Learn About Breach Detection
            <ChevronRight size={18} />
          </Link>
        </motion.div>
      )}

      {/* Users Table */}
      {!loading && hasData && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden"
        >
          <div className="p-4 border-b border-emerald-500/10 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Key className="text-red-500" size={20} />
              <h2 className="font-outfit font-semibold text-white">Users with Compromised Passwords</h2>
              <span className="px-2 py-0.5 text-xs bg-red-500/10 text-red-400 rounded-full">
                {filteredUsers.length}
              </span>
            </div>
          </div>

          {filteredUsers.length === 0 ? (
            <div className="p-8 text-center">
              <Search className="mx-auto text-neutral-600 mb-3" size={32} />
              <p className="text-neutral-400 text-sm">No users match your search criteria</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-emerald-500/10">
                    <th className="text-left px-4 py-3 text-xs font-mono text-emerald-500/70 uppercase">User</th>
                    <th className="text-left px-4 py-3 text-xs font-mono text-emerald-500/70 uppercase">Status</th>
                    <th className="text-left px-4 py-3 text-xs font-mono text-emerald-500/70 uppercase">Breach Count</th>
                    <th className="text-left px-4 py-3 text-xs font-mono text-emerald-500/70 uppercase">Last Checked</th>
                    <th className="text-right px-4 py-3 text-xs font-mono text-emerald-500/70 uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((user, index) => {
                    const StatusIcon = getStatusIcon(user.status);
                    return (
                      <motion.tr
                        key={user.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: index * 0.05 }}
                        className="border-b border-emerald-500/5 hover:bg-neutral-800/30 transition-colors"
                      >
                        <td className="px-4 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center text-red-400 text-sm font-medium">
                              {(user.name || user.email)[0].toUpperCase()}
                            </div>
                            <div>
                              <p className="text-sm text-white font-medium">{user.name || 'Unknown'}</p>
                              <p className="text-xs text-neutral-500 flex items-center gap-1">
                                <Mail size={10} />
                                {user.email}
                              </p>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-4">
                          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full border ${getStatusBg(user.status)} ${getStatusColor(user.status)}`}>
                            <StatusIcon size={12} />
                            {getStatusLabel(user.status)}
                          </span>
                        </td>
                        <td className="px-4 py-4">
                          <span className="text-sm text-white font-mono">{user.breachCount}</span>
                          <span className="text-xs text-neutral-500 ml-1">breaches</span>
                        </td>
                        <td className="px-4 py-4">
                          <span className="text-xs text-neutral-500 flex items-center gap-1">
                            <Clock size={10} />
                            {formatTimestamp(user.lastChecked)}
                          </span>
                        </td>
                        <td className="px-4 py-4 text-right">
                          {user.status !== 'resolved' && (
                            <button
                              onClick={() => setForceResetModal({ isOpen: true, user })}
                              className="px-3 py-1.5 text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20 rounded hover:bg-red-500/20 transition-colors"
                            >
                              Force Reset
                            </button>
                          )}
                          {user.status === 'resolved' && (
                            <span className="text-xs text-emerald-400 flex items-center gap-1 justify-end">
                              <CheckCircle size={12} />
                              Resolved
                            </span>
                          )}
                        </td>
                      </motion.tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>
      )}

      {/* Force Reset Modal */}
      <ConfirmationModal
        isOpen={forceResetModal.isOpen}
        onClose={() => setForceResetModal({ isOpen: false, user: null })}
        onConfirm={handleForceReset}
        title="Force Password Reset"
        message={`Are you sure you want to force a password reset for ${forceResetModal.user?.email}? This will revoke all their active sessions and require them to set a new password on their next login.`}
        confirmText="Force Reset"
        isLoading={actionLoading}
        variant="warning"
      />

      {/* Mass Reset Modal */}
      <ConfirmationModal
        isOpen={massResetModal}
        onClose={() => setMassResetModal(false)}
        onConfirm={handleMassReset}
        title="Mass Password Reset"
        message="⚠️ CRITICAL OPERATION: This will force ALL users in the realm to reset their passwords. All active sessions will be revoked. This action should only be used during a security incident. Are you absolutely sure?"
        confirmText="Reset All Passwords"
        isLoading={actionLoading}
        variant="danger"
      />

      {/* Toast Notifications */}
      <AnimatePresence>
        {toast && (
          <Toast
            message={toast.message}
            type={toast.type}
            onClose={() => setToast(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
