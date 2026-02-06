'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Users, Search, Filter, MoreVertical, Shield, Mail, 
  Clock, MapPin, Smartphone, Ban, CheckCircle, AlertTriangle,
  ChevronLeft, ChevronRight, Download, UserPlus
} from 'lucide-react';

interface User {
  id: string;
  email: string;
  name?: string;
  avatar?: string;
  status: 'active' | 'suspended' | 'pending';
  emailVerified: boolean;
  mfaEnabled: boolean;
  mfaMethods: string[];
  lastLoginAt?: string;
  lastLoginIp?: string;
  lastLoginLocation?: string;
  lastLoginDevice?: string;
  createdAt: string;
  sessionsCount: number;
}

const mockUsers: User[] = [
  {
    id: 'user_1',
    email: 'john@example.com',
    name: 'John Doe',
    status: 'active',
    emailVerified: true,
    mfaEnabled: true,
    mfaMethods: ['totp', 'webauthn'],
    lastLoginAt: '2026-02-03T10:30:00Z',
    lastLoginIp: '192.168.1.xxx',
    lastLoginLocation: 'Istanbul, Turkey',
    lastLoginDevice: 'Chrome on macOS',
    createdAt: '2026-01-15T08:00:00Z',
    sessionsCount: 2,
  },
  {
    id: 'user_2',
    email: 'jane@example.com',
    name: 'Jane Smith',
    status: 'active',
    emailVerified: true,
    mfaEnabled: false,
    mfaMethods: [],
    lastLoginAt: '2026-02-02T14:20:00Z',
    lastLoginIp: '10.0.0.xxx',
    lastLoginLocation: 'London, UK',
    lastLoginDevice: 'Safari on iOS',
    createdAt: '2026-01-20T12:00:00Z',
    sessionsCount: 1,
  },
  {
    id: 'user_3',
    email: 'bob@example.com',
    name: 'Bob Wilson',
    status: 'suspended',
    emailVerified: true,
    mfaEnabled: true,
    mfaMethods: ['totp'],
    lastLoginAt: '2026-01-28T09:15:00Z',
    lastLoginIp: '172.16.0.xxx',
    lastLoginLocation: 'New York, USA',
    lastLoginDevice: 'Firefox on Windows',
    createdAt: '2026-01-10T16:00:00Z',
    sessionsCount: 0,
  },
  {
    id: 'user_4',
    email: 'alice@example.com',
    status: 'pending',
    emailVerified: false,
    mfaEnabled: false,
    mfaMethods: [],
    createdAt: '2026-02-03T08:00:00Z',
    sessionsCount: 0,
  },
];

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>(mockUsers);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const usersPerPage = 10;

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.name?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || user.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const totalPages = Math.ceil(filteredUsers.length / usersPerPage);
  const paginatedUsers = filteredUsers.slice(
    (currentPage - 1) * usersPerPage,
    currentPage * usersPerPage
  );

  const suspendUser = async (userId: string) => {
    setUsers(users.map(u => u.id === userId ? { ...u, status: 'suspended' as const } : u));
  };

  const activateUser = async (userId: string) => {
    setUsers(users.map(u => u.id === userId ? { ...u, status: 'active' as const } : u));
  };

  const statusColors = {
    active: 'bg-emerald-500/20 text-emerald-400',
    suspended: 'bg-red-500/20 text-red-400',
    pending: 'bg-amber-500/20 text-amber-400',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Users</h1>
          <p className="text-neutral-400 mt-1">Manage your realm users</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 px-4 py-2 border border-neutral-700 text-neutral-300 rounded-lg hover:bg-neutral-800">
            <Download size={18} />
            Export
          </button>
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-500 text-neutral-950 rounded-lg font-medium"
          >
            <UserPlus size={18} />
            Invite User
          </motion.button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by email or name..."
            className="w-full pl-10 pr-4 py-2 bg-neutral-900 border border-emerald-500/10 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter size={18} className="text-neutral-500" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-4 py-2 bg-neutral-900 border border-emerald-500/10 rounded-lg text-white focus:border-emerald-500 focus:outline-none"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
            <option value="pending">Pending</option>
          </select>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Users', value: users.length, color: 'text-white' },
          { label: 'Active', value: users.filter(u => u.status === 'active').length, color: 'text-emerald-400' },
          { label: 'MFA Enabled', value: users.filter(u => u.mfaEnabled).length, color: 'text-blue-400' },
          { label: 'Pending', value: users.filter(u => u.status === 'pending').length, color: 'text-amber-400' },
        ].map((stat, i) => (
          <div key={i} className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-4">
            <p className="text-sm text-neutral-400">{stat.label}</p>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Users Table */}
      <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-emerald-500/10 bg-neutral-800/50">
                <th className="text-left px-4 py-3 text-sm text-neutral-400 font-medium">User</th>
                <th className="text-left px-4 py-3 text-sm text-neutral-400 font-medium">Status</th>
                <th className="text-left px-4 py-3 text-sm text-neutral-400 font-medium">MFA</th>
                <th className="text-left px-4 py-3 text-sm text-neutral-400 font-medium">Last Login</th>
                <th className="text-left px-4 py-3 text-sm text-neutral-400 font-medium">Sessions</th>
                <th className="text-right px-4 py-3 text-sm text-neutral-400 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedUsers.map((user) => (
                <tr 
                  key={user.id} 
                  className="border-b border-emerald-500/5 hover:bg-neutral-800/30 cursor-pointer"
                  onClick={() => setSelectedUser(user)}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-medium">
                        {(user.name || user.email)[0].toUpperCase()}
                      </div>
                      <div>
                        <p className="text-white font-medium">{user.name || user.email.split('@')[0]}</p>
                        <p className="text-sm text-neutral-500">{user.email}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[user.status]}`}>
                      {user.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {user.mfaEnabled ? (
                      <div className="flex items-center gap-1">
                        <Shield size={14} className="text-emerald-400" />
                        <span className="text-sm text-emerald-400">{user.mfaMethods.join(', ')}</span>
                      </div>
                    ) : (
                      <span className="text-sm text-neutral-500">Not enabled</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {user.lastLoginAt ? (
                      <div>
                        <p className="text-sm text-neutral-300">
                          {new Date(user.lastLoginAt).toLocaleDateString()}
                        </p>
                        <p className="text-xs text-neutral-500">{user.lastLoginLocation}</p>
                      </div>
                    ) : (
                      <span className="text-sm text-neutral-500">Never</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-neutral-300">{user.sessionsCount}</span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="relative group">
                      <button 
                        className="p-2 text-neutral-500 hover:text-white hover:bg-neutral-800 rounded-lg"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <MoreVertical size={16} />
                      </button>
                      <div className="absolute right-0 top-full mt-1 w-40 bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10">
                        <button className="w-full px-3 py-2 text-left text-sm text-neutral-300 hover:bg-neutral-700">
                          View Details
                        </button>
                        <button className="w-full px-3 py-2 text-left text-sm text-neutral-300 hover:bg-neutral-700">
                          Reset Password
                        </button>
                        {user.status === 'active' ? (
                          <button 
                            onClick={(e) => { e.stopPropagation(); suspendUser(user.id); }}
                            className="w-full px-3 py-2 text-left text-sm text-red-400 hover:bg-red-500/10"
                          >
                            Suspend User
                          </button>
                        ) : user.status === 'suspended' && (
                          <button 
                            onClick={(e) => { e.stopPropagation(); activateUser(user.id); }}
                            className="w-full px-3 py-2 text-left text-sm text-emerald-400 hover:bg-emerald-500/10"
                          >
                            Activate User
                          </button>
                        )}
                      </div>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-emerald-500/10">
            <p className="text-sm text-neutral-500">
              Showing {(currentPage - 1) * usersPerPage + 1} to {Math.min(currentPage * usersPerPage, filteredUsers.length)} of {filteredUsers.length}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="p-2 text-neutral-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft size={18} />
              </button>
              <span className="text-sm text-neutral-400">
                Page {currentPage} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="p-2 text-neutral-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight size={18} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* User Detail Modal */}
      <AnimatePresence>
        {selectedUser && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSelectedUser(null)}
              className="fixed inset-0 bg-black/60 z-50"
            />
            <motion.div
              initial={{ opacity: 0, x: 300 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 300 }}
              className="fixed right-0 top-0 h-full w-full max-w-md bg-neutral-900 border-l border-emerald-500/10 z-50 overflow-y-auto"
            >
              <div className="p-6 space-y-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400 text-2xl font-bold">
                      {(selectedUser.name || selectedUser.email)[0].toUpperCase()}
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-white">{selectedUser.name || 'No name'}</h2>
                      <p className="text-neutral-400">{selectedUser.email}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedUser(null)}
                    className="text-neutral-500 hover:text-white"
                  >
                    ×
                  </button>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between p-3 bg-neutral-800/50 rounded-lg">
                    <span className="text-neutral-400">Status</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[selectedUser.status]}`}>
                      {selectedUser.status}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-neutral-800/50 rounded-lg">
                    <span className="text-neutral-400">Email Verified</span>
                    {selectedUser.emailVerified ? (
                      <CheckCircle size={18} className="text-emerald-400" />
                    ) : (
                      <AlertTriangle size={18} className="text-amber-400" />
                    )}
                  </div>
                  <div className="flex items-center justify-between p-3 bg-neutral-800/50 rounded-lg">
                    <span className="text-neutral-400">MFA</span>
                    {selectedUser.mfaEnabled ? (
                      <span className="text-emerald-400">{selectedUser.mfaMethods.join(', ')}</span>
                    ) : (
                      <span className="text-neutral-500">Not enabled</span>
                    )}
                  </div>
                  <div className="flex items-center justify-between p-3 bg-neutral-800/50 rounded-lg">
                    <span className="text-neutral-400">Created</span>
                    <span className="text-white">{new Date(selectedUser.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>

                {selectedUser.lastLoginAt && (
                  <div className="space-y-3">
                    <h3 className="text-sm font-medium text-neutral-400 uppercase tracking-wider">Last Login</h3>
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm">
                        <Clock size={14} className="text-neutral-500" />
                        <span className="text-neutral-300">{new Date(selectedUser.lastLoginAt).toLocaleString()}</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <MapPin size={14} className="text-neutral-500" />
                        <span className="text-neutral-300">{selectedUser.lastLoginLocation}</span>
                      </div>
                      <div className="flex items-center gap-2 text-sm">
                        <Smartphone size={14} className="text-neutral-500" />
                        <span className="text-neutral-300">{selectedUser.lastLoginDevice}</span>
                      </div>
                    </div>
                  </div>
                )}

                <div className="space-y-2 pt-4 border-t border-emerald-500/10">
                  <button className="w-full px-4 py-2 text-left text-neutral-300 hover:bg-neutral-800 rounded-lg">
                    Reset Password
                  </button>
                  <button className="w-full px-4 py-2 text-left text-neutral-300 hover:bg-neutral-800 rounded-lg">
                    Revoke All Sessions
                  </button>
                  {selectedUser.status === 'active' ? (
                    <button 
                      onClick={() => { suspendUser(selectedUser.id); setSelectedUser(null); }}
                      className="w-full px-4 py-2 text-left text-red-400 hover:bg-red-500/10 rounded-lg"
                    >
                      Suspend User
                    </button>
                  ) : selectedUser.status === 'suspended' && (
                    <button 
                      onClick={() => { activateUser(selectedUser.id); setSelectedUser(null); }}
                      className="w-full px-4 py-2 text-left text-emerald-400 hover:bg-emerald-500/10 rounded-lg"
                    >
                      Activate User
                    </button>
                  )}
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
