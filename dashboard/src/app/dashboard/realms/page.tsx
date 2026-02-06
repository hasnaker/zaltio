'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { Building2, Plus, Search, Settings, Users, Key, Shield } from 'lucide-react';

interface Realm {
  id: string;
  name: string;
  slug: string;
  userCount: number;
  sessionCount: number;
  mfaPolicy: 'optional' | 'required' | 'webauthn_only';
  createdAt: string;
  status: 'active' | 'suspended';
}

export default function RealmsPage() {
  const [realms, setRealms] = useState<Realm[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    const fetchRealms = async () => {
      try {
        const response = await fetch('/api/dashboard/realms');
        if (response.ok) {
          const data = await response.json();
          setRealms(data.realms || []);
        }
      } catch (error) {
        console.error('Failed to fetch realms:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchRealms();
  }, []);

  const filteredRealms = realms.filter(realm =>
    realm.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    realm.slug.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getMfaPolicyBadge = (policy: string) => {
    switch (policy) {
      case 'webauthn_only':
        return <span className="px-2 py-0.5 text-xs font-mono bg-emerald-500/10 text-emerald-400 rounded border border-emerald-500/20">WebAuthn</span>;
      case 'required':
        return <span className="px-2 py-0.5 text-xs font-mono bg-blue-500/10 text-blue-400 rounded border border-blue-500/20">MFA Required</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-mono bg-neutral-500/10 text-neutral-400 rounded border border-neutral-500/20">Optional</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="font-outfit text-2xl font-bold text-white">Realms</h1>
          <p className="text-neutral-400 text-sm mt-1">Manage your authentication realms and their settings.</p>
        </div>
        <Link
          href="/dashboard/realms/new"
          className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-500 text-neutral-950 font-medium rounded-lg hover:bg-emerald-400 transition-colors"
        >
          <Plus size={16} />
          Create Realm
        </Link>
      </div>

      {/* Search */}
      {realms.length > 0 && (
        <div className="relative">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
          <input
            type="text"
            placeholder="Search realms..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-neutral-900 border border-emerald-500/10 rounded-lg text-white text-sm placeholder:text-neutral-500 focus:outline-none focus:border-emerald-500/30"
          />
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {[1, 2].map((i) => (
            <div key={i} className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6 animate-pulse">
              <div className="h-6 bg-neutral-800 rounded w-1/2 mb-4" />
              <div className="h-4 bg-neutral-800 rounded w-1/3 mb-6" />
              <div className="grid grid-cols-3 gap-4">
                <div className="h-12 bg-neutral-800 rounded" />
                <div className="h-12 bg-neutral-800 rounded" />
                <div className="h-12 bg-neutral-800 rounded" />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && realms.length === 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-neutral-900 border border-emerald-500/20 rounded-lg p-12 text-center"
        >
          <div className="w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto mb-6">
            <Building2 size={28} className="text-emerald-500" />
          </div>
          <h3 className="font-outfit text-xl font-bold text-white mb-2">No realms yet</h3>
          <p className="text-neutral-400 text-sm mb-8 max-w-md mx-auto">
            Realms are isolated authentication environments for your applications. 
            Each realm has its own users, sessions, and security policies.
          </p>
          <Link
            href="/dashboard/realms/new"
            className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-500 text-neutral-950 font-semibold rounded-lg hover:bg-emerald-400 transition-colors"
          >
            <Plus size={18} />
            Create Your First Realm
          </Link>
        </motion.div>
      )}

      {/* Realms Grid */}
      {!loading && filteredRealms.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filteredRealms.map((realm, index) => (
            <motion.div
              key={realm.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-neutral-900 border border-emerald-500/10 rounded-lg overflow-hidden hover:border-emerald-500/30 transition-colors"
            >
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded border border-emerald-500/20 bg-emerald-500/5 flex items-center justify-center">
                      <Building2 size={18} className="text-emerald-500" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-white">{realm.name}</h3>
                      <p className="text-xs text-neutral-500 font-mono">{realm.slug}</p>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 mb-6">
                  {getMfaPolicyBadge(realm.mfaPolicy)}
                  <span className={`px-2 py-0.5 text-xs font-mono rounded border ${
                    realm.status === 'active' 
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                      : 'bg-red-500/10 text-red-400 border-red-500/20'
                  }`}>
                    {realm.status}
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div className="p-3 bg-neutral-800/50 rounded-lg">
                    <div className="flex items-center gap-2 text-neutral-500 mb-1">
                      <Users size={12} />
                      <span className="text-xs">Users</span>
                    </div>
                    <p className="text-lg font-mono text-white">{realm.userCount.toLocaleString()}</p>
                  </div>
                  <div className="p-3 bg-neutral-800/50 rounded-lg">
                    <div className="flex items-center gap-2 text-neutral-500 mb-1">
                      <Key size={12} />
                      <span className="text-xs">Sessions</span>
                    </div>
                    <p className="text-lg font-mono text-white">{realm.sessionCount.toLocaleString()}</p>
                  </div>
                  <div className="p-3 bg-neutral-800/50 rounded-lg">
                    <div className="flex items-center gap-2 text-neutral-500 mb-1">
                      <Shield size={12} />
                      <span className="text-xs">MFA</span>
                    </div>
                    <p className="text-lg font-mono text-emerald-400">—</p>
                  </div>
                </div>
              </div>

              <div className="px-6 py-3 bg-neutral-800/30 border-t border-emerald-500/5 flex items-center justify-between">
                <span className="text-xs text-neutral-500">Created {realm.createdAt}</span>
                <Link
                  href={`/dashboard/realms/${realm.slug}`}
                  className="text-xs text-emerald-400 hover:underline flex items-center gap-1"
                >
                  <Settings size={12} />
                  Manage
                </Link>
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
