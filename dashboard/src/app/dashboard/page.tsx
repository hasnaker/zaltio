'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { 
  Building2, Users, Key, Activity, Shield, 
  ArrowUpRight, Plus, Zap, Lock, Globe,
  TrendingUp, TrendingDown
} from 'lucide-react';
import { 
  DashboardCard, 
  DashboardStatGrid, 
  DashboardSection,
  DashboardTableCard 
} from '@/components/dashboard';

interface DashboardStats {
  totalRealms: number;
  totalUsers: number;
  activeSessions: number;
  loginsTodayCount: number;
  trends?: {
    users: number;
    sessions: number;
    logins: number;
  };
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch('/api/dashboard/stats');
        if (response.ok) {
          const data = await response.json();
          setStats(data);
        }
      } catch (error) {
        console.error('Failed to fetch stats:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  const hasData = stats && (stats.totalRealms > 0 || stats.totalUsers > 0);

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-semibold text-neutral-900">Dashboard</h1>
        <p className="text-neutral-500 text-sm mt-1">
          {hasData ? 'Your authentication platform overview.' : 'Welcome to Zalt! Let\'s get you started.'}
        </p>
      </div>

      {/* Stats Grid */}
      <DashboardStatGrid columns={4}>
        <DashboardCard
          title="Total Realms"
          value={loading ? '—' : (stats?.totalRealms || 0).toLocaleString()}
          icon={Building2}
          variant="default"
        />
        <DashboardCard
          title="Total Users"
          value={loading ? '—' : (stats?.totalUsers || 0).toLocaleString()}
          icon={Users}
          trend={stats?.trends?.users ? { value: stats.trends.users, isPositive: stats.trends.users > 0 } : undefined}
          variant="default"
        />
        <DashboardCard
          title="Active Sessions"
          value={loading ? '—' : (stats?.activeSessions || 0).toLocaleString()}
          icon={Key}
          trend={stats?.trends?.sessions ? { value: stats.trends.sessions, isPositive: stats.trends.sessions > 0 } : undefined}
          variant="default"
        />
        <DashboardCard
          title="Logins Today"
          value={loading ? '—' : (stats?.loginsTodayCount || 0).toLocaleString()}
          icon={Activity}
          trend={stats?.trends?.logins ? { value: stats.trends.logins, isPositive: stats.trends.logins > 0 } : undefined}
          variant="gradient"
        />
      </DashboardStatGrid>

      {/* Empty State / Getting Started */}
      {!loading && !hasData && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-white rounded-2xl border border-neutral-200 shadow-sm p-8"
        >
          <div className="text-center max-w-lg mx-auto">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary/10 to-accent/10 flex items-center justify-center mx-auto mb-6">
              <Zap size={28} className="text-primary" />
            </div>
            <h2 className="text-xl font-semibold text-neutral-900 mb-2">Get Started with Zalt</h2>
            <p className="text-neutral-500 text-sm mb-8">
              Create your first realm to start authenticating users with enterprise-grade security.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
              {[
                { icon: Lock, label: 'Bank-grade encryption' },
                { icon: Shield, label: 'MFA & WebAuthn' },
                { icon: Globe, label: 'Global scale' },
              ].map((item) => (
                <div key={item.label} className="p-4 bg-neutral-50 rounded-xl border border-neutral-100">
                  <item.icon size={20} className="text-primary mx-auto mb-2" />
                  <p className="text-sm text-neutral-600">{item.label}</p>
                </div>
              ))}
            </div>

            <Link
              href="/dashboard/realms/new"
              className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-primary to-primary/90 
                         text-white font-medium rounded-xl shadow-md shadow-primary/20
                         hover:shadow-lg hover:shadow-primary/30 transition-all duration-200"
            >
              <Plus size={18} />
              Create Your First Realm
            </Link>
          </div>
        </motion.div>
      )}

      {/* Quick Actions */}
      <DashboardSection title="Quick Actions" description="Common tasks and shortcuts">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { label: 'Create Realm', href: '/dashboard/realms/new', icon: Building2, color: 'from-purple-500/10 to-purple-600/10' },
            { label: 'View Sessions', href: '/dashboard/sessions', icon: Key, color: 'from-blue-500/10 to-blue-600/10' },
            { label: 'API Keys', href: '/dashboard/api-keys', icon: Shield, color: 'from-green-500/10 to-green-600/10' },
            { label: 'Documentation', href: '/docs', icon: Activity, color: 'from-orange-500/10 to-orange-600/10' },
          ].map((action) => (
            <Link
              key={action.label}
              href={action.href}
              className="flex items-center gap-3 px-4 py-3.5 rounded-xl bg-white border border-neutral-200
                         text-neutral-700 hover:border-primary/30 hover:shadow-sm transition-all duration-200 group"
            >
              <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${action.color} flex items-center justify-center`}>
                <action.icon size={18} className="text-neutral-700" />
              </div>
              <span className="text-sm font-medium">{action.label}</span>
              <ArrowUpRight size={14} className="ml-auto text-neutral-400 opacity-0 group-hover:opacity-100 transition-opacity" />
            </Link>
          ))}
        </div>
      </DashboardSection>

      {/* Recent Activity Placeholder */}
      {hasData && (
        <DashboardTableCard
          title="Recent Activity"
          description="Latest authentication events"
          action={
            <Link 
              href="/dashboard/analytics" 
              className="text-sm text-primary hover:text-primary/80 transition-colors"
            >
              View all
            </Link>
          }
        >
          <div className="p-8 text-center text-neutral-500 text-sm">
            <Activity size={24} className="mx-auto mb-2 text-neutral-300" />
            Activity data will appear here
          </div>
        </DashboardTableCard>
      )}
    </div>
  );
}
