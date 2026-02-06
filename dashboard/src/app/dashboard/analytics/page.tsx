'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Activity, Users, Shield, TrendingUp, TrendingDown,
  Clock, Globe, Smartphone, Monitor, AlertTriangle,
  CheckCircle, XCircle, Calendar
} from 'lucide-react';

interface Stats {
  totalUsers: number;
  activeUsers: number;
  mauGrowth: number;
  loginSuccess: number;
  loginFailure: number;
  mfaAdoption: number;
  avgSessionDuration: number;
  topCountries: { country: string; users: number }[];
  topDevices: { device: string; percentage: number }[];
  recentActivity: { time: string; event: string; status: 'success' | 'warning' | 'error' }[];
}

const mockStats: Stats = {
  totalUsers: 12847,
  activeUsers: 3421,
  mauGrowth: 12.5,
  loginSuccess: 98.2,
  loginFailure: 1.8,
  mfaAdoption: 67,
  avgSessionDuration: 24,
  topCountries: [
    { country: 'Turkey', users: 4521 },
    { country: 'United States', users: 2834 },
    { country: 'Germany', users: 1923 },
    { country: 'United Kingdom', users: 1456 },
    { country: 'France', users: 892 },
  ],
  topDevices: [
    { device: 'Desktop', percentage: 58 },
    { device: 'Mobile', percentage: 35 },
    { device: 'Tablet', percentage: 7 },
  ],
  recentActivity: [
    { time: '2 min ago', event: 'New user registration', status: 'success' },
    { time: '5 min ago', event: 'Failed login attempt (rate limited)', status: 'warning' },
    { time: '8 min ago', event: 'MFA setup completed', status: 'success' },
    { time: '12 min ago', event: 'Password reset requested', status: 'success' },
    { time: '15 min ago', event: 'Suspicious login blocked', status: 'error' },
    { time: '18 min ago', event: 'New API key created', status: 'success' },
  ],
};

// Simple chart data
const loginData = [
  { day: 'Mon', success: 1245, failure: 23 },
  { day: 'Tue', success: 1389, failure: 31 },
  { day: 'Wed', success: 1567, failure: 28 },
  { day: 'Thu', success: 1423, failure: 19 },
  { day: 'Fri', success: 1678, failure: 35 },
  { day: 'Sat', success: 892, failure: 12 },
  { day: 'Sun', success: 756, failure: 8 },
];

export default function AnalyticsPage() {
  const [stats, setStats] = useState<Stats>(mockStats);
  const [timeRange, setTimeRange] = useState('7d');
  const [loading, setLoading] = useState(false);

  const StatCard = ({ 
    title, 
    value, 
    change, 
    icon: Icon, 
    suffix = '' 
  }: { 
    title: string; 
    value: number | string; 
    change?: number; 
    icon: React.ElementType;
    suffix?: string;
  }) => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-neutral-400">{title}</p>
          <p className="text-3xl font-bold text-white mt-2">
            {typeof value === 'number' ? value.toLocaleString() : value}{suffix}
          </p>
          {change !== undefined && (
            <div className={`flex items-center gap-1 mt-2 text-sm ${change >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
              {change >= 0 ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
              <span>{Math.abs(change)}% vs last period</span>
            </div>
          )}
        </div>
        <div className="w-12 h-12 rounded-lg bg-emerald-500/10 flex items-center justify-center">
          <Icon size={24} className="text-emerald-500" />
        </div>
      </div>
    </motion.div>
  );

  const maxLogins = Math.max(...loginData.map(d => d.success));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Analytics</h1>
          <p className="text-neutral-400 mt-1">Monitor your authentication metrics</p>
        </div>
        <div className="flex items-center gap-2 p-1 bg-neutral-800 rounded-lg">
          {['24h', '7d', '30d', '90d'].map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-4 py-1.5 rounded text-sm transition-colors ${
                timeRange === range 
                  ? 'bg-emerald-500 text-neutral-950' 
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Users" value={stats.totalUsers} change={stats.mauGrowth} icon={Users} />
        <StatCard title="Active Users (MAU)" value={stats.activeUsers} change={8.3} icon={Activity} />
        <StatCard title="Login Success Rate" value={stats.loginSuccess} suffix="%" icon={CheckCircle} />
        <StatCard title="MFA Adoption" value={stats.mfaAdoption} suffix="%" change={5.2} icon={Shield} />
      </div>

      {/* Charts Row */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Login Activity Chart */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
        >
          <h2 className="text-lg font-semibold text-white mb-6">Login Activity</h2>
          <div className="flex items-end gap-2 h-48">
            {loginData.map((day, i) => (
              <div key={day.day} className="flex-1 flex flex-col items-center gap-1">
                <div className="w-full flex flex-col gap-0.5">
                  <div 
                    className="w-full bg-emerald-500/80 rounded-t"
                    style={{ height: `${(day.success / maxLogins) * 160}px` }}
                  />
                  <div 
                    className="w-full bg-red-500/80 rounded-b"
                    style={{ height: `${(day.failure / maxLogins) * 160}px` }}
                  />
                </div>
                <span className="text-xs text-neutral-500">{day.day}</span>
              </div>
            ))}
          </div>
          <div className="flex items-center justify-center gap-6 mt-4">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded bg-emerald-500" />
              <span className="text-sm text-neutral-400">Success</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded bg-red-500" />
              <span className="text-sm text-neutral-400">Failed</span>
            </div>
          </div>
        </motion.div>

        {/* Device Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
        >
          <h2 className="text-lg font-semibold text-white mb-6">Device Distribution</h2>
          <div className="space-y-4">
            {stats.topDevices.map((device, i) => (
              <div key={device.device}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {device.device === 'Desktop' ? <Monitor size={16} className="text-neutral-500" /> :
                     device.device === 'Mobile' ? <Smartphone size={16} className="text-neutral-500" /> :
                     <Monitor size={16} className="text-neutral-500" />}
                    <span className="text-neutral-300">{device.device}</span>
                  </div>
                  <span className="text-white font-medium">{device.percentage}%</span>
                </div>
                <div className="h-2 bg-neutral-800 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${device.percentage}%` }}
                    transition={{ delay: 0.5 + i * 0.1, duration: 0.5 }}
                    className="h-full bg-emerald-500 rounded-full"
                  />
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Bottom Row */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Top Countries */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-white">Top Countries</h2>
            <Globe size={20} className="text-emerald-500" />
          </div>
          <div className="space-y-3">
            {stats.topCountries.map((country, i) => (
              <div key={country.country} className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-neutral-500 text-sm w-6">{i + 1}.</span>
                  <span className="text-neutral-300">{country.country}</span>
                </div>
                <span className="text-white font-medium">{country.users.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Recent Activity */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold text-white">Recent Activity</h2>
            <Clock size={20} className="text-emerald-500" />
          </div>
          <div className="space-y-3">
            {stats.recentActivity.map((activity, i) => (
              <div key={i} className="flex items-start gap-3">
                <div className={`w-2 h-2 rounded-full mt-2 ${
                  activity.status === 'success' ? 'bg-emerald-500' :
                  activity.status === 'warning' ? 'bg-amber-500' : 'bg-red-500'
                }`} />
                <div className="flex-1">
                  <p className="text-neutral-300 text-sm">{activity.event}</p>
                  <p className="text-neutral-500 text-xs">{activity.time}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Security Metrics */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
      >
        <h2 className="text-lg font-semibold text-white mb-6">Security Metrics</h2>
        <div className="grid md:grid-cols-4 gap-6">
          <div className="text-center">
            <div className="text-3xl font-bold text-emerald-400">0</div>
            <p className="text-sm text-neutral-400 mt-1">Breached Passwords</p>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-white">156</div>
            <p className="text-sm text-neutral-400 mt-1">Blocked Attacks</p>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-white">23</div>
            <p className="text-sm text-neutral-400 mt-1">Rate Limited IPs</p>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-emerald-400">A+</div>
            <p className="text-sm text-neutral-400 mt-1">Security Score</p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
