'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { 
  Shield, AlertTriangle, Activity, TrendingUp, 
  ChevronRight, RefreshCw, Filter, Search,
  AlertCircle, CheckCircle, XCircle, Clock,
  MapPin, Monitor, Globe, User
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

interface RiskScoreHistory {
  timestamp: string;
  score: number;
  level: 'low' | 'medium' | 'high' | 'critical';
  userId: string;
  email: string;
  ip: string;
  country?: string;
  factors: RiskFactorSummary[];
}

interface RiskFactorSummary {
  type: string;
  score: number;
  description: string;
}

interface RiskFactorBreakdown {
  type: string;
  label: string;
  count: number;
  avgScore: number;
  percentage: number;
}

interface HighRiskAlert {
  id: string;
  timestamp: string;
  userId: string;
  email: string;
  score: number;
  level: 'high' | 'critical';
  ip: string;
  country?: string;
  city?: string;
  factors: string[];
  action: 'blocked' | 'mfa_required' | 'allowed';
  resolved: boolean;
}

interface RiskStats {
  totalAssessments: number;
  avgRiskScore: number;
  highRiskCount: number;
  blockedCount: number;
  mfaTriggeredCount: number;
}

interface RiskDashboardData {
  stats: RiskStats;
  history: RiskScoreHistory[];
  factorBreakdown: RiskFactorBreakdown[];
  alerts: HighRiskAlert[];
}

// ============================================================================
// Helper Functions
// ============================================================================

function getRiskLevelColor(level: string): string {
  switch (level) {
    case 'low': return 'text-emerald-400';
    case 'medium': return 'text-yellow-400';
    case 'high': return 'text-orange-400';
    case 'critical': return 'text-red-400';
    default: return 'text-neutral-400';
  }
}

function getRiskLevelBg(level: string): string {
  switch (level) {
    case 'low': return 'bg-emerald-500/10 border-emerald-500/20';
    case 'medium': return 'bg-yellow-500/10 border-yellow-500/20';
    case 'high': return 'bg-orange-500/10 border-orange-500/20';
    case 'critical': return 'bg-red-500/10 border-red-500/20';
    default: return 'bg-neutral-500/10 border-neutral-500/20';
  }
}

function getActionIcon(action: string) {
  switch (action) {
    case 'blocked': return XCircle;
    case 'mfa_required': return Shield;
    case 'allowed': return CheckCircle;
    default: return AlertCircle;
  }
}

function getActionColor(action: string): string {
  switch (action) {
    case 'blocked': return 'text-red-400';
    case 'mfa_required': return 'text-yellow-400';
    case 'allowed': return 'text-emerald-400';
    default: return 'text-neutral-400';
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

function getFactorLabel(type: string): string {
  const labels: Record<string, string> = {
    'ip_reputation': 'IP Reputation',
    'geo_velocity': 'Geo Velocity',
    'device_trust': 'Device Trust',
    'behavior_anomaly': 'Behavior Anomaly',
    'credential_stuffing': 'Credential Stuffing',
    'brute_force': 'Brute Force',
    'tor_exit_node': 'Tor Exit Node',
    'vpn_proxy': 'VPN/Proxy',
    'bot_detection': 'Bot Detection',
    'time_anomaly': 'Time Anomaly',
    'new_device': 'New Device',
    'impossible_travel': 'Impossible Travel',
    'failed_attempts': 'Failed Attempts',
    'weak_password': 'Weak Password',
    'breached_password': 'Breached Password'
  };
  return labels[type] || type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ============================================================================
// Components
// ============================================================================

function RiskScoreGauge({ score }: { score: number }) {
  const level = score <= 30 ? 'low' : score <= 60 ? 'medium' : score <= 85 ? 'high' : 'critical';
  const rotation = (score / 100) * 180 - 90;
  
  return (
    <div className="relative w-32 h-16 overflow-hidden">
      {/* Background arc */}
      <div className="absolute inset-0 border-8 border-neutral-800 rounded-t-full" />
      {/* Colored arc based on score */}
      <div 
        className={`absolute inset-0 border-8 rounded-t-full ${
          level === 'low' ? 'border-emerald-500' :
          level === 'medium' ? 'border-yellow-500' :
          level === 'high' ? 'border-orange-500' : 'border-red-500'
        }`}
        style={{
          clipPath: `polygon(0 100%, 50% 50%, ${50 + 50 * Math.cos((rotation - 90) * Math.PI / 180)}% ${50 - 50 * Math.sin((rotation - 90) * Math.PI / 180)}%, 100% 100%)`
        }}
      />
      {/* Score display */}
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 text-center">
        <span className={`text-2xl font-bold ${getRiskLevelColor(level)}`}>{score}</span>
      </div>
    </div>
  );
}

function RiskHistoryChart({ history }: { history: RiskScoreHistory[] }) {
  if (history.length === 0) return null;
  
  const maxScore = Math.max(...history.map(h => h.score), 100);
  const chartHeight = 120;
  
  return (
    <div className="relative h-32 mt-4">
      {/* Y-axis labels */}
      <div className="absolute left-0 top-0 bottom-0 w-8 flex flex-col justify-between text-xs text-neutral-500">
        <span>100</span>
        <span>50</span>
        <span>0</span>
      </div>
      {/* Chart area */}
      <div className="ml-10 h-full flex items-end gap-1">
        {history.slice(-20).map((item, index) => {
          const height = (item.score / maxScore) * chartHeight;
          const level = item.score <= 30 ? 'low' : item.score <= 60 ? 'medium' : item.score <= 85 ? 'high' : 'critical';
          return (
            <div
              key={index}
              className="flex-1 group relative"
              title={`Score: ${item.score} - ${new Date(item.timestamp).toLocaleString()}`}
            >
              <div
                className={`w-full rounded-t transition-all ${
                  level === 'low' ? 'bg-emerald-500' :
                  level === 'medium' ? 'bg-yellow-500' :
                  level === 'high' ? 'bg-orange-500' : 'bg-red-500'
                } opacity-70 hover:opacity-100`}
                style={{ height: `${height}px` }}
              />
              {/* Tooltip */}
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block z-10">
                <div className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-xs whitespace-nowrap">
                  <div className="text-white font-medium">Score: {item.score}</div>
                  <div className="text-neutral-400">{formatTimestamp(item.timestamp)}</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      {/* Threshold lines */}
      <div className="absolute left-10 right-0 top-0 bottom-0 pointer-events-none">
        <div className="absolute w-full border-t border-dashed border-red-500/30" style={{ top: `${100 - 90}%` }} />
        <div className="absolute w-full border-t border-dashed border-orange-500/30" style={{ top: `${100 - 70}%` }} />
        <div className="absolute w-full border-t border-dashed border-yellow-500/30" style={{ top: `${100 - 50}%` }} />
      </div>
    </div>
  );
}

function FactorBreakdownChart({ factors }: { factors: RiskFactorBreakdown[] }) {
  if (factors.length === 0) return null;
  
  const maxCount = Math.max(...factors.map(f => f.count), 1);
  
  return (
    <div className="space-y-3">
      {factors.slice(0, 6).map((factor, index) => (
        <div key={factor.type} className="space-y-1">
          <div className="flex items-center justify-between text-sm">
            <span className="text-neutral-300">{factor.label}</span>
            <span className="text-neutral-500">{factor.count} ({factor.percentage}%)</span>
          </div>
          <div className="h-2 bg-neutral-800 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(factor.count / maxCount) * 100}%` }}
              transition={{ delay: index * 0.1, duration: 0.5 }}
              className={`h-full rounded-full ${
                factor.avgScore > 70 ? 'bg-red-500' :
                factor.avgScore > 50 ? 'bg-orange-500' :
                factor.avgScore > 30 ? 'bg-yellow-500' : 'bg-emerald-500'
              }`}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function RiskDashboardPage() {
  const [data, setData] = useState<RiskDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState('7d');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      setRefreshing(true);
      const params = new URLSearchParams({ range: timeRange });
      if (selectedUser) params.append('userId', selectedUser);
      
      const response = await fetch(`/api/dashboard/risk?${params}`);
      if (!response.ok) {
        throw new Error('Failed to fetch risk data');
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
  }, [timeRange, selectedUser]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Filter alerts based on search
  const filteredAlerts = data?.alerts.filter(alert => 
    !searchQuery || 
    alert.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    alert.ip.includes(searchQuery) ||
    alert.country?.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  const hasData = data && data.stats.totalAssessments > 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="font-outfit text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="text-emerald-500" size={28} />
            Risk Analytics
          </h1>
          <p className="text-neutral-400 text-sm mt-1">
            AI-powered risk assessment monitoring and high-risk login alerts.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {['24h', '7d', '30d'].map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${
                timeRange === range
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'text-neutral-400 hover:text-white hover:bg-neutral-800'
              }`}
            >
              {range}
            </button>
          ))}
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

      {/* Empty State */}
      {!loading && !hasData && !error && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-neutral-900 border border-emerald-500/20 rounded-lg p-12 text-center"
        >
          <div className="w-16 h-16 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mx-auto mb-6">
            <Shield size={28} className="text-emerald-500" />
          </div>
          <h3 className="font-outfit text-xl font-bold text-white mb-2">No risk data yet</h3>
          <p className="text-neutral-400 text-sm mb-8 max-w-md mx-auto">
            Risk assessments will appear here once users start authenticating. 
            The AI-powered system analyzes every login attempt for suspicious activity.
          </p>
          <Link
            href="/dashboard/realms"
            className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-500 text-neutral-950 font-semibold rounded-lg hover:bg-emerald-400 transition-colors"
          >
            View Realms
            <ChevronRight size={18} />
          </Link>
        </motion.div>
      )}

      {/* Dashboard with Data */}
      {!loading && hasData && data && (
        <>
          {/* Stats Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {[
              { 
                label: 'Total Assessments', 
                value: data.stats.totalAssessments.toLocaleString(), 
                icon: Activity,
                color: 'text-emerald-500'
              },
              { 
                label: 'Avg Risk Score', 
                value: data.stats.avgRiskScore.toFixed(1), 
                icon: TrendingUp,
                color: data.stats.avgRiskScore > 50 ? 'text-orange-500' : 'text-emerald-500'
              },
              { 
                label: 'High Risk Logins', 
                value: data.stats.highRiskCount.toLocaleString(), 
                icon: AlertTriangle,
                color: 'text-orange-500'
              },
              { 
                label: 'Blocked Attempts', 
                value: data.stats.blockedCount.toLocaleString(), 
                icon: XCircle,
                color: 'text-red-500'
              },
              { 
                label: 'MFA Triggered', 
                value: data.stats.mfaTriggeredCount.toLocaleString(), 
                icon: Shield,
                color: 'text-yellow-500'
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
                  <div className={`w-10 h-10 rounded border border-emerald-500/20 bg-emerald-500/5 flex items-center justify-center`}>
                    <stat.icon size={18} className={stat.color} />
                  </div>
                </div>
              </motion.div>
            ))}
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Risk Score History */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
            >
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-outfit font-semibold text-white">Risk Score History</h2>
                <span className="text-xs text-neutral-500">Last {data.history.length} assessments</span>
              </div>
              <RiskHistoryChart history={data.history} />
              <div className="flex items-center justify-center gap-4 mt-4 text-xs">
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded bg-emerald-500" /> Low (0-30)
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded bg-yellow-500" /> Medium (31-60)
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded bg-orange-500" /> High (61-85)
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-3 h-3 rounded bg-red-500" /> Critical (86+)
                </span>
              </div>
            </motion.div>

            {/* Risk Factor Breakdown */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
            >
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-outfit font-semibold text-white">Risk Factor Breakdown</h2>
                <span className="text-xs text-neutral-500">Top contributing factors</span>
              </div>
              <FactorBreakdownChart factors={data.factorBreakdown} />
            </motion.div>
          </div>

          {/* High-Risk Alerts */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="bg-neutral-900 border border-emerald-500/10 rounded-lg"
          >
            <div className="p-4 border-b border-emerald-500/10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="text-orange-500" size={20} />
                <h2 className="font-outfit font-semibold text-white">High-Risk Login Alerts</h2>
                <span className="px-2 py-0.5 text-xs bg-orange-500/10 text-orange-400 rounded-full">
                  {filteredAlerts.length}
                </span>
              </div>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" size={16} />
                <input
                  type="text"
                  placeholder="Search by email, IP, or country..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 pr-4 py-2 bg-neutral-800 border border-neutral-700 rounded-lg text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-emerald-500/50 w-full sm:w-64"
                />
              </div>
            </div>

            {filteredAlerts.length === 0 ? (
              <div className="p-8 text-center">
                <CheckCircle className="mx-auto text-emerald-500 mb-3" size={32} />
                <p className="text-neutral-400 text-sm">No high-risk alerts in this period</p>
              </div>
            ) : (
              <div className="divide-y divide-emerald-500/10">
                {filteredAlerts.slice(0, 10).map((alert, index) => {
                  const ActionIcon = getActionIcon(alert.action);
                  return (
                    <motion.div
                      key={alert.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                      className="p-4 hover:bg-neutral-800/50 transition-colors"
                    >
                      <div className="flex items-start gap-4">
                        {/* Risk Level Indicator */}
                        <div className={`w-10 h-10 rounded-lg border flex items-center justify-center flex-shrink-0 ${getRiskLevelBg(alert.level)}`}>
                          <span className={`text-lg font-bold ${getRiskLevelColor(alert.level)}`}>
                            {alert.score}
                          </span>
                        </div>

                        {/* Alert Details */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <User size={14} className="text-neutral-500" />
                            <span className="text-white font-medium truncate">{alert.email}</span>
                            <span className={`px-2 py-0.5 text-xs rounded-full border ${getRiskLevelBg(alert.level)} ${getRiskLevelColor(alert.level)}`}>
                              {alert.level}
                            </span>
                          </div>
                          
                          <div className="flex flex-wrap items-center gap-3 text-xs text-neutral-500 mb-2">
                            <span className="flex items-center gap-1">
                              <Globe size={12} />
                              {alert.ip}
                            </span>
                            {alert.country && (
                              <span className="flex items-center gap-1">
                                <MapPin size={12} />
                                {alert.city ? `${alert.city}, ${alert.country}` : alert.country}
                              </span>
                            )}
                            <span className="flex items-center gap-1">
                              <Clock size={12} />
                              {formatTimestamp(alert.timestamp)}
                            </span>
                          </div>

                          {/* Risk Factors */}
                          <div className="flex flex-wrap gap-1">
                            {alert.factors.slice(0, 3).map((factor, i) => (
                              <span
                                key={i}
                                className="px-2 py-0.5 text-xs bg-neutral-800 text-neutral-400 rounded"
                              >
                                {getFactorLabel(factor)}
                              </span>
                            ))}
                            {alert.factors.length > 3 && (
                              <span className="px-2 py-0.5 text-xs bg-neutral-800 text-neutral-500 rounded">
                                +{alert.factors.length - 3} more
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Action Taken */}
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <ActionIcon size={16} className={getActionColor(alert.action)} />
                          <span className={`text-xs ${getActionColor(alert.action)}`}>
                            {alert.action === 'blocked' ? 'Blocked' :
                             alert.action === 'mfa_required' ? 'MFA Required' : 'Allowed'}
                          </span>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            )}

            {filteredAlerts.length > 10 && (
              <div className="p-4 border-t border-emerald-500/10 text-center">
                <button className="text-sm text-emerald-400 hover:text-emerald-300 transition-colors">
                  View all {filteredAlerts.length} alerts
                </button>
              </div>
            )}
          </motion.div>
        </>
      )}
    </div>
  );
}
