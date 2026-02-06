'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { 
  Key, Search, Monitor, Smartphone, Tablet, Globe, Clock, Trash2,
  Activity, Users, TrendingUp, MapPin, RefreshCw, AlertCircle,
  ChevronRight, BarChart3, PieChart
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

interface SessionInfo {
  id: string;
  userId: string;
  userEmail: string;
  device: string;
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  browser: string;
  ip: string;
  location: string;
  country: string;
  countryCode: string;
  city: string;
  lastActive: string;
  createdAt: string;
  current: boolean;
}

interface ConcurrentSessionsDataPoint {
  timestamp: string;
  count: number;
  label: string;
}

interface DeviceDistribution {
  type: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  label: string;
  count: number;
  percentage: number;
  color: string;
}

interface LocationDistribution {
  country: string;
  countryCode: string;
  count: number;
  percentage: number;
  cities: { city: string; count: number; percentage: number }[];
}


interface SessionStats {
  totalActiveSessions: number;
  uniqueUsers: number;
  avgSessionsPerUser: number;
  peakConcurrentSessions: number;
  peakTime: string;
}

interface SessionAnalyticsData {
  stats: SessionStats;
  sessions: SessionInfo[];
  concurrentSessionsChart: ConcurrentSessionsDataPoint[];
  deviceDistribution: DeviceDistribution[];
  locationDistribution: LocationDistribution[];
  realtimeSessionCount: number;
}

// ============================================================================
// Helper Functions
// ============================================================================

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

function getDeviceIcon(type: string) {
  switch (type) {
    case 'mobile': return Smartphone;
    case 'tablet': return Tablet;
    default: return Monitor;
  }
}

function getCountryFlag(countryCode: string): string {
  // Convert country code to flag emoji
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}


// ============================================================================
// Chart Components
// ============================================================================

/**
 * Concurrent Sessions Chart
 * Validates: Requirement 13.9 - Show concurrent sessions over time chart
 */
function ConcurrentSessionsChart({ data }: { data: ConcurrentSessionsDataPoint[] }) {
  if (data.length === 0) return null;
  
  const maxCount = Math.max(...data.map(d => d.count), 1);
  const chartHeight = 150;
  
  return (
    <div className="relative h-44">
      {/* Y-axis labels */}
      <div className="absolute left-0 top-0 bottom-8 w-8 flex flex-col justify-between text-xs text-neutral-500">
        <span>{maxCount}</span>
        <span>{Math.round(maxCount / 2)}</span>
        <span>0</span>
      </div>
      {/* Chart area */}
      <div className="ml-10 h-36 flex items-end gap-0.5">
        {data.map((item, index) => {
          const height = (item.count / maxCount) * chartHeight;
          return (
            <div
              key={index}
              className="flex-1 group relative"
              title={`${item.count} sessions - ${item.label}`}
            >
              <motion.div
                initial={{ height: 0 }}
                animate={{ height: `${height}px` }}
                transition={{ delay: index * 0.02, duration: 0.3 }}
                className="w-full rounded-t bg-emerald-500 opacity-70 hover:opacity-100 transition-opacity"
              />
              {/* Tooltip */}
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block z-10">
                <div className="bg-neutral-800 border border-neutral-700 rounded px-2 py-1 text-xs whitespace-nowrap">
                  <div className="text-white font-medium">{item.count} sessions</div>
                  <div className="text-neutral-400">{item.label}</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
      {/* X-axis labels */}
      <div className="ml-10 flex justify-between text-xs text-neutral-500 mt-1">
        <span>{data[0]?.label}</span>
        <span>{data[Math.floor(data.length / 2)]?.label}</span>
        <span>{data[data.length - 1]?.label}</span>
      </div>
    </div>
  );
}


/**
 * Device Distribution Chart (Donut)
 * Validates: Requirement 13.9 - Show device type distribution (Desktop/Mobile/Tablet)
 */
function DeviceDistributionChart({ data }: { data: DeviceDistribution[] }) {
  if (data.length === 0) return null;
  
  const total = data.reduce((sum, d) => sum + d.count, 0);
  
  // Calculate SVG arc paths for donut chart
  let currentAngle = -90; // Start from top
  const arcs = data.map((item) => {
    const angle = (item.count / total) * 360;
    const startAngle = currentAngle;
    const endAngle = currentAngle + angle;
    currentAngle = endAngle;
    
    const startRad = (startAngle * Math.PI) / 180;
    const endRad = (endAngle * Math.PI) / 180;
    
    const x1 = 50 + 40 * Math.cos(startRad);
    const y1 = 50 + 40 * Math.sin(startRad);
    const x2 = 50 + 40 * Math.cos(endRad);
    const y2 = 50 + 40 * Math.sin(endRad);
    
    const largeArc = angle > 180 ? 1 : 0;
    
    return {
      ...item,
      path: `M 50 50 L ${x1} ${y1} A 40 40 0 ${largeArc} 1 ${x2} ${y2} Z`
    };
  });
  
  return (
    <div className="flex items-center gap-6">
      {/* Donut Chart */}
      <div className="relative w-32 h-32 flex-shrink-0">
        <svg viewBox="0 0 100 100" className="w-full h-full">
          {arcs.map((arc, index) => (
            <path
              key={index}
              d={arc.path}
              fill={arc.color}
              className="opacity-80 hover:opacity-100 transition-opacity cursor-pointer"
            />
          ))}
          {/* Center hole */}
          <circle cx="50" cy="50" r="25" fill="#171717" />
          {/* Center text */}
          <text x="50" y="47" textAnchor="middle" className="fill-white text-lg font-bold">
            {total}
          </text>
          <text x="50" y="58" textAnchor="middle" className="fill-neutral-400 text-[8px]">
            sessions
          </text>
        </svg>
      </div>
      
      {/* Legend */}
      <div className="flex-1 space-y-2">
        {data.map((item, index) => {
          const Icon = getDeviceIcon(item.type);
          return (
            <div key={index} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div 
                  className="w-3 h-3 rounded-sm" 
                  style={{ backgroundColor: item.color }}
                />
                <Icon size={14} className="text-neutral-400" />
                <span className="text-sm text-neutral-300">{item.label}</span>
              </div>
              <div className="text-sm">
                <span className="text-white font-medium">{item.count}</span>
                <span className="text-neutral-500 ml-1">({item.percentage}%)</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


/**
 * Location Distribution Map
 * Validates: Requirement 13.9 - Show geographic distribution of sessions
 */
function LocationDistributionMap({ data }: { data: LocationDistribution[] }) {
  if (data.length === 0) return null;
  
  const maxCount = Math.max(...data.map(d => d.count), 1);
  
  return (
    <div className="space-y-3">
      {data.slice(0, 6).map((location, index) => (
        <motion.div
          key={location.countryCode}
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: index * 0.1 }}
          className="space-y-1"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-lg">{getCountryFlag(location.countryCode)}</span>
              <span className="text-sm text-neutral-300">{location.country}</span>
            </div>
            <div className="text-sm">
              <span className="text-white font-medium">{location.count}</span>
              <span className="text-neutral-500 ml-1">({location.percentage}%)</span>
            </div>
          </div>
          {/* Progress bar */}
          <div className="h-2 bg-neutral-800 rounded-full overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(location.count / maxCount) * 100}%` }}
              transition={{ delay: index * 0.1 + 0.2, duration: 0.5 }}
              className="h-full bg-gradient-to-r from-emerald-500 to-emerald-400 rounded-full"
            />
          </div>
          {/* Cities breakdown */}
          {location.cities.length > 1 && (
            <div className="flex flex-wrap gap-2 mt-1">
              {location.cities.slice(0, 3).map((city) => (
                <span 
                  key={city.city}
                  className="text-xs px-2 py-0.5 bg-neutral-800 text-neutral-400 rounded"
                >
                  {city.city}: {city.count}
                </span>
              ))}
            </div>
          )}
        </motion.div>
      ))}
    </div>
  );
}


// ============================================================================
// Main Component
// ============================================================================

/**
 * Session Analytics Dashboard Page
 * Validates: Requirement 13.9
 * - Show concurrent sessions over time chart
 * - Show device type distribution (Desktop/Mobile/Tablet)
 * - Show geographic distribution of sessions
 * - Real-time session count
 */
export default function SessionsPage() {
  const [data, setData] = useState<SessionAnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState('7d');
  const [searchQuery, setSearchQuery] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState<'analytics' | 'sessions'>('analytics');

  const fetchData = useCallback(async () => {
    try {
      setRefreshing(true);
      const params = new URLSearchParams({ range: timeRange });
      
      const response = await fetch(`/api/dashboard/sessions?${params}`);
      if (!response.ok) {
        throw new Error('Failed to fetch session data');
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
  }, [timeRange]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Auto-refresh every 30 seconds for real-time count
  useEffect(() => {
    const interval = setInterval(() => {
      if (!refreshing) {
        fetchData();
      }
    }, 30000);
    return () => clearInterval(interval);
  }, [fetchData, refreshing]);

  // Filter sessions based on search
  const filteredSessions = data?.sessions.filter(session =>
    !searchQuery ||
    session.userEmail.toLowerCase().includes(searchQuery.toLowerCase()) ||
    session.ip.includes(searchQuery) ||
    session.location.toLowerCase().includes(searchQuery.toLowerCase()) ||
    session.device.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  const hasData = data && data.stats.totalActiveSessions > 0;

  const handleRevokeSession = async (sessionId: string) => {
    try {
      await fetch(`/api/dashboard/sessions/${sessionId}`, { method: 'DELETE' });
      // Refresh data after revocation
      fetchData();
    } catch (error) {
      console.error('Failed to revoke session:', error);
    }
  };


  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="font-outfit text-2xl font-bold text-white flex items-center gap-2">
            <Activity className="text-emerald-500" size={28} />
            Session Analytics
          </h1>
          <p className="text-neutral-400 text-sm mt-1">
            Monitor active sessions, device distribution, and geographic spread.
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
            <Key size={28} className="text-emerald-500" />
          </div>
          <h3 className="font-outfit text-xl font-bold text-white mb-2">No active sessions</h3>
          <p className="text-neutral-400 text-sm max-w-md mx-auto">
            When users log in to your applications, their sessions will appear here.
            You can monitor activity, view analytics, and revoke sessions if needed.
          </p>
        </motion.div>
      )}

      {/* Dashboard with Data */}
      {!loading && hasData && data && (
        <>
          {/* Stats Grid - Real-time session count */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                label: 'Active Sessions',
                value: data.realtimeSessionCount.toLocaleString(),
                icon: Activity,
                color: 'text-emerald-500',
                description: 'Real-time count'
              },
              {
                label: 'Unique Users',
                value: data.stats.uniqueUsers.toLocaleString(),
                icon: Users,
                color: 'text-blue-500',
                description: 'With active sessions'
              },
              {
                label: 'Avg Sessions/User',
                value: data.stats.avgSessionsPerUser.toFixed(1),
                icon: TrendingUp,
                color: 'text-violet-500',
                description: 'Per user average'
              },
              {
                label: 'Peak Concurrent',
                value: data.stats.peakConcurrentSessions.toLocaleString(),
                icon: BarChart3,
                color: 'text-orange-500',
                description: formatTimestamp(data.stats.peakTime)
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
                    <p className="text-xs text-neutral-500 mt-1">{stat.description}</p>
                  </div>
                  <div className="w-10 h-10 rounded border border-emerald-500/20 bg-emerald-500/5 flex items-center justify-center">
                    <stat.icon size={18} className={stat.color} />
                  </div>
                </div>
              </motion.div>
            ))}
          </div>


          {/* Tab Navigation */}
          <div className="flex gap-2 border-b border-emerald-500/10 pb-2">
            <button
              onClick={() => setActiveTab('analytics')}
              className={`px-4 py-2 text-sm rounded-t-lg transition-colors flex items-center gap-2 ${
                activeTab === 'analytics'
                  ? 'bg-emerald-500/10 text-emerald-400 border-b-2 border-emerald-500'
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              <PieChart size={16} />
              Analytics
            </button>
            <button
              onClick={() => setActiveTab('sessions')}
              className={`px-4 py-2 text-sm rounded-t-lg transition-colors flex items-center gap-2 ${
                activeTab === 'sessions'
                  ? 'bg-emerald-500/10 text-emerald-400 border-b-2 border-emerald-500'
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              <Key size={16} />
              Active Sessions ({data.sessions.length})
            </button>
          </div>

          {/* Analytics Tab */}
          {activeTab === 'analytics' && (
            <>
              {/* Charts Row */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Concurrent Sessions Chart */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3 }}
                  className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
                >
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <BarChart3 className="text-emerald-500" size={20} />
                      <h2 className="font-outfit font-semibold text-white">Concurrent Sessions</h2>
                    </div>
                    <span className="text-xs text-neutral-500">Over time</span>
                  </div>
                  <ConcurrentSessionsChart data={data.concurrentSessionsChart} />
                </motion.div>

                {/* Device Distribution */}
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4 }}
                  className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
                >
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Monitor className="text-blue-500" size={20} />
                      <h2 className="font-outfit font-semibold text-white">Device Distribution</h2>
                    </div>
                    <span className="text-xs text-neutral-500">By device type</span>
                  </div>
                  <DeviceDistributionChart data={data.deviceDistribution} />
                </motion.div>
              </div>

              {/* Location Map */}
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 }}
                className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-6"
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Globe className="text-violet-500" size={20} />
                    <h2 className="font-outfit font-semibold text-white">Geographic Distribution</h2>
                  </div>
                  <span className="text-xs text-neutral-500">Sessions by country</span>
                </div>
                <LocationDistributionMap data={data.locationDistribution} />
              </motion.div>
            </>
          )}


          {/* Sessions Tab */}
          {activeTab === 'sessions' && (
            <>
              {/* Search */}
              <div className="relative">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
                <input
                  type="text"
                  placeholder="Search by email, IP, location, or device..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-neutral-900 border border-emerald-500/10 rounded-lg text-white text-sm placeholder:text-neutral-500 focus:outline-none focus:border-emerald-500/30"
                />
              </div>

              {/* Sessions List */}
              <div className="space-y-3">
                {filteredSessions.length === 0 ? (
                  <div className="bg-neutral-900 border border-emerald-500/10 rounded-lg p-8 text-center">
                    <Search className="mx-auto text-neutral-500 mb-3" size={32} />
                    <p className="text-neutral-400 text-sm">No sessions match your search</p>
                  </div>
                ) : (
                  filteredSessions.map((session, index) => {
                    const DeviceIcon = getDeviceIcon(session.deviceType);
                    return (
                      <motion.div
                        key={session.id}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.03 }}
                        className={`bg-neutral-900 border rounded-lg p-4 ${
                          session.current ? 'border-emerald-500/30' : 'border-emerald-500/10'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <div className={`w-10 h-10 rounded flex items-center justify-center ${
                              session.current ? 'bg-emerald-500/20 border border-emerald-500/30' : 'bg-neutral-800'
                            }`}>
                              <DeviceIcon size={18} className={session.current ? 'text-emerald-400' : 'text-neutral-400'} />
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <p className="text-sm text-white font-medium">{session.device}</p>
                                <span className="text-xs text-neutral-500">• {session.browser}</span>
                                {session.current && (
                                  <span className="px-2 py-0.5 text-xs font-mono bg-emerald-500/10 text-emerald-400 rounded border border-emerald-500/20">
                                    Current
                                  </span>
                                )}
                              </div>
                              <p className="text-xs text-neutral-500">{session.userEmail}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-6">
                            <div className="text-right hidden sm:block">
                              <div className="flex items-center gap-1 text-xs text-neutral-400">
                                <MapPin size={10} />
                                {session.location}
                              </div>
                              <p className="text-xs text-neutral-500 font-mono">{session.ip}</p>
                            </div>
                            <div className="text-right hidden md:block">
                              <div className="flex items-center gap-1 text-xs text-neutral-400">
                                <Clock size={10} />
                                {formatTimestamp(session.lastActive)}
                              </div>
                            </div>
                            {!session.current && (
                              <button
                                onClick={() => handleRevokeSession(session.id)}
                                className="p-2 text-neutral-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                                title="Revoke session"
                              >
                                <Trash2 size={16} />
                              </button>
                            )}
                          </div>
                        </div>
                      </motion.div>
                    );
                  })
                )}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
