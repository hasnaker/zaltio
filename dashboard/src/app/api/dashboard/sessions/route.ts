/**
 * Session Analytics API Endpoint
 * 
 * Provides session analytics data for the dashboard:
 * - Concurrent sessions over time chart
 * - Device type distribution (Desktop/Mobile/Tablet)
 * - Geographic distribution of sessions
 * - Real-time session count
 * 
 * Security Requirements:
 * - Audit logging for all access
 * - No information leakage in error messages
 * 
 * Validates: Requirements 13.9
 */

import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';

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
  cities: CityDistribution[];
}

interface CityDistribution {
  city: string;
  count: number;
  percentage: number;
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

function getDeviceColor(type: string): string {
  switch (type) {
    case 'desktop': return '#10B981'; // emerald-500
    case 'mobile': return '#3B82F6'; // blue-500
    case 'tablet': return '#8B5CF6'; // violet-500
    default: return '#6B7280'; // gray-500
  }
}

function getDeviceLabel(type: string): string {
  switch (type) {
    case 'desktop': return 'Desktop';
    case 'mobile': return 'Mobile';
    case 'tablet': return 'Tablet';
    default: return 'Unknown';
  }
}

function formatTimestamp(date: Date): string {
  return date.toISOString();
}

function formatTimeLabel(date: Date, range: string): string {
  if (range === '24h') {
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  } else if (range === '7d') {
    return date.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
  } else {
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }
}

/**
 * Generate realistic session analytics data
 * In production, this would fetch from DynamoDB
 */
function generateSessionAnalyticsData(range: string, realmId?: string): SessionAnalyticsData {
  const now = new Date();
  let startTime: Date;
  let dataPoints: number;
  
  switch (range) {
    case '24h':
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      dataPoints = 24; // Hourly
      break;
    case '30d':
      startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      dataPoints = 30; // Daily
      break;
    case '7d':
    default:
      startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      dataPoints = 7 * 4; // Every 6 hours
  }

  // Mock users for session generation
  const mockUsers = [
    { id: 'user_001', email: 'john.doe@example.com' },
    { id: 'user_002', email: 'jane.smith@clinisyn.com' },
    { id: 'user_003', email: 'admin@healthcare.org' },
    { id: 'user_004', email: 'support@company.io' },
    { id: 'user_005', email: 'dr.wilson@clinisyn.com' },
    { id: 'user_006', email: 'nurse.johnson@healthcare.org' },
    { id: 'user_007', email: 'patient.care@clinisyn.com' },
    { id: 'user_008', email: 'tech.support@company.io' },
  ];

  const mockLocations = [
    { country: 'United States', countryCode: 'US', city: 'New York' },
    { country: 'United States', countryCode: 'US', city: 'Los Angeles' },
    { country: 'United States', countryCode: 'US', city: 'Chicago' },
    { country: 'United Kingdom', countryCode: 'GB', city: 'London' },
    { country: 'United Kingdom', countryCode: 'GB', city: 'Manchester' },
    { country: 'Germany', countryCode: 'DE', city: 'Berlin' },
    { country: 'Germany', countryCode: 'DE', city: 'Munich' },
    { country: 'France', countryCode: 'FR', city: 'Paris' },
    { country: 'Japan', countryCode: 'JP', city: 'Tokyo' },
    { country: 'Australia', countryCode: 'AU', city: 'Sydney' },
    { country: 'Canada', countryCode: 'CA', city: 'Toronto' },
    { country: 'Netherlands', countryCode: 'NL', city: 'Amsterdam' },
  ];

  const mockDevices = [
    { type: 'desktop' as const, device: 'Windows PC', browser: 'Chrome 120' },
    { type: 'desktop' as const, device: 'MacBook Pro', browser: 'Safari 17' },
    { type: 'desktop' as const, device: 'Linux Desktop', browser: 'Firefox 121' },
    { type: 'mobile' as const, device: 'iPhone 15', browser: 'Safari Mobile' },
    { type: 'mobile' as const, device: 'Samsung Galaxy S24', browser: 'Chrome Mobile' },
    { type: 'mobile' as const, device: 'Google Pixel 8', browser: 'Chrome Mobile' },
    { type: 'tablet' as const, device: 'iPad Pro', browser: 'Safari' },
    { type: 'tablet' as const, device: 'Samsung Galaxy Tab', browser: 'Chrome' },
  ];

  const mockIPs = [
    '192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.45',
    '198.51.100.78', '45.33.32.156', '104.16.85.20', '185.199.108.153',
    '151.101.1.140', '140.82.112.3', '52.216.100.205', '34.117.59.81'
  ];

  // Generate active sessions
  const sessionCount = Math.floor(Math.random() * 20) + 15; // 15-35 sessions
  const sessions: SessionInfo[] = [];

  for (let i = 0; i < sessionCount; i++) {
    const user = mockUsers[Math.floor(Math.random() * mockUsers.length)];
    const location = mockLocations[Math.floor(Math.random() * mockLocations.length)];
    const deviceInfo = mockDevices[Math.floor(Math.random() * mockDevices.length)];
    const ip = mockIPs[Math.floor(Math.random() * mockIPs.length)];
    
    // Random creation time within the range
    const createdAt = new Date(
      startTime.getTime() + Math.random() * (now.getTime() - startTime.getTime())
    );
    
    // Last active is between creation and now
    const lastActive = new Date(
      createdAt.getTime() + Math.random() * (now.getTime() - createdAt.getTime())
    );

    sessions.push({
      id: `session_${i}_${Date.now()}`,
      userId: user.id,
      userEmail: user.email,
      device: deviceInfo.device,
      deviceType: deviceInfo.type,
      browser: deviceInfo.browser,
      ip: `${ip.split('.').slice(0, 2).join('.')}.*.*`, // Masked IP
      location: `${location.city}, ${location.country}`,
      country: location.country,
      countryCode: location.countryCode,
      city: location.city,
      lastActive: lastActive.toISOString(),
      createdAt: createdAt.toISOString(),
      current: i === 0 // First session is current
    });
  }

  // Generate concurrent sessions chart data
  const concurrentSessionsChart: ConcurrentSessionsDataPoint[] = [];
  let peakCount = 0;
  let peakTime = now.toISOString();

  for (let i = 0; i < dataPoints; i++) {
    const timestamp = new Date(
      startTime.getTime() + (i / dataPoints) * (now.getTime() - startTime.getTime())
    );
    
    // Simulate realistic session patterns (higher during business hours)
    const hour = timestamp.getHours();
    const isBusinessHours = hour >= 9 && hour <= 18;
    const baseCount = isBusinessHours ? 20 : 8;
    const variance = Math.floor(Math.random() * 10) - 5;
    const count = Math.max(1, baseCount + variance);
    
    if (count > peakCount) {
      peakCount = count;
      peakTime = timestamp.toISOString();
    }

    concurrentSessionsChart.push({
      timestamp: formatTimestamp(timestamp),
      count,
      label: formatTimeLabel(timestamp, range)
    });
  }

  // Calculate device distribution
  const deviceCounts: Record<string, number> = {
    desktop: 0,
    mobile: 0,
    tablet: 0,
    unknown: 0
  };

  sessions.forEach(s => {
    deviceCounts[s.deviceType]++;
  });

  const totalSessions = sessions.length;
  const deviceDistribution: DeviceDistribution[] = Object.entries(deviceCounts)
    .filter(([_, count]) => count > 0)
    .map(([type, count]) => ({
      type: type as 'desktop' | 'mobile' | 'tablet' | 'unknown',
      label: getDeviceLabel(type),
      count,
      percentage: Math.round((count / totalSessions) * 100),
      color: getDeviceColor(type)
    }))
    .sort((a, b) => b.count - a.count);

  // Calculate location distribution
  const locationCounts: Record<string, { 
    country: string; 
    countryCode: string; 
    count: number;
    cities: Record<string, number>;
  }> = {};

  sessions.forEach(s => {
    if (!locationCounts[s.countryCode]) {
      locationCounts[s.countryCode] = {
        country: s.country,
        countryCode: s.countryCode,
        count: 0,
        cities: {}
      };
    }
    locationCounts[s.countryCode].count++;
    locationCounts[s.countryCode].cities[s.city] = 
      (locationCounts[s.countryCode].cities[s.city] || 0) + 1;
  });

  const locationDistribution: LocationDistribution[] = Object.values(locationCounts)
    .map(loc => ({
      country: loc.country,
      countryCode: loc.countryCode,
      count: loc.count,
      percentage: Math.round((loc.count / totalSessions) * 100),
      cities: Object.entries(loc.cities)
        .map(([city, count]) => ({
          city,
          count,
          percentage: Math.round((count / loc.count) * 100)
        }))
        .sort((a, b) => b.count - a.count)
    }))
    .sort((a, b) => b.count - a.count);

  // Calculate unique users
  const uniqueUsers = new Set(sessions.map(s => s.userId)).size;

  // Calculate stats
  const stats: SessionStats = {
    totalActiveSessions: totalSessions,
    uniqueUsers,
    avgSessionsPerUser: Math.round((totalSessions / uniqueUsers) * 10) / 10,
    peakConcurrentSessions: peakCount,
    peakTime
  };

  return {
    stats,
    sessions: sessions.sort((a, b) => 
      new Date(b.lastActive).getTime() - new Date(a.lastActive).getTime()
    ),
    concurrentSessionsChart,
    deviceDistribution,
    locationDistribution,
    realtimeSessionCount: totalSessions
  };
}

// ============================================================================
// API Handler
// ============================================================================

export async function GET(request: NextRequest) {
  try {
    // Verify authentication
    const cookieStore = await cookies();
    const token = cookieStore.get('zalt_dashboard_token')?.value;
    
    if (!token) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Verify JWT (in production, use proper secret)
    try {
      const jwtSecret = process.env.JWT_SECRET || 'zalt-dashboard-secret';
      jwt.verify(token, jwtSecret);
    } catch {
      return NextResponse.json(
        { error: 'Invalid token' },
        { status: 401 }
      );
    }

    // Get query parameters
    const { searchParams } = new URL(request.url);
    const range = searchParams.get('range') || '7d';
    const realmId = searchParams.get('realmId') || undefined;

    // Validate range parameter
    if (!['24h', '7d', '30d'].includes(range)) {
      return NextResponse.json(
        { error: 'Invalid range parameter' },
        { status: 400 }
      );
    }

    // In production, this would fetch from DynamoDB via analytics service
    // For now, generate realistic mock data
    const data = generateSessionAnalyticsData(range, realmId);

    // Log access for audit (in production, use proper audit logging)
    console.log(`[AUDIT] Session analytics accessed - range: ${range}, realmId: ${realmId || 'all'}`);

    return NextResponse.json(data);
  } catch (error) {
    // Generic error message to prevent information leakage
    console.error('Session analytics API error:', error);
    return NextResponse.json(
      { error: 'An error occurred while fetching session analytics' },
      { status: 500 }
    );
  }
}
