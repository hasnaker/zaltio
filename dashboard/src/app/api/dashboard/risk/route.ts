/**
 * Risk Analytics API Endpoint
 * 
 * Provides risk assessment data for the dashboard:
 * - Risk score history per user
 * - Risk factor breakdown
 * - High-risk login alerts
 * 
 * Security Requirements:
 * - Audit logging for all access
 * - No information leakage in error messages
 * 
 * Validates: Requirements 10.7
 */

import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import jwt from 'jsonwebtoken';

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

function getRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
  if (score <= 30) return 'low';
  if (score <= 60) return 'medium';
  if (score <= 85) return 'high';
  return 'critical';
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

function generateMockRiskData(range: string, userId?: string): RiskDashboardData {
  // Calculate time range
  const now = new Date();
  let startTime: Date;
  switch (range) {
    case '24h':
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      break;
    case '30d':
      startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    case '7d':
    default:
      startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  }

  // Generate mock history data
  const historyCount = range === '24h' ? 24 : range === '30d' ? 100 : 50;
  const history: RiskScoreHistory[] = [];
  
  const mockUsers = [
    { id: 'user_001', email: 'john.doe@example.com' },
    { id: 'user_002', email: 'jane.smith@clinisyn.com' },
    { id: 'user_003', email: 'admin@healthcare.org' },
    { id: 'user_004', email: 'support@company.io' },
    { id: 'user_005', email: 'test@suspicious.net' },
  ];

  const mockCountries = ['US', 'UK', 'DE', 'FR', 'JP', 'AU', 'CA', 'RU', 'CN', 'BR'];
  const mockIPs = [
    '192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.45',
    '198.51.100.78', '45.33.32.156', '104.16.85.20', '185.199.108.153'
  ];

  const factorTypes = [
    'new_device', 'geo_velocity', 'vpn_proxy', 'failed_attempts',
    'behavior_anomaly', 'ip_reputation', 'time_anomaly', 'tor_exit_node',
    'impossible_travel', 'credential_stuffing'
  ];

  for (let i = 0; i < historyCount; i++) {
    const timestamp = new Date(
      startTime.getTime() + (i / historyCount) * (now.getTime() - startTime.getTime())
    );
    
    // Generate realistic score distribution (mostly low, some high)
    let score: number;
    const rand = Math.random();
    if (rand < 0.6) {
      score = Math.floor(Math.random() * 30) + 5; // Low risk (5-35)
    } else if (rand < 0.85) {
      score = Math.floor(Math.random() * 30) + 35; // Medium risk (35-65)
    } else if (rand < 0.95) {
      score = Math.floor(Math.random() * 20) + 65; // High risk (65-85)
    } else {
      score = Math.floor(Math.random() * 15) + 85; // Critical risk (85-100)
    }

    const user = mockUsers[Math.floor(Math.random() * mockUsers.length)];
    const numFactors = Math.floor(Math.random() * 3) + 1;
    const factors: RiskFactorSummary[] = [];
    
    for (let j = 0; j < numFactors; j++) {
      const factorType = factorTypes[Math.floor(Math.random() * factorTypes.length)];
      factors.push({
        type: factorType,
        score: Math.floor(Math.random() * 50) + 20,
        description: getFactorLabel(factorType)
      });
    }

    history.push({
      timestamp: timestamp.toISOString(),
      score,
      level: getRiskLevel(score),
      userId: user.id,
      email: user.email,
      ip: mockIPs[Math.floor(Math.random() * mockIPs.length)],
      country: mockCountries[Math.floor(Math.random() * mockCountries.length)],
      factors
    });
  }

  // Filter by userId if provided
  const filteredHistory = userId 
    ? history.filter(h => h.userId === userId)
    : history;

  // Calculate stats
  const totalAssessments = filteredHistory.length;
  const avgRiskScore = totalAssessments > 0
    ? filteredHistory.reduce((sum, h) => sum + h.score, 0) / totalAssessments
    : 0;
  const highRiskCount = filteredHistory.filter(h => h.level === 'high' || h.level === 'critical').length;
  const blockedCount = filteredHistory.filter(h => h.score > 90).length;
  const mfaTriggeredCount = filteredHistory.filter(h => h.score > 70 && h.score <= 90).length;

  // Calculate factor breakdown
  const factorCounts: Record<string, { count: number; totalScore: number }> = {};
  filteredHistory.forEach(h => {
    h.factors.forEach(f => {
      if (!factorCounts[f.type]) {
        factorCounts[f.type] = { count: 0, totalScore: 0 };
      }
      factorCounts[f.type].count++;
      factorCounts[f.type].totalScore += f.score;
    });
  });

  const totalFactorCount = Object.values(factorCounts).reduce((sum, f) => sum + f.count, 0);
  const factorBreakdown: RiskFactorBreakdown[] = Object.entries(factorCounts)
    .map(([type, data]) => ({
      type,
      label: getFactorLabel(type),
      count: data.count,
      avgScore: Math.round(data.totalScore / data.count),
      percentage: Math.round((data.count / totalFactorCount) * 100)
    }))
    .sort((a, b) => b.count - a.count);

  // Generate high-risk alerts
  const alerts: HighRiskAlert[] = filteredHistory
    .filter(h => h.level === 'high' || h.level === 'critical')
    .map((h, index) => {
      const action: 'blocked' | 'mfa_required' | 'allowed' = 
        h.score > 90 ? 'blocked' : h.score > 70 ? 'mfa_required' : 'allowed';
      
      return {
        id: `alert_${index}_${Date.now()}`,
        timestamp: h.timestamp,
        userId: h.userId,
        email: h.email,
        score: h.score,
        level: h.level as 'high' | 'critical',
        ip: h.ip,
        country: h.country,
        city: ['New York', 'London', 'Berlin', 'Tokyo', 'Sydney'][Math.floor(Math.random() * 5)],
        factors: h.factors.map(f => f.type),
        action,
        resolved: Math.random() > 0.3
      };
    })
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return {
    stats: {
      totalAssessments,
      avgRiskScore: Math.round(avgRiskScore * 10) / 10,
      highRiskCount,
      blockedCount,
      mfaTriggeredCount
    },
    history: filteredHistory.slice(-50), // Last 50 for chart
    factorBreakdown,
    alerts
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
    const userId = searchParams.get('userId') || undefined;

    // Validate range parameter
    if (!['24h', '7d', '30d'].includes(range)) {
      return NextResponse.json(
        { error: 'Invalid range parameter' },
        { status: 400 }
      );
    }

    // In production, this would fetch from DynamoDB
    // For now, generate mock data that simulates real risk assessments
    const data = generateMockRiskData(range, userId);

    // Log access for audit (in production, use proper audit logging)
    console.log(`[AUDIT] Risk dashboard accessed - range: ${range}, userId: ${userId || 'all'}`);

    return NextResponse.json(data);
  } catch (error) {
    // Generic error message to prevent information leakage
    console.error('Risk API error:', error);
    return NextResponse.json(
      { error: 'An error occurred while fetching risk data' },
      { status: 500 }
    );
  }
}
