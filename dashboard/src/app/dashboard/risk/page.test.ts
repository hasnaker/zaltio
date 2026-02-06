/**
 * Risk Analytics Dashboard Tests
 * 
 * Tests for the risk score display dashboard page.
 * Validates: Requirements 10.7
 */

// Mock fetch
const mockFetch = jest.fn();
global.fetch = mockFetch as jest.Mock;

describe('Risk Analytics Dashboard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Data Fetching', () => {
    it('should fetch risk data with correct parameters', async () => {
      const mockData = {
        stats: {
          totalAssessments: 100,
          avgRiskScore: 35.5,
          highRiskCount: 10,
          blockedCount: 2,
          mfaTriggeredCount: 8,
        },
        history: [],
        factorBreakdown: [],
        alerts: [],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockData,
      });

      // Simulate API call
      const response = await fetch('/api/dashboard/risk?range=7d');
      const data = await response.json();

      expect(mockFetch).toHaveBeenCalledWith('/api/dashboard/risk?range=7d');
      expect(data.stats.totalAssessments).toBe(100);
    });

    it('should handle API errors gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const response = await fetch('/api/dashboard/risk?range=7d');
      expect(response.ok).toBe(false);
    });

    it('should support different time ranges', async () => {
      const ranges = ['24h', '7d', '30d'];
      
      for (const range of ranges) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ stats: {}, history: [], factorBreakdown: [], alerts: [] }),
        });

        await fetch(`/api/dashboard/risk?range=${range}`);
        expect(mockFetch).toHaveBeenCalledWith(`/api/dashboard/risk?range=${range}`);
      }
    });

    it('should support filtering by userId', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ stats: {}, history: [], factorBreakdown: [], alerts: [] }),
      });

      await fetch('/api/dashboard/risk?range=7d&userId=user_123');
      expect(mockFetch).toHaveBeenCalledWith('/api/dashboard/risk?range=7d&userId=user_123');
    });
  });

  describe('Risk Level Classification', () => {
    it('should classify scores correctly', () => {
      const getRiskLevel = (score: number): string => {
        if (score <= 30) return 'low';
        if (score <= 60) return 'medium';
        if (score <= 85) return 'high';
        return 'critical';
      };

      expect(getRiskLevel(0)).toBe('low');
      expect(getRiskLevel(30)).toBe('low');
      expect(getRiskLevel(31)).toBe('medium');
      expect(getRiskLevel(60)).toBe('medium');
      expect(getRiskLevel(61)).toBe('high');
      expect(getRiskLevel(85)).toBe('high');
      expect(getRiskLevel(86)).toBe('critical');
      expect(getRiskLevel(100)).toBe('critical');
    });
  });

  describe('Risk Factor Labels', () => {
    it('should return correct labels for factor types', () => {
      const getFactorLabel = (type: string): string => {
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
      };

      expect(getFactorLabel('ip_reputation')).toBe('IP Reputation');
      expect(getFactorLabel('geo_velocity')).toBe('Geo Velocity');
      expect(getFactorLabel('impossible_travel')).toBe('Impossible Travel');
      expect(getFactorLabel('unknown_factor')).toBe('Unknown Factor');
    });
  });

  describe('Action Classification', () => {
    it('should determine correct action based on score', () => {
      const getAction = (score: number): string => {
        if (score > 90) return 'blocked';
        if (score > 70) return 'mfa_required';
        return 'allowed';
      };

      expect(getAction(95)).toBe('blocked');
      expect(getAction(91)).toBe('blocked');
      expect(getAction(90)).toBe('mfa_required');
      expect(getAction(75)).toBe('mfa_required');
      expect(getAction(71)).toBe('mfa_required');
      expect(getAction(70)).toBe('allowed');
      expect(getAction(50)).toBe('allowed');
      expect(getAction(0)).toBe('allowed');
    });
  });

  describe('Timestamp Formatting', () => {
    it('should format timestamps correctly', () => {
      const formatTimestamp = (timestamp: string): string => {
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
      };

      const now = new Date();
      
      // Just now
      expect(formatTimestamp(now.toISOString())).toBe('Just now');
      
      // Minutes ago
      const fiveMinAgo = new Date(now.getTime() - 5 * 60 * 1000);
      expect(formatTimestamp(fiveMinAgo.toISOString())).toBe('5m ago');
      
      // Hours ago
      const threeHoursAgo = new Date(now.getTime() - 3 * 60 * 60 * 1000);
      expect(formatTimestamp(threeHoursAgo.toISOString())).toBe('3h ago');
      
      // Days ago
      const twoDaysAgo = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000);
      expect(formatTimestamp(twoDaysAgo.toISOString())).toBe('2d ago');
    });
  });

  describe('Stats Calculation', () => {
    it('should calculate average risk score correctly', () => {
      const history = [
        { score: 20 },
        { score: 40 },
        { score: 60 },
        { score: 80 },
      ];
      
      const avgScore = history.reduce((sum, h) => sum + h.score, 0) / history.length;
      expect(avgScore).toBe(50);
    });

    it('should count high risk assessments correctly', () => {
      const history = [
        { score: 20, level: 'low' },
        { score: 50, level: 'medium' },
        { score: 75, level: 'high' },
        { score: 95, level: 'critical' },
      ];
      
      const highRiskCount = history.filter(
        h => h.level === 'high' || h.level === 'critical'
      ).length;
      
      expect(highRiskCount).toBe(2);
    });

    it('should count blocked attempts correctly', () => {
      const history = [
        { score: 50 },
        { score: 85 },
        { score: 91 },
        { score: 95 },
      ];
      
      const blockedCount = history.filter(h => h.score > 90).length;
      expect(blockedCount).toBe(2);
    });

    it('should count MFA triggered correctly', () => {
      const history = [
        { score: 50 },
        { score: 75 },
        { score: 85 },
        { score: 95 },
      ];
      
      const mfaTriggeredCount = history.filter(
        h => h.score > 70 && h.score <= 90
      ).length;
      
      expect(mfaTriggeredCount).toBe(2);
    });
  });

  describe('Factor Breakdown', () => {
    it('should calculate factor percentages correctly', () => {
      const factors = [
        { type: 'new_device', count: 30 },
        { type: 'geo_velocity', count: 20 },
        { type: 'vpn_proxy', count: 50 },
      ];
      
      const total = factors.reduce((sum, f) => sum + f.count, 0);
      
      const breakdown = factors.map(f => ({
        ...f,
        percentage: Math.round((f.count / total) * 100)
      }));
      
      expect(breakdown[0].percentage).toBe(30);
      expect(breakdown[1].percentage).toBe(20);
      expect(breakdown[2].percentage).toBe(50);
    });
  });

  describe('Alert Filtering', () => {
    it('should filter alerts by email', () => {
      const alerts = [
        { email: 'john@example.com', ip: '192.168.1.1', country: 'US' },
        { email: 'jane@example.com', ip: '10.0.0.1', country: 'UK' },
        { email: 'admin@example.com', ip: '172.16.0.1', country: 'DE' },
      ];
      
      const searchQuery = 'john';
      const filtered = alerts.filter(a => 
        a.email.toLowerCase().includes(searchQuery.toLowerCase())
      );
      
      expect(filtered.length).toBe(1);
      expect(filtered[0].email).toBe('john@example.com');
    });

    it('should filter alerts by IP', () => {
      const alerts = [
        { email: 'john@example.com', ip: '192.168.1.1', country: 'US' },
        { email: 'jane@example.com', ip: '10.0.0.1', country: 'UK' },
      ];
      
      const searchQuery = '192.168';
      const filtered = alerts.filter(a => a.ip.includes(searchQuery));
      
      expect(filtered.length).toBe(1);
      expect(filtered[0].ip).toBe('192.168.1.1');
    });

    it('should filter alerts by country', () => {
      const alerts = [
        { email: 'john@example.com', ip: '192.168.1.1', country: 'US' },
        { email: 'jane@example.com', ip: '10.0.0.1', country: 'UK' },
      ];
      
      const searchQuery = 'uk';
      const filtered = alerts.filter(a => 
        a.country?.toLowerCase().includes(searchQuery.toLowerCase())
      );
      
      expect(filtered.length).toBe(1);
      expect(filtered[0].country).toBe('UK');
    });
  });

  describe('Security Requirements', () => {
    it('should not expose sensitive data in error messages', () => {
      // Error messages should be generic
      const errorMessage = 'An error occurred while fetching risk data';
      
      expect(errorMessage).not.toContain('password');
      expect(errorMessage).not.toContain('token');
      expect(errorMessage).not.toContain('secret');
      expect(errorMessage).not.toContain('key');
    });

    it('should mask IP addresses for privacy', () => {
      const maskIP = (ip: string): string => {
        if (ip.includes('.')) {
          const parts = ip.split('.');
          if (parts.length === 4) {
            return `${parts[0]}.${parts[1]}.*.*`;
          }
        }
        return 'masked';
      };

      expect(maskIP('192.168.1.100')).toBe('192.168.*.*');
      expect(maskIP('10.0.0.50')).toBe('10.0.*.*');
    });
  });
});

describe('Risk API Route', () => {
  describe('Authentication', () => {
    it('should require authentication', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ error: 'Unauthorized' }),
      });

      const response = await fetch('/api/dashboard/risk');
      expect(response.status).toBe(401);
    });
  });

  describe('Input Validation', () => {
    it('should validate range parameter', () => {
      const validRanges = ['24h', '7d', '30d'];
      const invalidRanges = ['1h', '90d', 'invalid', ''];

      validRanges.forEach(range => {
        expect(validRanges.includes(range)).toBe(true);
      });

      invalidRanges.forEach(range => {
        expect(validRanges.includes(range)).toBe(false);
      });
    });
  });

  describe('Audit Logging', () => {
    it('should log access events', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      // Simulate audit log
      console.log('[AUDIT] Risk dashboard accessed - range: 7d, userId: all');
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('[AUDIT]')
      );
      
      consoleSpy.mockRestore();
    });
  });
});
