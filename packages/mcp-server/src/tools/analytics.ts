/**
 * Analytics Tools for Zalt MCP Server
 * @zalt/mcp-server
 */

import { makeApiRequest } from '../config.js';

// Types
interface AuthStats {
  period: string;
  total_users: number;
  active_users: {
    dau: number;
    wau: number;
    mau: number;
  };
  logins: {
    total: number;
    successful: number;
    failed: number;
    success_rate: number;
  };
  registrations: number;
  mfa: {
    enabled_users: number;
    adoption_rate: number;
    methods: {
      totp: number;
      webauthn: number;
    };
  };
}

interface SecurityEvent {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  user_id?: string;
  email?: string;
  ip_address?: string;
  location?: string;
  description: string;
  timestamp: string;
}

// Tool Definitions
export const analyticsTools = [
  {
    name: 'zalt_get_auth_stats',
    description: 'Get authentication statistics for a realm (logins, registrations, MFA adoption)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        period: {
          type: 'string',
          enum: ['today', '7d', '30d', '90d'],
          description: 'Time period for stats (default: 7d)',
          default: '7d',
        },
      },
      required: ['realm_id'],
    },
  },
  {
    name: 'zalt_get_security_events',
    description: 'Get recent security events (failed logins, suspicious activity, etc.)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        severity: {
          type: 'string',
          enum: ['all', 'low', 'medium', 'high', 'critical'],
          description: 'Filter by severity (default: all)',
          default: 'all',
        },
        limit: {
          type: 'number',
          description: 'Number of events to return (default: 20, max: 100)',
          default: 20,
        },
        event_type: {
          type: 'string',
          enum: ['all', 'login_failure', 'account_lockout', 'suspicious_activity', 'impossible_travel', 'credential_stuffing'],
          description: 'Filter by event type',
          default: 'all',
        },
      },
      required: ['realm_id'],
    },
  },
  {
    name: 'zalt_get_failed_logins',
    description: 'Get recent failed login attempts (useful for security monitoring)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        limit: {
          type: 'number',
          description: 'Number of events to return (default: 20)',
          default: 20,
        },
        user_id: {
          type: 'string',
          description: 'Filter by specific user ID (optional)',
        },
      },
      required: ['realm_id'],
    },
  },
];

// Tool Handlers
export async function handleGetAuthStats(args: {
  realm_id: string;
  period?: string;
}) {
  const period = args.period || '7d';
  
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/analytics?period=${period}`,
    { method: 'GET' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to get auth stats: ${response.error}` }],
      isError: true,
    };
  }

  const stats = response.data as AuthStats;

  const successRate = stats.logins.success_rate.toFixed(1);
  const mfaRate = stats.mfa.adoption_rate.toFixed(1);

  return {
    content: [{
      type: 'text' as const,
      text: `📊 Auth Statistics for Realm ${args.realm_id}\nPeriod: ${stats.period}\n\n👥 Users\n   Total: ${stats.total_users.toLocaleString()}\n   DAU: ${stats.active_users.dau.toLocaleString()}\n   WAU: ${stats.active_users.wau.toLocaleString()}\n   MAU: ${stats.active_users.mau.toLocaleString()}\n\n🔐 Logins\n   Total: ${stats.logins.total.toLocaleString()}\n   Successful: ${stats.logins.successful.toLocaleString()}\n   Failed: ${stats.logins.failed.toLocaleString()}\n   Success Rate: ${successRate}%\n\n📝 Registrations: ${stats.registrations.toLocaleString()}\n\n🔑 MFA\n   Enabled Users: ${stats.mfa.enabled_users.toLocaleString()}\n   Adoption Rate: ${mfaRate}%\n   TOTP Users: ${stats.mfa.methods.totp.toLocaleString()}\n   WebAuthn Users: ${stats.mfa.methods.webauthn.toLocaleString()}`,
    }],
  };
}

export async function handleGetSecurityEvents(args: {
  realm_id: string;
  severity?: string;
  limit?: number;
  event_type?: string;
}) {
  const params = new URLSearchParams();
  params.set('limit', String(Math.min(args.limit || 20, 100)));
  if (args.severity && args.severity !== 'all') params.set('severity', args.severity);
  if (args.event_type && args.event_type !== 'all') params.set('type', args.event_type);

  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/security-events?${params.toString()}`,
    { method: 'GET' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to get security events: ${response.error}` }],
      isError: true,
    };
  }

  const data = response.data as { events: SecurityEvent[]; total: number };
  const events = data.events || [];

  if (events.length === 0) {
    return {
      content: [{ type: 'text' as const, text: '✅ No security events found matching criteria.' }],
    };
  }

  const severityIcon: Record<string, string> = {
    low: '🟢',
    medium: '🟡',
    high: '🟠',
    critical: '🔴',
  };

  const eventList = events.map((e: SecurityEvent) => {
    const icon = severityIcon[e.severity] || '⚪';
    const user = e.email || e.user_id || 'Unknown';
    const location = e.location ? ` (${e.location})` : '';
    
    return `${icon} ${e.type.toUpperCase()} - ${e.severity}\n   ${e.description}\n   User: ${user}${location}\n   Time: ${e.timestamp}`;
  }).join('\n\n');

  return {
    content: [{
      type: 'text' as const,
      text: `🚨 Security Events (${events.length} of ${data.total})\n\n${eventList}`,
    }],
  };
}

export async function handleGetFailedLogins(args: {
  realm_id: string;
  limit?: number;
  user_id?: string;
}) {
  const params = new URLSearchParams();
  params.set('type', 'login_failure');
  params.set('limit', String(args.limit || 20));
  if (args.user_id) params.set('user_id', args.user_id);

  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/security-events?${params.toString()}`,
    { method: 'GET' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to get failed logins: ${response.error}` }],
      isError: true,
    };
  }

  const data = response.data as { events: SecurityEvent[]; total: number };
  const events = data.events || [];

  if (events.length === 0) {
    return {
      content: [{ type: 'text' as const, text: '✅ No failed login attempts found.' }],
    };
  }

  const eventList = events.map((e: SecurityEvent) => {
    const user = e.email || 'Unknown email';
    const ip = e.ip_address || 'Unknown IP';
    const location = e.location || 'Unknown location';
    
    return `❌ ${user}\n   IP: ${ip}\n   Location: ${location}\n   Time: ${e.timestamp}`;
  }).join('\n\n');

  return {
    content: [{
      type: 'text' as const,
      text: `🔒 Failed Login Attempts (${events.length} of ${data.total})\n\n${eventList}`,
    }],
  };
}
