/**
 * Session Management Tools for Zalt MCP Server
 * @zalt/mcp-server
 */

import { makeApiRequest } from '../config.js';

// Types
interface ZaltSession {
  id: string;
  user_id: string;
  device_id?: string;
  device_info?: {
    browser?: string;
    os?: string;
    device_type?: string;
  };
  ip_address?: string;
  location?: string;
  created_at: string;
  last_activity_at: string;
  expires_at: string;
  is_current?: boolean;
}

interface ListSessionsResponse {
  sessions: ZaltSession[];
  total: number;
}

// Tool Definitions
export const sessionTools = [
  {
    name: 'zalt_list_sessions',
    description: 'List all active sessions for a user',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to list sessions for',
        },
      },
      required: ['realm_id', 'user_id'],
    },
  },
  {
    name: 'zalt_revoke_session',
    description: 'Revoke a specific session',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        session_id: {
          type: 'string',
          description: 'Session ID to revoke',
        },
      },
      required: ['realm_id', 'session_id'],
    },
  },
  {
    name: 'zalt_revoke_all_sessions',
    description: 'Revoke all sessions for a user (force logout everywhere)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to revoke all sessions for',
        },
        reason: {
          type: 'string',
          description: 'Reason for revoking all sessions (for audit)',
        },
      },
      required: ['realm_id', 'user_id'],
    },
  },
];

// Tool Handlers
export async function handleListSessions(args: {
  realm_id: string;
  user_id: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}/sessions`,
    { method: 'GET' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to list sessions: ${response.error}` }],
      isError: true,
    };
  }

  const data = response.data as ListSessionsResponse;
  const sessions = data.sessions || [];

  if (sessions.length === 0) {
    return {
      content: [{ type: 'text' as const, text: 'No active sessions found for this user.' }],
    };
  }

  const sessionList = sessions.map((s: ZaltSession) => {
    const device = s.device_info
      ? `${s.device_info.browser || 'Unknown'} on ${s.device_info.os || 'Unknown'}`
      : 'Unknown device';
    const current = s.is_current ? ' (CURRENT)' : '';
    const location = s.location || 'Unknown location';
    
    return `📱 ${device}${current}\n   ID: ${s.id}\n   Location: ${location}\n   Last active: ${s.last_activity_at}\n   Created: ${s.created_at}`;
  }).join('\n\n');

  return {
    content: [{
      type: 'text' as const,
      text: `Found ${sessions.length} active session(s):\n\n${sessionList}`,
    }],
  };
}

export async function handleRevokeSession(args: {
  realm_id: string;
  session_id: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/sessions/${args.session_id}`,
    { method: 'DELETE' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to revoke session: ${response.error}` }],
      isError: true,
    };
  }

  return {
    content: [{
      type: 'text' as const,
      text: `✅ Session ${args.session_id} has been revoked.`,
    }],
  };
}

export async function handleRevokeAllSessions(args: {
  realm_id: string;
  user_id: string;
  reason?: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}/sessions`,
    { 
      method: 'DELETE',
      body: args.reason ? { reason: args.reason } : undefined,
    }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to revoke sessions: ${response.error}` }],
      isError: true,
    };
  }

  const data = response.data as { revoked_count?: number };
  const count = data.revoked_count || 0;

  return {
    content: [{
      type: 'text' as const,
      text: `✅ Revoked ${count} session(s) for user ${args.user_id}.\nUser has been logged out from all devices.`,
    }],
  };
}
