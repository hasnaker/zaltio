/**
 * User Management Tools for Zalt MCP Server
 * @zalt/mcp-server
 */

import { ZALT_API_URL, ZALT_ADMIN_KEY, makeApiRequest } from '../config.js';

// Types
interface ZaltUser {
  id: string;
  email: string;
  profile?: {
    first_name?: string;
    last_name?: string;
  };
  status: 'active' | 'suspended' | 'deleted';
  mfa_enabled: boolean;
  created_at: string;
  last_login_at?: string;
}

interface ListUsersResponse {
  users: ZaltUser[];
  total: number;
  has_more: boolean;
}

// Tool Definitions
export const userTools = [
  {
    name: 'zalt_list_users',
    description: 'List all users in a Zalt realm with pagination and filtering',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID to list users from',
        },
        limit: {
          type: 'number',
          description: 'Number of users to return (default: 10, max: 100)',
          default: 10,
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default: 0)',
          default: 0,
        },
        search: {
          type: 'string',
          description: 'Search by email (partial match)',
        },
        status: {
          type: 'string',
          enum: ['active', 'suspended', 'all'],
          description: 'Filter by user status (default: all)',
          default: 'all',
        },
      },
      required: ['realm_id'],
    },
  },
  {
    name: 'zalt_get_user',
    description: 'Get detailed information about a specific user',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to retrieve',
        },
        email: {
          type: 'string',
          description: 'User email to retrieve (alternative to user_id)',
        },
      },
      required: ['realm_id'],
    },
  },
  {
    name: 'zalt_update_user',
    description: 'Update user profile information',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to update',
        },
        first_name: {
          type: 'string',
          description: 'New first name',
        },
        last_name: {
          type: 'string',
          description: 'New last name',
        },
        metadata: {
          type: 'object',
          description: 'Custom metadata to store with user',
        },
      },
      required: ['realm_id', 'user_id'],
    },
  },
  {
    name: 'zalt_suspend_user',
    description: 'Suspend a user account (revokes all sessions)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to suspend',
        },
        reason: {
          type: 'string',
          description: 'Reason for suspension (required for audit)',
        },
      },
      required: ['realm_id', 'user_id', 'reason'],
    },
  },
  {
    name: 'zalt_activate_user',
    description: 'Reactivate a suspended user account',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to activate',
        },
      },
      required: ['realm_id', 'user_id'],
    },
  },
  {
    name: 'zalt_delete_user',
    description: 'Delete a user account (soft delete by default)',
    inputSchema: {
      type: 'object',
      properties: {
        realm_id: {
          type: 'string',
          description: 'Realm ID',
        },
        user_id: {
          type: 'string',
          description: 'User ID to delete',
        },
        hard_delete: {
          type: 'boolean',
          description: 'Permanently delete user data (GDPR right to erasure)',
          default: false,
        },
      },
      required: ['realm_id', 'user_id'],
    },
  },
];

// Tool Handlers
export async function handleListUsers(args: {
  realm_id: string;
  limit?: number;
  offset?: number;
  search?: string;
  status?: string;
}) {
  const params = new URLSearchParams();
  if (args.limit) params.set('limit', String(Math.min(args.limit, 100)));
  if (args.offset) params.set('offset', String(args.offset));
  if (args.search) params.set('search', args.search);
  if (args.status && args.status !== 'all') params.set('status', args.status);

  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users?${params.toString()}`,
    { method: 'GET' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to list users: ${response.error}` }],
      isError: true,
    };
  }

  const data = response.data as ListUsersResponse;
  const users = data.users || [];

  if (users.length === 0) {
    return {
      content: [{ type: 'text' as const, text: 'No users found matching criteria.' }],
    };
  }

  const userList = users.map((u: ZaltUser) => {
    const name = u.profile?.first_name 
      ? `${u.profile.first_name} ${u.profile.last_name || ''}`.trim()
      : 'No name';
    const mfa = u.mfa_enabled ? '🔐' : '';
    const status = u.status === 'suspended' ? '⚠️ SUSPENDED' : '';
    return `- ${u.email} (${name}) ${mfa} ${status}\n  ID: ${u.id}`;
  }).join('\n');

  return {
    content: [{
      type: 'text' as const,
      text: `Found ${data.total} user(s)${data.has_more ? ' (more available)' : ''}:\n\n${userList}`,
    }],
  };
}

export async function handleGetUser(args: {
  realm_id: string;
  user_id?: string;
  email?: string;
}) {
  if (!args.user_id && !args.email) {
    return {
      content: [{ type: 'text' as const, text: 'Either user_id or email is required.' }],
      isError: true,
    };
  }

  const endpoint = args.user_id
    ? `/admin/realms/${args.realm_id}/users/${args.user_id}`
    : `/admin/realms/${args.realm_id}/users?email=${encodeURIComponent(args.email!)}`;

  const response = await makeApiRequest(endpoint, { method: 'GET' });

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to get user: ${response.error}` }],
      isError: true,
    };
  }

  const user = (args.user_id ? response.data : (response.data as ListUsersResponse).users?.[0]) as ZaltUser;

  if (!user) {
    return {
      content: [{ type: 'text' as const, text: 'User not found.' }],
      isError: true,
    };
  }

  const name = user.profile?.first_name
    ? `${user.profile.first_name} ${user.profile.last_name || ''}`.trim()
    : 'Not set';

  return {
    content: [{
      type: 'text' as const,
      text: `👤 User Details\n\nID: ${user.id}\nEmail: ${user.email}\nName: ${name}\nStatus: ${user.status}\nMFA Enabled: ${user.mfa_enabled ? 'Yes 🔐' : 'No'}\nCreated: ${user.created_at}\nLast Login: ${user.last_login_at || 'Never'}`,
    }],
  };
}

export async function handleUpdateUser(args: {
  realm_id: string;
  user_id: string;
  first_name?: string;
  last_name?: string;
  metadata?: Record<string, unknown>;
}) {
  const body: Record<string, unknown> = {};
  if (args.first_name !== undefined) body.first_name = args.first_name;
  if (args.last_name !== undefined) body.last_name = args.last_name;
  if (args.metadata !== undefined) body.metadata = args.metadata;

  if (Object.keys(body).length === 0) {
    return {
      content: [{ type: 'text' as const, text: 'No fields to update provided.' }],
      isError: true,
    };
  }

  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}`,
    { method: 'PATCH', body }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to update user: ${response.error}` }],
      isError: true,
    };
  }

  return {
    content: [{
      type: 'text' as const,
      text: `✅ User ${args.user_id} updated successfully.`,
    }],
  };
}

export async function handleSuspendUser(args: {
  realm_id: string;
  user_id: string;
  reason: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}/suspend`,
    { method: 'POST', body: { reason: args.reason } }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to suspend user: ${response.error}` }],
      isError: true,
    };
  }

  return {
    content: [{
      type: 'text' as const,
      text: `⚠️ User ${args.user_id} has been suspended.\nReason: ${args.reason}\nAll active sessions have been revoked.`,
    }],
  };
}

export async function handleActivateUser(args: {
  realm_id: string;
  user_id: string;
}) {
  const response = await makeApiRequest(
    `/admin/realms/${args.realm_id}/users/${args.user_id}/activate`,
    { method: 'POST' }
  );

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to activate user: ${response.error}` }],
      isError: true,
    };
  }

  return {
    content: [{
      type: 'text' as const,
      text: `✅ User ${args.user_id} has been reactivated.`,
    }],
  };
}

export async function handleDeleteUser(args: {
  realm_id: string;
  user_id: string;
  hard_delete?: boolean;
}) {
  const endpoint = args.hard_delete
    ? `/admin/realms/${args.realm_id}/users/${args.user_id}?hard_delete=true`
    : `/admin/realms/${args.realm_id}/users/${args.user_id}`;

  const response = await makeApiRequest(endpoint, { method: 'DELETE' });

  if (!response.ok) {
    return {
      content: [{ type: 'text' as const, text: `Failed to delete user: ${response.error}` }],
      isError: true,
    };
  }

  const deleteType = args.hard_delete ? 'permanently deleted (GDPR erasure)' : 'soft deleted';
  return {
    content: [{
      type: 'text' as const,
      text: `🗑️ User ${args.user_id} has been ${deleteType}.`,
    }],
  };
}
