# @zalt.io/mcp-server

Model Context Protocol (MCP) server for AI assistants to manage Zalt authentication.

## Installation

```bash
npm install -g @zalt.io/mcp-server
```

## Configuration

Set environment variables:

```bash
export ZALT_API_URL=https://api.zalt.io  # Optional, defaults to production
export ZALT_ADMIN_KEY=your-admin-key     # Required for admin operations
```

## Usage with Claude Desktop

Add to your Claude Desktop config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "zalt": {
      "command": "npx",
      "args": ["@zalt.io/mcp-server"],
      "env": {
        "ZALT_ADMIN_KEY": "your-admin-key"
      }
    }
  }
}
```

## Usage with Kiro

Add to your Kiro MCP config (`.kiro/settings/mcp.json`):

```json
{
  "mcpServers": {
    "zalt": {
      "command": "npx",
      "args": ["@zalt.io/mcp-server"],
      "env": {
        "ZALT_ADMIN_KEY": "your-admin-key"
      }
    }
  }
}
```

## Available Tools

### Core Tools

| Tool | Description |
|------|-------------|
| `zalt_create_realm` | Create a new realm for multi-tenant isolation |
| `zalt_list_realms` | List all realms |
| `zalt_create_user` | Create a new user in a realm |
| `zalt_check_auth_status` | Check API health status |
| `zalt_get_sdk_snippet` | Get code snippets for SDK integration |
| `zalt_security_check` | Analyze code for security issues |

### User Management

| Tool | Description |
|------|-------------|
| `zalt_list_users` | List users with pagination and filtering |
| `zalt_get_user` | Get user details by ID or email |
| `zalt_update_user` | Update user profile |
| `zalt_suspend_user` | Suspend user account |
| `zalt_activate_user` | Reactivate suspended user |
| `zalt_delete_user` | Delete user (soft/hard delete) |

### Session Management

| Tool | Description |
|------|-------------|
| `zalt_list_sessions` | List active sessions for a user |
| `zalt_revoke_session` | Revoke a specific session |
| `zalt_revoke_all_sessions` | Revoke all sessions (force logout) |

### MFA Management

| Tool | Description |
|------|-------------|
| `zalt_get_mfa_status` | Get MFA status for a user |
| `zalt_reset_mfa` | Reset MFA (admin action) |
| `zalt_configure_mfa_policy` | Configure realm MFA policy |
| `zalt_get_mfa_policy` | Get current MFA policy |

### API Key Management

| Tool | Description |
|------|-------------|
| `zalt_list_api_keys` | List API keys for a user |
| `zalt_create_api_key` | Create new API key |
| `zalt_revoke_api_key` | Revoke an API key |

### Analytics

| Tool | Description |
|------|-------------|
| `zalt_get_auth_stats` | Get authentication statistics |
| `zalt_get_security_events` | Get security events |
| `zalt_get_failed_logins` | Get failed login attempts |

## Available Resources

| Resource | Description |
|----------|-------------|
| `zalt://docs/quickstart` | Quick start guide |
| `zalt://docs/security` | Security best practices |
| `zalt://docs/mfa` | MFA setup guide |

## Example Conversations

### List users in a realm

```
User: Show me all users in the clinisyn realm
AI: [Uses zalt_list_users with realm_id="clinisyn"]
```

### Check security events

```
User: Are there any suspicious login attempts?
AI: [Uses zalt_get_security_events with severity="high"]
```

### Configure MFA policy

```
User: Make MFA required for all users in the healthcare realm
AI: [Uses zalt_configure_mfa_policy with policy="required"]
```

### Get SDK code

```
User: How do I add Zalt auth to my Next.js app?
AI: [Uses zalt_get_sdk_snippet with framework="nextjs", feature="middleware"]
```

## Security Notes

- ⚠️ SMS MFA is NOT supported due to SS7 vulnerabilities
- Use TOTP or WebAuthn for secure authentication
- Admin key should be kept secure and rotated regularly
- All admin actions are audit logged

## License

MIT
