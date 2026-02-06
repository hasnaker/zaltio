/**
 * Tool exports for Zalt MCP Server
 * @zalt/mcp-server
 */

// User Management
export { 
  userTools,
  handleListUsers,
  handleGetUser,
  handleUpdateUser,
  handleSuspendUser,
  handleActivateUser,
  handleDeleteUser,
} from './users.js';

// Session Management
export {
  sessionTools,
  handleListSessions,
  handleRevokeSession,
  handleRevokeAllSessions,
} from './sessions.js';

// MFA Management
export {
  mfaTools,
  handleGetMFAStatus,
  handleResetMFA,
  handleConfigureMFAPolicy,
  handleGetMFAPolicy,
} from './mfa.js';

// API Key Management
export {
  apiKeyTools,
  handleListAPIKeys,
  handleCreateAPIKey,
  handleRevokeAPIKey,
} from './api-keys.js';

// Analytics
export {
  analyticsTools,
  handleGetAuthStats,
  handleGetSecurityEvents,
  handleGetFailedLogins,
} from './analytics.js';
