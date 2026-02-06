/**
 * Handler exports for HSD Auth Platform
 */

export { handler as registerHandler } from './register-handler';
export { handler as loginHandler } from './login-handler';
export { handler as refreshHandler } from './refresh-handler';
export { handler as logoutHandler } from './logout-handler';
export {
  listRealmsHandler,
  getRealmHandler,
  createRealmHandler,
  updateRealmHandler,
  deleteRealmHandler,
  listUsersHandler,
  getUserHandler,
  suspendUserHandler,
  activateUserHandler,
  unlockUserHandler,
  adminResetPasswordHandler,
  deleteUserHandler,
  listSessionsHandler,
  revokeSessionHandler,
  revokeUserSessionsHandler,
  adminResetMFAHandler
} from './admin-handler';
export { handler as ssoHandler } from './sso-handler';
export {
  discoveryHandler,
  authorizeHandler,
  tokenHandler,
  userinfoHandler,
  validateSSOHandler,
  createSSOSessionHandler,
  addApplicationHandler,
  convertLegacyHandler,
  validateLegacyHandler,
  registerClientHandler,
  getApplicationsHandler
} from './sso-handler';
export {
  healthHandler,
  livenessHandler,
  readinessHandler,
  metricsHandler
} from './health-handler';
