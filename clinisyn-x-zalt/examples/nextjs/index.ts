/**
 * Clinisyn x Zalt.io - Next.js Integration
 * 
 * Tüm componentleri ve client'ı tek yerden export eder.
 * 
 * Kullanım:
 * import { zaltAuth, LoginForm, MfaVerifyForm, TotpSetup, WebAuthnSetup } from './auth';
 */

// Configuration
export { ZALT_CONFIG, ZALT_ENDPOINTS, ZALT_ERROR_CODES } from './auth-config';
export type { ZaltErrorCode } from './auth-config';

// Auth Client
export { zaltAuth, default as authClient } from './auth-client';

// Components
export { LoginForm } from './LoginForm';
export { MfaVerifyForm } from './MfaVerifyForm';
export { TotpSetup } from './TotpSetup';
export { WebAuthnSetup } from './WebAuthnSetup';
