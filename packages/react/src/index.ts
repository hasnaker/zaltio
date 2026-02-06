/**
 * Zalt.io React SDK
 * @zalt/react
 * 
 * React hooks and components for Zalt.io Authentication
 * 
 * @packageDocumentation
 * 
 * @example
 * ```tsx
 * import { ZaltProvider, useAuth, SignedIn, SignedOut, UserButton } from '@zalt.io/react';
 * 
 * function App() {
 *   return (
 *     <ZaltProvider publishableKey="pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456">
 *       <SignedIn>
 *         <UserButton />
 *         <Dashboard />
 *       </SignedIn>
 *       <SignedOut>
 *         <LoginPage />
 *       </SignedOut>
 *     </ZaltProvider>
 *   );
 * }
 * ```
 */

// Provider
export { ZaltProvider, type ZaltProviderProps, type AppearanceConfig } from './provider';

// Context (for advanced use)
export { ZaltContext, useZaltContext, type ZaltContextValue } from './context';

// Hooks
export {
  useAuth,
  useUser,
  useMFA,
  useZaltClient,
  useReverification,
  useInvitations,
  useImpersonation,
  useBilling,
  useAPIKeys,
  useSessions,
  useSessionTasks,
  type UseAuthReturn,
  type UseMFAReturn,
  type UseReverificationReturn,
  type ReverificationLevel,
  type ReverificationStatus,
  type ReverificationResult,
  type PendingRequest,
  type UseInvitationsReturn,
  type Invitation,
  type InvitationStatus,
  type CreateInvitationInput,
  type UseImpersonationReturn,
  type UseImpersonationOptions,
  type ImpersonationSession,
  type ImpersonationStatus,
  type RestrictedAction,
  type UseBillingReturn,
  type UseBillingOptions,
  type BillingPlan,
  type BillingPlanType,
  type BillingInterval,
  type Subscription,
  type SubscriptionStatus,
  type UsageMetrics,
  type EntitlementResult,
  type SubscribeInput,
  type UseAPIKeysReturn,
  type UseAPIKeysOptions,
  type APIKey,
  type APIKeyStatus,
  type CreateAPIKeyInput,
  type CreateAPIKeyResult,
  type UseSessionsReturn,
  type UseSessionsOptions,
  type Session,
  type SessionLocation,
  type ImpossibleTravelInfo,
  type UseSessionTasksReturn,
  type UseSessionTasksOptions,
  type SessionTask,
  type SessionTaskType,
  type SessionTaskStatus,
  type SessionTaskMetadata,
  type TaskCompletionData,
  type OrganizationOption,
} from './hooks';

// Components
export {
  SignedIn,
  SignedOut,
  UserButton,
  ZaltButton,
  SignInButton,
  SignUpButton,
  PasskeyButton,
  InvitationList,
  Waitlist,
  PricingTable,
  APIKeyManager,
  SessionList,
  BillingPortal,
  ReverificationModal,
  ImpersonationBanner,
  SessionTaskHandler,
  type SignedInProps,
  type SignedOutProps,
  type UserButtonProps,
  type ButtonProps,
  type SignInButtonProps,
  type SignUpButtonProps,
  type PasskeyButtonProps,
  type InvitationListProps,
  type InvitationRole,
  type WaitlistProps,
  type WaitlistEntry,
  type WaitlistJoinResult,
  type WaitlistPositionResult,
  type WaitlistStatus,
  type WaitlistMetadata,
  type PricingTableProps,
  type PricingTablePlan,
  type SubscribeResult,
  type APIKeyManagerProps,
  type SessionListProps,
  type BillingPortalProps,
  type ReverificationModalProps,
  type ImpersonationBannerProps,
  type BannerPosition,
  type BannerVariant,
  type SessionTaskHandlerProps,
  type TaskRendererProps,
} from './components';

// Re-export useful types from core
export type {
  User,
  AuthState,
  AuthResult,
  MFAMethod,
  MFASetupResult,
  MFAStatus,
} from '@zalt.io/core';
