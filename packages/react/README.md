# @zalt.io/react

React hooks and components for Zalt.io authentication. Beautiful, accessible, customizable.

## Installation

```bash
npm install @zalt.io/core @zalt.io/react
```

## Quick Start

```tsx
import { ZaltProvider, useAuth, SignedIn, SignedOut, UserButton } from '@zalt.io/react';

function App() {
  return (
    <ZaltProvider publishableKey="pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456">
      <Header />
      <MainContent />
    </ZaltProvider>
  );
}

function Header() {
  return (
    <header>
      <SignedIn>
        <UserButton />
      </SignedIn>
      <SignedOut>
        <a href="/sign-in">Sign In</a>
      </SignedOut>
    </header>
  );
}
```

## Features

- 🎣 **React Hooks** - useAuth, useUser, useMFA, useReverification, useInvitations, useSessions, useBilling, useImpersonation, useZaltClient
- 🧩 **Components** - SignedIn, SignedOut, UserButton, SignInButton, InvitationList, SessionList, PricingTable, BillingPortal, Waitlist
- 🔐 **Step-Up Auth** - Automatic reverification for sensitive operations
- 👥 **Team Management** - Invitation system with create, resend, revoke
- 📱 **Session Management** - View and revoke active sessions across devices
- 💳 **Billing Integration** - Pricing tables, billing portal, entitlements
- 🎨 **Theming** - CSS variables, dark mode, customizable
- ♿ **Accessible** - WCAG 2.1 AA compliant
- 📦 **Lightweight** - < 3KB gzipped
- 🔑 **Simple Setup** - Just one publishableKey prop

## API Reference

### ZaltProvider

Wrap your app with ZaltProvider to enable authentication.

```tsx
<ZaltProvider
  publishableKey="pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
  baseUrl="https://api.zalt.io"  // Optional
  appearance={{                   // Optional theming
    primaryColor: '#10b981',
    backgroundColor: '#0a0a0a',
    textColor: '#ffffff',
    borderRadius: '0.5rem',
    fontFamily: 'system-ui, sans-serif',
    darkMode: 'auto',            // 'light' | 'dark' | 'auto'
  }}
  debug={false}                   // Enable debug logging
  onAuthStateChange={(state) => console.log(state)}
>
  {children}
</ZaltProvider>
```

### useAuth

Main authentication hook.

```tsx
function Component() {
  const {
    user,              // Current user or null
    isLoading,         // Loading state
    isAuthenticated,   // Boolean
    signIn,            // (email, password) => Promise
    signUp,            // (data: { email, password, profile? }) => Promise
    signOut,           // () => Promise
    state,             // Full auth state
  } = useAuth();

  const handleLogin = async () => {
    try {
      await signIn('user@example.com', 'SecurePassword123!');
    } catch (error) {
      if (error.mfaRequired) {
        // Redirect to MFA page
      }
    }
  };
}
```

### useUser

Get current user data.

```tsx
function Profile() {
  const user = useUser();

  if (!user) return <div>Not logged in</div>;

  return <div>Hello, {user.email}</div>;
}
```

### useMFA

MFA setup and verification.

```tsx
function MFASetup() {
  const { 
    setup,      // (method: 'totp' | 'webauthn') => Promise
    verify,     // (code: string) => Promise
    isLoading,
    qrCode,     // QR code data URL after setup
    backupCodes // Array of backup codes
  } = useMFA();

  return (
    <button onClick={() => setup('totp')}>
      Enable 2FA
    </button>
  );
}
```

### useZaltClient

Access the raw ZaltClient for advanced use cases.

```tsx
function Advanced() {
  const client = useZaltClient();
  
  // Direct API access
  await client.webauthn.register({ name: 'My Device' });
}
```

### useReverification

Handle step-up authentication (reverification) for sensitive operations.

**Validates: Requirements 3.6, 3.7**

```tsx
import { useReverification } from '@zalt.io/react';

function SensitiveAction() {
  const {
    isModalOpen,        // Whether reverification modal should be shown
    requiredLevel,      // 'password' | 'mfa' | 'webauthn'
    validityMinutes,    // How long reverification is valid
    isLoading,          // Loading state during verification
    error,              // Error message if verification failed
    lastReverification, // Last successful reverification result
    verifyWithPassword, // (password: string) => Promise<void>
    verifyWithMFA,      // (code: string) => Promise<void>
    verifyWithWebAuthn, // (credential, challenge) => Promise<void>
    getWebAuthnChallenge, // () => Promise<{ challenge, rpId }>
    checkStatus,        // (level?) => Promise<ReverificationStatus>
    closeModal,         // Close modal without completing
    withReverification, // Wrap async function for auto-handling
    interceptResponse,  // Check if response requires reverification
  } = useReverification();

  // Wrap sensitive operations - automatically shows modal if needed
  const handleDeleteAccount = async () => {
    await withReverification(async () => {
      await api.deleteAccount();
    });
  };

  return (
    <>
      <button onClick={handleDeleteAccount}>Delete Account</button>
      
      {isModalOpen && (
        <ReverificationModal
          level={requiredLevel}
          onPasswordSubmit={verifyWithPassword}
          onMFASubmit={verifyWithMFA}
          onClose={closeModal}
          isLoading={isLoading}
          error={error}
        />
      )}
    </>
  );
}
```

#### Reverification Levels

| Level | Security | Use Case |
|-------|----------|----------|
| `password` | Basic | Profile updates, settings changes |
| `mfa` | Medium | Payment info, email change |
| `webauthn` | Highest | Account deletion, admin actions |

Higher levels satisfy lower level requirements (e.g., `webauthn` satisfies `password`).

#### Automatic Request Retry

When using `withReverification`, the original request is automatically retried after successful verification:

```tsx
const { withReverification } = useReverification();

// This will:
// 1. Execute the function
// 2. If 403 REVERIFICATION_REQUIRED, show modal
// 3. After user verifies, retry the original request
// 4. Return the result
const result = await withReverification(async () => {
  return await api.updatePaymentMethod(newCard);
});
```

#### Manual Response Interception

For custom fetch implementations:

```tsx
const { interceptResponse } = useReverification();

const response = await fetch('/api/sensitive-action', { method: 'POST' });

const needsReverification = await interceptResponse(response, async () => {
  // This will be called after successful reverification
  return fetch('/api/sensitive-action', { method: 'POST' });
});

if (!needsReverification) {
  // Process response normally
  const data = await response.json();
}
```

#### WebAuthn Reverification

For highest security operations:

```tsx
const { verifyWithWebAuthn, getWebAuthnChallenge, requiredLevel } = useReverification();

const handleWebAuthnVerify = async () => {
  // Get challenge from server
  const { challenge, rpId } = await getWebAuthnChallenge();
  
  // Get credential from browser
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: Uint8Array.from(atob(challenge), c => c.charCodeAt(0)),
      rpId,
      userVerification: 'required',
    },
  });
  
  // Verify with server
  await verifyWithWebAuthn(credential as PublicKeyCredential, challenge);
};
```

### SignedIn / SignedOut

Conditional rendering based on auth state.

```tsx
<SignedIn>
  <p>Welcome back!</p>
  <UserButton />
</SignedIn>

<SignedOut>
  <p>Please sign in</p>
  <SignInButton />
</SignedOut>
```

### UserButton

User avatar with dropdown menu.

```tsx
<UserButton 
  afterSignOutUrl="/"
  showName={true}
/>
```

### SignInButton / SignUpButton

Pre-styled auth buttons.

```tsx
<SignInButton mode="modal" />
<SignUpButton redirectUrl="/onboarding" />
```

### useInvitations

Hook for managing team invitations within a tenant.

**Validates: Requirement 11.10**

```tsx
import { useInvitations } from '@zalt.io/react';

function InvitationManager({ tenantId }) {
  const {
    invitations,        // Array of invitations
    isLoading,          // Loading state
    error,              // Error message
    hasMore,            // Whether there are more to load
    fetchInvitations,   // (tenantId, status?) => Promise
    loadMore,           // () => Promise - pagination
    createInvitation,   // (tenantId, input) => Promise<Invitation>
    resendInvitation,   // (tenantId, invitationId) => Promise
    revokeInvitation,   // (tenantId, invitationId) => Promise
    clearError,         // () => void
    refresh,            // () => Promise - refresh list
  } = useInvitations();

  useEffect(() => {
    fetchInvitations(tenantId);
  }, [tenantId]);

  const handleInvite = async (email: string, role: string) => {
    await createInvitation(tenantId, { email, role });
  };

  return (
    <div>
      {invitations.map(inv => (
        <div key={inv.id}>
          {inv.email} - {inv.status}
          {inv.status === 'pending' && (
            <>
              <button onClick={() => resendInvitation(tenantId, inv.id)}>Resend</button>
              <button onClick={() => revokeInvitation(tenantId, inv.id)}>Revoke</button>
            </>
          )}
        </div>
      ))}
    </div>
  );
}
```

### InvitationList

Complete component for managing team invitations with create form, list display, and actions.

**Validates: Requirement 11.10**

```tsx
import { InvitationList } from '@zalt.io/react';

function TeamSettings({ tenantId }) {
  return (
    <InvitationList
      tenantId={tenantId}
      roles={[
        { id: 'admin', name: 'Admin', description: 'Full access' },
        { id: 'member', name: 'Member', description: 'Standard access' },
        { id: 'viewer', name: 'Viewer', description: 'Read-only access' },
      ]}
      defaultRole="member"
      showCreateForm={true}
      statusFilter="all"  // 'pending' | 'accepted' | 'expired' | 'revoked' | 'all'
      onInvitationCreated={(inv) => console.log('Invited:', inv.email)}
      onInvitationRevoked={(id) => console.log('Revoked:', id)}
      onInvitationResent={(id) => console.log('Resent:', id)}
      emptyMessage="No invitations yet. Invite team members to get started."
      compact={false}
    />
  );
}
```

#### InvitationList Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `tenantId` | `string` | required | Tenant ID to manage invitations for |
| `roles` | `InvitationRole[]` | `[admin, member, viewer]` | Available roles for invitation |
| `defaultRole` | `string` | `'member'` | Default role for new invitations |
| `statusFilter` | `InvitationStatus \| 'all'` | `'all'` | Filter invitations by status |
| `showCreateForm` | `boolean` | `true` | Show the create invitation form |
| `className` | `string` | `''` | Custom CSS class |
| `onInvitationCreated` | `(inv) => void` | - | Callback when invitation is created |
| `onInvitationRevoked` | `(id) => void` | - | Callback when invitation is revoked |
| `onInvitationResent` | `(id) => void` | - | Callback when invitation is resent |
| `emptyMessage` | `string` | `'No invitations yet...'` | Custom empty state message |
| `hideStatusBadges` | `boolean` | `false` | Hide status badges |
| `compact` | `boolean` | `false` | Use compact layout |

#### Invitation Status Types

| Status | Description |
|--------|-------------|
| `pending` | Invitation sent, awaiting acceptance |
| `accepted` | User has accepted the invitation |
| `expired` | Invitation has expired (7 days) |
| `revoked` | Invitation was manually revoked |

#### Features

- **Create Form**: Email input, role selector, optional custom message
- **List Display**: Shows all invitations with status badges
- **Actions**: Resend and revoke buttons for pending invitations
- **Pagination**: Load more button for large lists
- **Error Handling**: Displays errors with dismiss button
- **Loading States**: Spinner during operations
- **Accessibility**: ARIA labels, keyboard navigation

### PricingTable

Component for displaying billing plans and allowing subscription.

**Validates: Requirement 7.7**

```tsx
import { PricingTable } from '@zalt.io/react';

function PricingPage() {
  return (
    <PricingTable
      realmId="your-realm-id"
      tenantId="your-tenant-id"
      accessToken={token}
      currentPlanId={currentPlan?.id}
      onSubscribe={async (planId, interval) => {
        // Handle subscription with Stripe
        const { clientSecret } = await createSubscription(planId, interval);
        // Redirect to Stripe checkout or handle payment
      }}
      onSubscribeSuccess={(result) => {
        console.log('Subscribed:', result);
        router.push('/dashboard');
      }}
      onError={(error) => {
        console.error('Subscription error:', error);
      }}
    />
  );
}
```

#### PricingTable Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `realmId` | `string` | required | Realm ID for fetching plans |
| `apiUrl` | `string` | `'https://api.zalt.io'` | API base URL |
| `accessToken` | `string` | - | Access token for authenticated requests |
| `tenantId` | `string` | - | Tenant ID for subscription |
| `currentPlanId` | `string` | - | Current plan ID (shows as selected) |
| `defaultInterval` | `'monthly' \| 'yearly'` | `'monthly'` | Default billing interval |
| `showIntervalToggle` | `boolean` | `true` | Show monthly/yearly toggle |
| `showFeatures` | `boolean` | `true` | Show feature comparison |
| `maxFeaturesShown` | `number` | `6` | Max features to show per plan |
| `className` | `string` | `''` | Custom CSS class |
| `onSubscribe` | `(planId, interval) => Promise` | - | Callback when user clicks subscribe |
| `onSubscribeSuccess` | `(result) => void` | - | Callback when subscription succeeds |
| `onError` | `(error) => void` | - | Callback on error |
| `subscribeButtonText` | `string` | `'Get Started'` | Custom subscribe button text |
| `currentPlanButtonText` | `string` | `'Current Plan'` | Custom current plan button text |
| `upgradeButtonText` | `string` | `'Upgrade'` | Custom upgrade button text |
| `downgradeButtonText` | `string` | `'Downgrade'` | Custom downgrade button text |
| `showContactSales` | `boolean` | `true` | Show contact sales section |
| `onContactSales` | `() => void` | - | Callback when contact sales clicked |
| `compact` | `boolean` | `false` | Use compact layout |
| `highlightRecommended` | `boolean` | `true` | Highlight recommended plan |
| `plans` | `BillingPlan[]` | - | Plans to display (if not fetching from API) |
| `currency` | `string` | - | Currency override |

#### Features

- **Plan Display**: Shows plan name, description, pricing, and features
- **Interval Toggle**: Switch between monthly and yearly pricing with savings badge
- **Feature Comparison**: Display included features with checkmarks
- **Limits Display**: Show plan limits (users, storage, etc.)
- **Highlight Badge**: Mark recommended plans with custom badge text
- **Trial Badge**: Show trial period for plans with free trials
- **Current Plan**: Disable button and show "Current Plan" for active subscription
- **Upgrade/Downgrade**: Smart button text based on price comparison
- **Loading States**: Spinner during plan fetch and subscription
- **Error Handling**: Display errors with alert role
- **Accessibility**: ARIA roles, labels, keyboard navigation

#### Example with Custom Plans

```tsx
<PricingTable
  realmId="your-realm-id"
  plans={[
    {
      id: 'plan_free',
      name: 'Free',
      description: 'Perfect for getting started',
      type: 'flat_rate',
      price_monthly: 0,
      price_yearly: 0,
      currency: 'usd',
      features: ['5 users', 'Basic support', '1 GB storage'],
      limits: { users: 5, storage_gb: 1 },
      status: 'active',
      sort_order: 1,
    },
    {
      id: 'plan_pro',
      name: 'Pro',
      description: 'For growing teams',
      type: 'per_user',
      price_monthly: 2900,
      price_yearly: 29000,
      currency: 'usd',
      features: ['Unlimited users', 'Priority support', '100 GB storage'],
      limits: { users: -1, storage_gb: 100 },
      status: 'active',
      sort_order: 2,
      highlight_text: 'Most Popular',
      trial_days: 14,
    },
  ]}
/>
```

### BillingPortal

Component for managing billing subscriptions, payment methods, and invoice history.

**Validates: Requirement 7.8**

```tsx
import { BillingPortal } from '@zalt.io/react';

function BillingPage() {
  return (
    <BillingPortal
      tenantId="your-tenant-id"
      realmId="your-realm-id"
      accessToken={token}
      onCancelSuccess={() => {
        console.log('Subscription canceled');
        // Show confirmation message
      }}
      onChangePlan={() => {
        // Navigate to pricing page
        router.push('/pricing');
      }}
      onUpdatePaymentMethod={() => {
        // Open Stripe payment method update
        openStripePortal();
      }}
      onError={(error) => {
        console.error('Billing error:', error);
      }}
    />
  );
}
```

#### BillingPortal Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `apiUrl` | `string` | `'https://api.zalt.io'` | API base URL |
| `accessToken` | `string` | - | Access token for authenticated requests |
| `tenantId` | `string` | - | Tenant ID for billing operations |
| `realmId` | `string` | - | Realm ID for fetching plan details |
| `className` | `string` | `''` | Custom CSS class |
| `showPaymentMethods` | `boolean` | `true` | Show payment methods section |
| `showInvoices` | `boolean` | `true` | Show invoice history section |
| `maxInvoicesShown` | `number` | `10` | Maximum invoices to display |
| `onCancelSubscription` | `(id, cancelAtPeriodEnd) => Promise` | - | Custom cancel handler |
| `onCancelSuccess` | `() => void` | - | Callback when cancel succeeds |
| `onUpdatePaymentMethod` | `() => void` | - | Callback to update payment method |
| `onError` | `(error) => void` | - | Callback on error |
| `cancelButtonText` | `string` | `'Cancel Subscription'` | Custom cancel button text |
| `reactivateButtonText` | `string` | `'Reactivate'` | Custom reactivate button text |
| `showChangePlan` | `boolean` | `true` | Show change plan button |
| `onChangePlan` | `() => void` | - | Callback when user wants to change plan |
| `compact` | `boolean` | `false` | Use compact layout |
| `subscription` | `Subscription` | - | Pre-loaded subscription (skip API fetch) |
| `plan` | `BillingPlan` | - | Pre-loaded plan (skip API fetch) |

#### Features

- **Subscription Info**: Shows current plan name, price, and status
- **Status Badges**: Active, Trial, Past Due, Canceled with appropriate colors
- **Billing Period**: Display current period dates and days remaining
- **Trial Info**: Show trial days remaining for trialing subscriptions
- **Cancel Warning**: Alert when subscription is set to cancel at period end
- **Past Due Warning**: Alert when payment is past due
- **Payment Methods**: Display cards with masked numbers (last 4 digits only)
- **Invoice History**: Table with date, amount, status, and download links
- **Cancel Modal**: Confirmation dialog before canceling
- **Reactivate**: Button to reactivate canceled subscriptions
- **Loading States**: Spinner during data fetch and operations
- **Error Handling**: Display errors with alert role
- **Accessibility**: ARIA labels, roles, keyboard navigation

#### Security Features

- **Payment Info Masking**: Card numbers show only last 4 digits (•••• •••• •••• 4242)
- **No Sensitive Data Exposure**: Full card numbers never displayed
- **Secure API Calls**: All requests include authorization headers

#### Example with Pre-loaded Data

```tsx
<BillingPortal
  tenantId="tenant_123"
  subscription={{
    id: 'sub_123',
    tenant_id: 'tenant_123',
    plan_id: 'plan_pro',
    stripe_subscription_id: 'sub_stripe123',
    status: 'active',
    current_period_start: '2024-01-01T00:00:00Z',
    current_period_end: '2024-02-01T00:00:00Z',
    created_at: '2024-01-01T00:00:00Z',
  }}
  plan={{
    id: 'plan_pro',
    name: 'Pro Plan',
    price_monthly: 2900,
    currency: 'usd',
    // ... other plan fields
  }}
/>
```

### useBilling

Hook for managing billing plans, subscriptions, and entitlements.

**Validates: Requirement 7.9**

```tsx
import { useBilling } from '@zalt.io/react';

function BillingManager() {
  const {
    plans,              // Available billing plans
    subscription,       // Current subscription
    currentPlan,        // Current plan (from subscription)
    usage,              // Usage metrics
    isLoading,          // Loading state
    error,              // Error state
    fetchPlans,         // (realmId?) => Promise
    fetchSubscription,  // () => Promise
    fetchUsage,         // () => Promise
    subscribe,          // (input) => Promise<Subscription>
    cancelSubscription, // (cancelAtPeriodEnd?) => Promise
    checkEntitlement,   // (feature) => Promise<EntitlementResult>
    hasFeature,         // (feature) => boolean (local check)
    getLimit,           // (limitKey) => number | undefined
    isWithinLimit,      // (limitKey, currentUsage) => boolean
    getYearlySavings,   // (plan) => number
    formatPrice,        // (priceInCents, currency?) => string
    clearError,         // () => void
    refresh,            // () => Promise
  } = useBilling({
    realmId: 'your-realm-id',
    tenantId: 'your-tenant-id',
    accessToken: token,
  });

  // Check feature access
  if (hasFeature('advanced_analytics')) {
    // Show advanced features
  }

  // Check usage limits
  if (!isWithinLimit('api_calls', currentApiCalls)) {
    // Show upgrade prompt
  }

  return (
    <div>
      <h2>Current Plan: {currentPlan?.name || 'No Plan'}</h2>
      {subscription?.status === 'trialing' && (
        <p>Trial ends in {getDaysRemaining(subscription.trial_end)} days</p>
      )}
    </div>
  );
}
```

### useSessions

Hook for managing user sessions with support for listing, revoking, and monitoring.

**Validates: Requirement 13.7**

```tsx
import { useSessions } from '@zalt.io/react';

function SessionManager() {
  const {
    sessions,                  // Array of active sessions
    currentSession,            // Current session (if found)
    otherSessions,             // Other sessions (excluding current)
    totalSessions,             // Total session count
    impossibleTravelDetected,  // Whether suspicious activity detected
    isLoading,                 // Loading state
    error,                     // Error message
    fetchSessions,             // () => Promise - refresh sessions
    revokeSession,             // (sessionId) => Promise<boolean>
    revokeAllSessions,         // () => Promise<number> - revoke all except current
    clearError,                // () => void
  } = useSessions({
    accessToken: token,
    apiUrl: 'https://api.zalt.io',
    autoFetch: true,
    pollingInterval: 30000,    // Poll every 30 seconds (0 to disable)
    onSessionRevoked: (id) => console.log('Revoked:', id),
    onAllSessionsRevoked: (count) => console.log('Revoked all:', count),
    onError: (error) => console.error(error),
  });

  const handleRevokeOther = async (sessionId: string) => {
    const success = await revokeSession(sessionId);
    if (success) {
      toast.success('Session revoked');
    }
  };

  return (
    <div>
      <h2>Active Sessions ({totalSessions})</h2>
      {impossibleTravelDetected && (
        <Alert type="warning">Suspicious login activity detected!</Alert>
      )}
      {sessions.map(session => (
        <div key={session.id}>
          <span>{session.device} • {session.browser}</span>
          <span>{session.location?.city}, {session.location?.country}</span>
          {session.is_current ? (
            <Badge>Current</Badge>
          ) : (
            <button onClick={() => handleRevokeOther(session.id)}>Revoke</button>
          )}
        </div>
      ))}
    </div>
  );
}
```

#### Session Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Session ID |
| `device` | `string` | Device type (Desktop, Mobile, Tablet) |
| `browser` | `string` | Browser name and version |
| `ip_address` | `string` | Masked IP address |
| `location` | `SessionLocation` | City, country, country_code |
| `last_activity` | `string` | ISO timestamp of last activity |
| `created_at` | `string` | ISO timestamp of session creation |
| `is_current` | `boolean` | Whether this is the current session |
| `user_agent` | `string` | Full user agent string |
| `impossible_travel` | `ImpossibleTravelInfo` | Suspicious activity details (if detected) |

### SessionList

Complete component for managing user sessions with device info, location, and revoke actions.

**Validates: Requirement 13.7**

```tsx
import { SessionList } from '@zalt.io/react';

function SecuritySettings() {
  return (
    <SessionList
      accessToken={token}
      apiUrl="https://api.zalt.io"
      showRevokeAll={true}
      showLocation={true}
      showImpossibleTravelWarning={true}
      title="Active Sessions"
      onSessionRevoked={(id) => console.log('Revoked:', id)}
      onAllSessionsRevoked={(count) => console.log('Revoked all:', count)}
      onError={(error) => console.error(error)}
      confirmRevoke={true}
      confirmRevokeAll={true}
    />
  );
}
```

#### SessionList Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `apiUrl` | `string` | `'/api'` | API base URL |
| `accessToken` | `string` | - | Access token for authenticated requests |
| `autoFetch` | `boolean` | `true` | Auto-fetch sessions on mount |
| `pollingInterval` | `number` | `0` | Polling interval in ms (0 to disable) |
| `className` | `string` | `''` | Custom CSS class |
| `showRevokeAll` | `boolean` | `true` | Show "Revoke All Others" button |
| `showLocation` | `boolean` | `true` | Show location information |
| `showImpossibleTravelWarning` | `boolean` | `true` | Show suspicious activity warnings |
| `compact` | `boolean` | `false` | Use compact layout |
| `emptyMessage` | `string` | `'No active sessions found.'` | Custom empty state message |
| `title` | `string` | `'Active Sessions'` | Component title |
| `hideTitle` | `boolean` | `false` | Hide the title |
| `onSessionRevoked` | `(id) => void` | - | Callback when session is revoked |
| `onAllSessionsRevoked` | `(count) => void` | - | Callback when all sessions revoked |
| `onError` | `(error) => void` | - | Callback on error |
| `confirmRevoke` | `boolean` | `true` | Show confirmation before revoking |
| `confirmRevokeAll` | `boolean` | `true` | Show confirmation before revoking all |

#### Features

- **Session List**: Display all active sessions with device, browser, and location info
- **Current Session Badge**: Highlight the current session with "Current" badge
- **Revoke Individual**: Button to revoke specific sessions (not shown for current)
- **Revoke All Others**: Button to revoke all sessions except current
- **Location Display**: Show city and country for each session
- **IP Address**: Display masked IP address for privacy
- **Last Activity**: Show relative time since last activity
- **Impossible Travel Detection**: Warning badge and details for suspicious activity
- **Security Alert**: Global warning banner when suspicious activity detected
- **Confirmation Dialogs**: Optional confirmation before revoking sessions
- **Loading States**: Spinner during fetch and revoke operations
- **Error Handling**: Display errors with dismiss button
- **Accessibility**: ARIA labels, keyboard navigation

#### Impossible Travel Warning

When suspicious login activity is detected (e.g., login from two distant locations in a short time), the component shows:

1. **Global Alert**: Warning banner at the top of the component
2. **Session Badge**: "Suspicious" badge on affected sessions
3. **Details**: Information about the suspicious activity including:
   - Previous and current locations
   - Distance traveled
   - Time elapsed
   - Calculated speed

```tsx
// Session with impossible travel info
{
  id: 'session_123',
  device: 'Desktop',
  browser: 'Chrome 120',
  is_current: true,
  impossible_travel: {
    detected: true,
    risk_level: 'high',
    previous_location: { city: 'New York', country: 'USA' },
    current_location: { city: 'Istanbul', country: 'Turkey' },
    distance_km: 8500,
    time_elapsed_hours: 2,
    speed_kmh: 4250,
    reason: 'Travel speed exceeds maximum possible'
  }
}
```

## Theming

Customize appearance with CSS variables:

```tsx
<ZaltProvider
  realmId="your-realm-id"
  appearance={{
    theme: 'dark',
    variables: {
      colorPrimary: '#6366f1',
      colorBackground: '#1a1a2e',
      colorText: '#ffffff',
      fontFamily: 'Inter, sans-serif',
      borderRadius: '12px',
    },
  }}
>
```

Or use CSS:

```css
:root {
  --zalt-color-primary: #6366f1;
  --zalt-color-background: #ffffff;
  --zalt-border-radius: 8px;
}
```

## TypeScript

Full TypeScript support with exported types:

```typescript
import type { User, AuthResult, ZaltConfig } from '@zalt/react';
```

## License

MIT
