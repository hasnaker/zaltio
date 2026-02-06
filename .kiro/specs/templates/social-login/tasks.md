# Social Login Implementation Tasks

## Tasks

- [ ] 1. OAuth Configuration
  - [ ] 1.1 Set up Google OAuth
    - Create project in Google Cloud Console
    - Configure OAuth consent screen
    - Create OAuth credentials
    - Add to Zalt realm settings
  - [ ] 1.2 Set up GitHub OAuth
    - Create OAuth App in GitHub
    - Add to Zalt realm settings
  - [ ] 1.3 Configure callback URLs
    - Add `https://yourapp.com/api/auth/callback`

- [ ] 2. Social Login Buttons
  - [ ] 2.1 Create GoogleButton component
    ```tsx
    import { useAuth } from '@zalt/react';
    
    function GoogleButton() {
      const { signInWithOAuth } = useAuth();
      return (
        <button onClick={() => signInWithOAuth('google')}>
          Continue with Google
        </button>
      );
    }
    ```
  - [ ] 2.2 Create GitHubButton component
  - [ ] 2.3 Style buttons per brand guidelines

- [ ] 3. Callback Handler
  - [ ] 3.1 Create callback route
    ```typescript
    // app/api/auth/callback/route.ts
    import { handleOAuthCallback } from '@zalt/next';
    
    export async function GET(request: Request) {
      return handleOAuthCallback(request);
    }
    ```
  - [ ] 3.2 Handle success redirect
  - [ ] 3.3 Handle error cases

- [ ] 4. Account Linking
  - [ ] 4.1 Create linked accounts page
    - Show connected providers
    - Connect/disconnect buttons
  - [ ] 4.2 Implement link flow
    ```typescript
    const { linkAccount } = useAuth();
    await linkAccount('github');
    ```
  - [ ] 4.3 Implement unlink flow
    - Verify user has another login method
    - Confirm before unlinking

- [ ] 5. Testing
  - [ ] 5.1 Test Google OAuth flow
  - [ ] 5.2 Test GitHub OAuth flow
  - [ ] 5.3 Test account linking
  - [ ] 5.4 Test error handling

## Code Examples

### Login Page with Social
```tsx
function LoginPage() {
  const { signIn, signInWithOAuth } = useAuth();
  
  return (
    <div>
      <form onSubmit={handleEmailLogin}>
        {/* Email/password form */}
      </form>
      
      <div className="divider">or</div>
      
      <button onClick={() => signInWithOAuth('google')}>
        <GoogleIcon /> Continue with Google
      </button>
      <button onClick={() => signInWithOAuth('github')}>
        <GitHubIcon /> Continue with GitHub
      </button>
    </div>
  );
}
```

### Linked Accounts
```tsx
function LinkedAccounts() {
  const { user, linkAccount, unlinkAccount } = useAuth();
  
  return (
    <div>
      <h2>Connected Accounts</h2>
      {user.linkedAccounts.map(account => (
        <div key={account.provider}>
          {account.provider}: {account.email}
          <button onClick={() => unlinkAccount(account.provider)}>
            Disconnect
          </button>
        </div>
      ))}
      
      <button onClick={() => linkAccount('google')}>
        Connect Google
      </button>
    </div>
  );
}
```
