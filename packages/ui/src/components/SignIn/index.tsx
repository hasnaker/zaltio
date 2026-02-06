'use client';

import React, { useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../../primitives/Card';
import { Button } from '../../primitives/Button';
import { Input } from '../../primitives/Input';
import { cn } from '../../utils/cn';
import { SocialButtons, type SocialProvider } from './SocialButtons';
import { MFAChallenge } from './MFAChallenge';

export interface SignInAppearance {
  theme?: 'light' | 'dark';
  elements?: {
    card?: string;
    header?: string;
    title?: string;
    description?: string;
    form?: string;
    input?: string;
    button?: string;
    socialButtons?: string;
    footer?: string;
  };
}

export interface SignInProps {
  /** Custom appearance configuration */
  appearance?: SignInAppearance;
  /** Routing mode */
  routing?: 'path' | 'hash' | 'virtual';
  /** Path for sign-in page */
  path?: string;
  /** URL to redirect after sign-in */
  afterSignInUrl?: string;
  /** URL for sign-up page */
  signUpUrl?: string;
  /** URL for forgot password */
  forgotPasswordUrl?: string;
  /** Social buttons placement */
  socialButtonsPlacement?: 'top' | 'bottom';
  /** Social buttons variant */
  socialButtonsVariant?: 'auto' | 'iconButton' | 'blockButton';
  /** Available social providers */
  socialProviders?: SocialProvider[];
  /** Custom logo */
  logo?: React.ReactNode;
  /** Custom header text */
  headerText?: string;
  /** Custom description */
  description?: string;
  /** Callback when sign-in is successful */
  onSignIn?: (data: { userId: string; accessToken: string }) => void;
  /** Callback when sign-in fails */
  onError?: (error: Error) => void;
  /** Custom sign-in handler (for headless usage) */
  signInHandler?: (email: string, password: string) => Promise<SignInResult>;
  /** Custom social sign-in handler */
  socialSignInHandler?: (provider: SocialProvider) => Promise<void>;
}

export interface SignInResult {
  success: boolean;
  mfaRequired?: boolean;
  mfaSessionId?: string;
  mfaMethods?: ('totp' | 'webauthn' | 'backup_code')[];
  userId?: string;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
}

/**
 * SignIn - Drop-in sign-in component
 * 
 * @example
 * ```tsx
 * <SignIn 
 *   afterSignInUrl="/dashboard"
 *   signUpUrl="/sign-up"
 *   socialProviders={['google', 'apple', 'github']}
 * />
 * ```
 */
export function SignIn({
  appearance,
  afterSignInUrl = '/dashboard',
  signUpUrl = '/sign-up',
  forgotPasswordUrl = '/forgot-password',
  socialButtonsPlacement = 'bottom',
  socialButtonsVariant = 'auto',
  socialProviders = [],
  logo,
  headerText = 'Sign in',
  description = 'Enter your credentials to access your account',
  onSignIn,
  onError,
  signInHandler,
  socialSignInHandler,
}: SignInProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mfaState, setMfaState] = useState<{
    required: boolean;
    sessionId: string;
    methods: ('totp' | 'webauthn' | 'backup_code')[];
  } | null>(null);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (!signInHandler) {
        throw new Error('signInHandler is required');
      }

      const result = await signInHandler(email, password);

      if (result.mfaRequired && result.mfaSessionId) {
        setMfaState({
          required: true,
          sessionId: result.mfaSessionId,
          methods: result.mfaMethods || ['totp'],
        });
        return;
      }

      if (result.success && result.userId && result.accessToken) {
        onSignIn?.({ userId: result.userId, accessToken: result.accessToken });
        if (afterSignInUrl) {
          window.location.href = afterSignInUrl;
        }
      } else {
        setError(result.error || 'Invalid credentials');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setLoading(false);
    }
  }, [email, password, signInHandler, onSignIn, onError, afterSignInUrl]);

  const handleSocialSignIn = useCallback(async (provider: SocialProvider) => {
    if (!socialSignInHandler) return;
    
    try {
      setLoading(true);
      setError(null);
      await socialSignInHandler(provider);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Social sign-in failed';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setLoading(false);
    }
  }, [socialSignInHandler, onError]);

  const handleMFAComplete = useCallback((result: SignInResult) => {
    if (result.success && result.userId && result.accessToken) {
      onSignIn?.({ userId: result.userId, accessToken: result.accessToken });
      if (afterSignInUrl) {
        window.location.href = afterSignInUrl;
      }
    }
  }, [onSignIn, afterSignInUrl]);

  // Show MFA challenge if required
  if (mfaState?.required) {
    return (
      <MFAChallenge
        sessionId={mfaState.sessionId}
        methods={mfaState.methods}
        onComplete={handleMFAComplete}
        onCancel={() => setMfaState(null)}
        appearance={appearance}
      />
    );
  }

  const socialButtonsElement = socialProviders.length > 0 && (
    <SocialButtons
      providers={socialProviders}
      variant={socialButtonsVariant}
      onSelect={handleSocialSignIn}
      disabled={loading}
      className={appearance?.elements?.socialButtons}
    />
  );

  return (
    <Card className={cn('w-full max-w-md mx-auto', appearance?.elements?.card)}>
      <CardHeader className={cn('space-y-1 text-center', appearance?.elements?.header)}>
        {logo && <div className="flex justify-center mb-4">{logo}</div>}
        <CardTitle className={cn('text-2xl', appearance?.elements?.title)}>
          {headerText}
        </CardTitle>
        <CardDescription className={appearance?.elements?.description}>
          {description}
        </CardDescription>
      </CardHeader>

      <CardContent className={appearance?.elements?.form}>
        {socialButtonsPlacement === 'top' && socialButtonsElement}
        
        {socialButtonsPlacement === 'top' && socialProviders.length > 0 && (
          <div className="relative my-4">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-[var(--zalt-border)]" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-[var(--zalt-card)] px-2 text-[var(--zalt-muted-foreground)]">
                Or continue with email
              </span>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            type="email"
            label="Email"
            placeholder="name@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
            disabled={loading}
            className={appearance?.elements?.input}
          />

          <Input
            type="password"
            label="Password"
            placeholder="Enter your password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            disabled={loading}
            className={appearance?.elements?.input}
          />

          {error && (
            <div className="text-sm text-[var(--zalt-error)] text-center">
              {error}
            </div>
          )}

          <Button
            type="submit"
            className={cn('w-full', appearance?.elements?.button)}
            loading={loading}
          >
            Sign in
          </Button>
        </form>

        {socialButtonsPlacement === 'bottom' && socialProviders.length > 0 && (
          <div className="relative my-4">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-[var(--zalt-border)]" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-[var(--zalt-card)] px-2 text-[var(--zalt-muted-foreground)]">
                Or continue with
              </span>
            </div>
          </div>
        )}

        {socialButtonsPlacement === 'bottom' && socialButtonsElement}
      </CardContent>

      <CardFooter className={cn('flex flex-col space-y-2 text-center text-sm', appearance?.elements?.footer)}>
        {forgotPasswordUrl && (
          <a
            href={forgotPasswordUrl}
            className="text-[var(--zalt-primary)] hover:underline"
          >
            Forgot your password?
          </a>
        )}
        {signUpUrl && (
          <p className="text-[var(--zalt-muted-foreground)]">
            Don't have an account?{' '}
            <a href={signUpUrl} className="text-[var(--zalt-primary)] hover:underline">
              Sign up
            </a>
          </p>
        )}
      </CardFooter>
    </Card>
  );
}

export { SocialButtons, type SocialProvider } from './SocialButtons';
export { MFAChallenge } from './MFAChallenge';
