'use client';

import React, { useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../../primitives/Card';
import { Button } from '../../primitives/Button';
import { Input } from '../../primitives/Input';
import { cn } from '../../utils/cn';
import { SocialButtons, type SocialProvider } from '../SignIn/SocialButtons';
import { PasswordStrength } from './PasswordStrength';

export interface SignUpAppearance {
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

export interface SignUpProps {
  appearance?: SignUpAppearance;
  path?: string;
  afterSignUpUrl?: string;
  signInUrl?: string;
  socialButtonsPlacement?: 'top' | 'bottom';
  socialProviders?: SocialProvider[];
  logo?: React.ReactNode;
  headerText?: string;
  description?: string;
  /** Show password strength indicator */
  showPasswordStrength?: boolean;
  /** Require terms acceptance */
  requireTerms?: boolean;
  termsUrl?: string;
  privacyUrl?: string;
  /** Custom metadata to attach to user */
  unsafeMetadata?: Record<string, unknown>;
  onSignUp?: (data: { userId: string; accessToken: string }) => void;
  onError?: (error: Error) => void;
  signUpHandler?: (data: SignUpData) => Promise<SignUpResult>;
  socialSignUpHandler?: (provider: SocialProvider) => Promise<void>;
}

export interface SignUpData {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  metadata?: Record<string, unknown>;
}

export interface SignUpResult {
  success: boolean;
  requiresEmailVerification?: boolean;
  userId?: string;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
}

export function SignUp({
  appearance,
  afterSignUpUrl = '/dashboard',
  signInUrl = '/sign-in',
  socialButtonsPlacement = 'bottom',
  socialProviders = [],
  logo,
  headerText = 'Create an account',
  description = 'Enter your details to get started',
  showPasswordStrength = true,
  requireTerms = false,
  termsUrl = '/terms',
  privacyUrl = '/privacy',
  unsafeMetadata,
  onSignUp,
  onError,
  signUpHandler,
  socialSignUpHandler,
}: SignUpProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verificationSent, setVerificationSent] = useState(false);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (requireTerms && !termsAccepted) {
      setError('Please accept the terms and conditions');
      return;
    }

    setLoading(true);

    try {
      if (!signUpHandler) {
        throw new Error('signUpHandler is required');
      }

      const result = await signUpHandler({
        email,
        password,
        firstName: firstName || undefined,
        lastName: lastName || undefined,
        metadata: unsafeMetadata,
      });

      if (result.requiresEmailVerification) {
        setVerificationSent(true);
        return;
      }

      if (result.success && result.userId && result.accessToken) {
        onSignUp?.({ userId: result.userId, accessToken: result.accessToken });
        if (afterSignUpUrl) {
          window.location.href = afterSignUpUrl;
        }
      } else {
        setError(result.error || 'Registration failed');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setLoading(false);
    }
  }, [email, password, firstName, lastName, termsAccepted, requireTerms, signUpHandler, unsafeMetadata, onSignUp, onError, afterSignUpUrl]);

  const handleSocialSignUp = useCallback(async (provider: SocialProvider) => {
    if (!socialSignUpHandler) return;
    
    try {
      setLoading(true);
      setError(null);
      await socialSignUpHandler(provider);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Social sign-up failed';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setLoading(false);
    }
  }, [socialSignUpHandler, onError]);

  // Show verification message
  if (verificationSent) {
    return (
      <Card className={cn('w-full max-w-md mx-auto', appearance?.elements?.card)}>
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="p-3 rounded-full bg-[var(--zalt-success)]/10 text-[var(--zalt-success)]">
              <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
          </div>
          <CardTitle>Check your email</CardTitle>
          <CardDescription>
            We've sent a verification link to <strong>{email}</strong>
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center text-sm text-[var(--zalt-muted-foreground)]">
          <p>Click the link in the email to verify your account and complete registration.</p>
        </CardContent>
        <CardFooter className="justify-center">
          <Button variant="ghost" onClick={() => setVerificationSent(false)}>
            Use a different email
          </Button>
        </CardFooter>
      </Card>
    );
  }

  const socialButtonsElement = socialProviders.length > 0 && (
    <SocialButtons
      providers={socialProviders}
      variant="blockButton"
      onSelect={handleSocialSignUp}
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
          <div className="grid grid-cols-2 gap-4">
            <Input
              type="text"
              label="First name"
              placeholder="John"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              autoComplete="given-name"
              disabled={loading}
              className={appearance?.elements?.input}
            />
            <Input
              type="text"
              label="Last name"
              placeholder="Doe"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              autoComplete="family-name"
              disabled={loading}
              className={appearance?.elements?.input}
            />
          </div>

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

          <div>
            <Input
              type="password"
              label="Password"
              placeholder="Create a strong password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="new-password"
              disabled={loading}
              className={appearance?.elements?.input}
            />
            {showPasswordStrength && password && (
              <PasswordStrength password={password} />
            )}
          </div>

          {requireTerms && (
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={termsAccepted}
                onChange={(e) => setTermsAccepted(e.target.checked)}
                className="mt-1 rounded border-[var(--zalt-border)]"
              />
              <span className="text-[var(--zalt-muted-foreground)]">
                I agree to the{' '}
                <a href={termsUrl} className="text-[var(--zalt-primary)] hover:underline" target="_blank" rel="noopener noreferrer">
                  Terms of Service
                </a>{' '}
                and{' '}
                <a href={privacyUrl} className="text-[var(--zalt-primary)] hover:underline" target="_blank" rel="noopener noreferrer">
                  Privacy Policy
                </a>
              </span>
            </label>
          )}

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
            Create account
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

      <CardFooter className={cn('flex justify-center text-sm', appearance?.elements?.footer)}>
        <p className="text-[var(--zalt-muted-foreground)]">
          Already have an account?{' '}
          <a href={signInUrl} className="text-[var(--zalt-primary)] hover:underline">
            Sign in
          </a>
        </p>
      </CardFooter>
    </Card>
  );
}

export { PasswordStrength } from './PasswordStrength';
