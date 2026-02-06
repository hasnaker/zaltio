'use client';

import React, { useState } from 'react';
import { GlassCard } from '../ui/GlassCard';
import { FloatingInput } from '../ui/FloatingInput';
import { GlowButton } from '../ui/GlowButton';

export interface LoginCardProps {
  onSubmit: (email: string, password: string) => Promise<void>;
  error?: string;
  loading?: boolean;
  onForgotPassword?: () => void;
  onSignUp?: () => void;
}

/**
 * LoginCard Component
 * 
 * A glassmorphism login card with NEXUS branding, floating inputs,
 * gradient sign-in button, and security badge.
 * 
 * Requirements: 3.1, 3.2, 3.3, 3.4, 3.6, 3.7
 */
export function LoginCard({
  onSubmit,
  error,
  loading = false,
  onForgotPassword,
  onSignUp,
}: LoginCardProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [hasError, setHasError] = useState(false);

  // Trigger shake animation when error changes
  React.useEffect(() => {
    if (error) {
      setHasError(true);
      const timer = setTimeout(() => setHasError(false), 500);
      return () => clearTimeout(timer);
    }
  }, [error]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSubmit(email, password);
  };

  return (
    <GlassCard
      variant="elevated"
      glow="cyan"
      className={`w-full max-w-md p-8 ${hasError ? 'animate-shake' : ''}`}
    >
      {/* NEXUS Logo with Glow */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center mb-4">
          <div className="relative">
            {/* Logo glow effect */}
            <div className="absolute inset-0 blur-xl bg-nexus-glow-cyan/30 rounded-full animate-glow-pulse" />
            {/* Logo icon */}
            <div className="relative w-16 h-16 flex items-center justify-center">
              <svg
                viewBox="0 0 48 48"
                className="w-full h-full text-nexus-glow-cyan"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M24 4L4 14v20l20 10 20-10V14L24 4z"
                  stroke="currentColor"
                  strokeWidth="2"
                  fill="none"
                />
                <path
                  d="M24 4v40M4 14l20 10 20-10M4 34l20-10 20 10"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeOpacity="0.5"
                />
                <circle cx="24" cy="24" r="6" fill="currentColor" fillOpacity="0.3" />
                <circle cx="24" cy="24" r="3" fill="currentColor" />
              </svg>
            </div>
          </div>
        </div>
        <h1 className="text-3xl font-heading font-bold text-nexus-text-primary tracking-tight">
          NEXUS
        </h1>
        <p className="text-nexus-text-muted mt-1 text-sm">
          Neural EXtended Unified Security
        </p>
      </div>

      {/* Login Form */}
      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Error Message */}
        {error && (
          <div
            className="bg-nexus-error/10 border border-nexus-error/30 text-nexus-error px-4 py-3 rounded-lg text-sm animate-shake"
            role="alert"
            data-testid="login-error"
          >
            {error}
          </div>
        )}

        {/* Email Input */}
        <FloatingInput
          label="Email"
          type="email"
          value={email}
          onChange={setEmail}
          required
          autoComplete="email"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          }
        />

        {/* Password Input */}
        <FloatingInput
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          required
          autoComplete="current-password"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          }
        />

        {/* Sign In Button */}
        <GlowButton
          type="submit"
          variant="primary"
          size="lg"
          loading={loading}
          disabled={loading}
          className="w-full"
        >
          Sign In
        </GlowButton>
      </form>

      {/* Links */}
      <div className="mt-6 flex items-center justify-between text-sm">
        <button
          type="button"
          onClick={onForgotPassword}
          className="text-nexus-text-muted hover:text-nexus-glow-cyan transition-colors duration-200 hover:underline underline-offset-4"
        >
          Forgot Password?
        </button>
        <button
          type="button"
          onClick={onSignUp}
          className="text-nexus-text-muted hover:text-nexus-glow-cyan transition-colors duration-200 hover:underline underline-offset-4"
        >
          Sign Up
        </button>
      </div>

      {/* Security Badge */}
      <div className="mt-8 pt-6 border-t border-white/10">
        <div className="flex items-center justify-center gap-2 text-nexus-text-muted text-xs">
          <svg className="w-4 h-4 text-nexus-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <span>256-bit encryption</span>
          <span className="text-nexus-text-disabled">•</span>
          <span>Secure connection</span>
        </div>
      </div>
    </GlassCard>
  );
}

export default LoginCard;
