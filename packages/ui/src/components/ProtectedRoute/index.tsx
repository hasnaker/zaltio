'use client';

import React, { useEffect, useState } from 'react';
import { Spinner } from '../../primitives/Spinner';

export interface ProtectedRouteProps {
  /** Content to render when authenticated */
  children: React.ReactNode;
  /** Fallback to show while checking auth */
  fallback?: React.ReactNode;
  /** URL to redirect if not authenticated */
  redirectTo?: string;
  /** Custom auth check function */
  isAuthenticated?: () => boolean | Promise<boolean>;
  /** Called when auth check completes */
  onAuthStateChange?: (isAuthenticated: boolean) => void;
}

/**
 * ProtectedRoute - Guards routes that require authentication
 * 
 * @example
 * ```tsx
 * <ProtectedRoute 
 *   redirectTo="/sign-in"
 *   fallback={<Loading />}
 * >
 *   <Dashboard />
 * </ProtectedRoute>
 * ```
 */
export function ProtectedRoute({
  children,
  fallback,
  redirectTo = '/sign-in',
  isAuthenticated,
  onAuthStateChange,
}: ProtectedRouteProps) {
  const [authState, setAuthState] = useState<'loading' | 'authenticated' | 'unauthenticated'>('loading');

  useEffect(() => {
    async function checkAuth() {
      try {
        let authenticated = false;

        if (isAuthenticated) {
          const result = isAuthenticated();
          authenticated = result instanceof Promise ? await result : result;
        } else {
          // Default: check for access token in localStorage
          const token = localStorage.getItem('zalt_access_token');
          authenticated = !!token;
        }

        setAuthState(authenticated ? 'authenticated' : 'unauthenticated');
        onAuthStateChange?.(authenticated);

        if (!authenticated && redirectTo) {
          // Add return URL for redirect back after login
          const returnUrl = encodeURIComponent(window.location.pathname + window.location.search);
          window.location.href = `${redirectTo}?returnUrl=${returnUrl}`;
        }
      } catch (error) {
        console.error('Auth check failed:', error);
        setAuthState('unauthenticated');
        onAuthStateChange?.(false);
        
        if (redirectTo) {
          window.location.href = redirectTo;
        }
      }
    }

    checkAuth();
  }, [isAuthenticated, redirectTo, onAuthStateChange]);

  // Loading state
  if (authState === 'loading') {
    return (
      fallback || (
        <div className="flex items-center justify-center min-h-[200px]">
          <Spinner size="lg" />
        </div>
      )
    );
  }

  // Unauthenticated - will redirect
  if (authState === 'unauthenticated') {
    return (
      fallback || (
        <div className="flex items-center justify-center min-h-[200px]">
          <Spinner size="lg" />
        </div>
      )
    );
  }

  // Authenticated - render children
  return <>{children}</>;
}

/**
 * Hook version for more control
 */
export function useProtectedRoute(options?: {
  redirectTo?: string;
  isAuthenticated?: () => boolean | Promise<boolean>;
}): {
  isLoading: boolean;
  isAuthenticated: boolean;
} {
  const [state, setState] = useState<{ isLoading: boolean; isAuthenticated: boolean }>({
    isLoading: true,
    isAuthenticated: false,
  });

  useEffect(() => {
    async function checkAuth() {
      try {
        let authenticated = false;

        if (options?.isAuthenticated) {
          const result = options.isAuthenticated();
          authenticated = result instanceof Promise ? await result : result;
        } else {
          const token = localStorage.getItem('zalt_access_token');
          authenticated = !!token;
        }

        setState({ isLoading: false, isAuthenticated: authenticated });

        if (!authenticated && options?.redirectTo) {
          const returnUrl = encodeURIComponent(window.location.pathname + window.location.search);
          window.location.href = `${options.redirectTo}?returnUrl=${returnUrl}`;
        }
      } catch {
        setState({ isLoading: false, isAuthenticated: false });
        if (options?.redirectTo) {
          window.location.href = options.redirectTo;
        }
      }
    }

    checkAuth();
  }, [options]);

  return state;
}
