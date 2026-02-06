/**
 * useAuth Hook
 * @zalt/react
 */

'use client';

import { useCallback } from 'react';
import type { User, AuthState } from '@zalt.io/core';
import { useZaltContext } from '../context';

/**
 * useAuth return type
 */
export interface UseAuthReturn {
  /** Current user or null */
  user: User | null;
  /** Loading state */
  isLoading: boolean;
  /** Whether user is authenticated */
  isAuthenticated: boolean;
  /** Sign in with email and password */
  signIn: (email: string, password: string) => Promise<void>;
  /** Sign up with email and password */
  signUp: (data: { email: string; password: string; profile?: Record<string, unknown> }) => Promise<void>;
  /** Sign out */
  signOut: () => Promise<void>;
  /** Current auth state */
  state: AuthState;
}

/**
 * Hook to access authentication state and methods
 * 
 * @example
 * ```tsx
 * import { useAuth } from '@zalt/react';
 * 
 * function LoginButton() {
 *   const { user, isLoading, signIn, signOut } = useAuth();
 * 
 *   if (isLoading) return <div>Loading...</div>;
 * 
 *   if (user) {
 *     return <button onClick={signOut}>Sign Out</button>;
 *   }
 * 
 *   return <button onClick={() => signIn('email', 'password')}>Sign In</button>;
 * }
 * ```
 */
export function useAuth(): UseAuthReturn {
  const { state, signIn, signUp, signOut } = useZaltContext();

  return {
    user: state.user,
    isLoading: state.isLoading,
    isAuthenticated: state.isAuthenticated,
    signIn,
    signUp,
    signOut,
    state,
  };
}

export default useAuth;
