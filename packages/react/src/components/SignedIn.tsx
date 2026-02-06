/**
 * SignedIn Component
 * @zalt/react
 */

'use client';

import type { ReactNode } from 'react';
import { useAuth } from '../hooks/useAuth';

/**
 * SignedIn props
 */
export interface SignedInProps {
  /** Content to render when user is signed in */
  children: ReactNode;
  /** Content to render while loading (optional) */
  fallback?: ReactNode;
}

/**
 * Renders children only when user is authenticated
 * 
 * @example
 * ```tsx
 * import { SignedIn } from '@zalt/react';
 * 
 * function App() {
 *   return (
 *     <SignedIn>
 *       <Dashboard />
 *     </SignedIn>
 *   );
 * }
 * ```
 */
export function SignedIn({ children, fallback = null }: SignedInProps): JSX.Element | null {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return fallback as JSX.Element | null;
  }

  if (!isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}

export default SignedIn;
