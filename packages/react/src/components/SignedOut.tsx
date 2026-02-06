/**
 * SignedOut Component
 * @zalt/react
 */

'use client';

import type { ReactNode } from 'react';
import { useAuth } from '../hooks/useAuth';

/**
 * SignedOut props
 */
export interface SignedOutProps {
  /** Content to render when user is signed out */
  children: ReactNode;
  /** Content to render while loading (optional) */
  fallback?: ReactNode;
}

/**
 * Renders children only when user is NOT authenticated
 * 
 * @example
 * ```tsx
 * import { SignedOut } from '@zalt/react';
 * 
 * function App() {
 *   return (
 *     <SignedOut>
 *       <LoginPage />
 *     </SignedOut>
 *   );
 * }
 * ```
 */
export function SignedOut({ children, fallback = null }: SignedOutProps): JSX.Element | null {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return fallback as JSX.Element | null;
  }

  if (isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}

export default SignedOut;
