/**
 * useUser Hook
 * @zalt/react
 */

'use client';

import type { User } from '@zalt.io/core';
import { useZaltContext } from '../context';

/**
 * Hook to access current user
 * 
 * @example
 * ```tsx
 * import { useUser } from '@zalt/react';
 * 
 * function Profile() {
 *   const user = useUser();
 * 
 *   if (!user) return null;
 * 
 *   return <div>Hello, {user.email}</div>;
 * }
 * ```
 */
export function useUser(): User | null {
  const { state } = useZaltContext();
  return state.user;
}

export default useUser;
