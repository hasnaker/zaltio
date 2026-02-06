/**
 * Zalt React Context
 * @zalt/react
 */

import { createContext, useContext } from 'react';
import type { ZaltClient, AuthState, User } from '@zalt.io/core';

/**
 * Zalt context value
 */
export interface ZaltContextValue {
  client: ZaltClient;
  state: AuthState;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (data: { email: string; password: string; profile?: Record<string, unknown> }) => Promise<void>;
  signOut: () => Promise<void>;
}

/**
 * Zalt context - internal use only
 */
export const ZaltContext = createContext<ZaltContextValue | null>(null);

/**
 * Hook to access Zalt context
 * @internal
 */
export function useZaltContext(): ZaltContextValue {
  const context = useContext(ZaltContext);
  if (!context) {
    throw new Error(
      'useZaltContext must be used within a ZaltProvider. ' +
      'Wrap your app with <ZaltProvider publishableKey="pk_live_xxx">...</ZaltProvider>'
    );
  }
  return context;
}
