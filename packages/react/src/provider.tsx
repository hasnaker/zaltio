/**
 * Zalt Provider Component
 * @zalt/react
 */

'use client';

import React, { useEffect, useState, useCallback, useMemo, type ReactNode } from 'react';
import {
  createZaltClient,
  type ZaltClient as ZaltClientType,
  type AuthState,
  type AuthStateChangeEvent,
  type User,
  MFARequiredError,
} from '@zalt.io/core';
import { ZaltContext, type ZaltContextValue } from './context';

/**
 * Appearance configuration for Zalt components
 */
export interface AppearanceConfig {
  /** Primary brand color */
  primaryColor?: string;
  /** Background color */
  backgroundColor?: string;
  /** Text color */
  textColor?: string;
  /** Border radius */
  borderRadius?: string;
  /** Font family */
  fontFamily?: string;
  /** Dark mode preference */
  darkMode?: 'auto' | 'light' | 'dark';
}

/**
 * ZaltProvider props
 */
export interface ZaltProviderProps {
  /** 
   * Publishable API key (pk_live_xxx or pk_test_xxx)
   * Get this from your Zalt.io dashboard
   */
  publishableKey: string;
  /** 
   * Realm ID for multi-tenant isolation
   * @deprecated Use publishableKey instead - realm is extracted from the key
   */
  realmId?: string;
  /** Children components */
  children: ReactNode;
  /** API base URL (default: https://api.zalt.io) */
  baseUrl?: string;
  /** Appearance configuration */
  appearance?: AppearanceConfig;
  /** Enable debug logging */
  debug?: boolean;
  /** Callback when auth state changes */
  onAuthStateChange?: (state: AuthState) => void;
}

/**
 * MFA state for handling MFA flow
 */
export interface MFAState {
  isRequired: boolean;
  sessionId: string | null;
  methods: string[];
}

/**
 * Zalt Provider - wraps your app to provide auth context
 * 
 * @example
 * ```tsx
 * import { ZaltProvider } from '@zalt.io/react';
 * 
 * function App() {
 *   return (
 *     <ZaltProvider publishableKey="pk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456">
 *       <YourApp />
 *     </ZaltProvider>
 *   );
 * }
 * ```
 */
export function ZaltProvider({
  publishableKey,
  realmId,
  children,
  baseUrl,
  appearance,
  debug = false,
  onAuthStateChange,
}: ZaltProviderProps): JSX.Element {
  // Create client once
  const client = useMemo(() => {
    return createZaltClient({
      publishableKey,
      realmId,
      baseUrl,
      debug,
    });
  }, [publishableKey, realmId, baseUrl, debug]);

  // Auth state
  const [state, setState] = useState<AuthState>({
    user: null,
    isLoading: true,
    isAuthenticated: false,
    error: null,
  });

  // MFA state
  const [mfaState, setMfaState] = useState<MFAState>({
    isRequired: false,
    sessionId: null,
    methods: [],
  });

  // Initialize on mount
  useEffect(() => {
    let mounted = true;

    const initialize = async () => {
      try {
        const user = await client.initialize();
        if (mounted) {
          setState({
            user,
            isLoading: false,
            isAuthenticated: user !== null,
            error: null,
          });
        }
      } catch (error) {
        if (mounted) {
          setState({
            user: null,
            isLoading: false,
            isAuthenticated: false,
            error: null,
          });
        }
      }
    };

    initialize();

    // Subscribe to auth state changes
    const unsubscribe = client.onAuthStateChange((event: AuthStateChangeEvent) => {
      if (!mounted) return;

      switch (event.type) {
        case 'SIGNED_IN':
          setState({
            user: event.user,
            isLoading: false,
            isAuthenticated: true,
            error: null,
          });
          setMfaState({ isRequired: false, sessionId: null, methods: [] });
          break;

        case 'SIGNED_OUT':
          setState({
            user: null,
            isLoading: false,
            isAuthenticated: false,
            error: null,
          });
          break;

        case 'USER_UPDATED':
          setState(prev => ({
            ...prev,
            user: event.user,
          }));
          break;

        case 'SESSION_EXPIRED':
          setState({
            user: null,
            isLoading: false,
            isAuthenticated: false,
            error: { code: 'AUTHENTICATION_ERROR', message: 'Session expired', statusCode: 401 },
          });
          break;

        case 'MFA_REQUIRED':
          setMfaState({
            isRequired: true,
            sessionId: event.sessionId,
            methods: event.methods,
          });
          break;
      }
    });

    return () => {
      mounted = false;
      unsubscribe();
    };
  }, [client]);

  // Notify parent of state changes
  useEffect(() => {
    onAuthStateChange?.(state);
  }, [state, onAuthStateChange]);

  // Sign in handler
  const signIn = useCallback(async (email: string, password: string) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      await client.login({ email, password });
    } catch (error) {
      if (error instanceof MFARequiredError) {
        setMfaState({
          isRequired: true,
          sessionId: error.sessionId,
          methods: error.methods,
        });
        setState(prev => ({ ...prev, isLoading: false }));
        return;
      }

      setState(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error 
          ? { code: 'AUTHENTICATION_ERROR', message: error.message, statusCode: 401 }
          : null,
      }));
      throw error;
    }
  }, [client]);

  // Sign up handler
  const signUp = useCallback(async (data: { email: string; password: string; profile?: Record<string, unknown> }) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      await client.register({
        email: data.email,
        password: data.password,
        profile: data.profile,
      });
    } catch (error) {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error
          ? { code: 'VALIDATION_ERROR' as const, message: error.message, statusCode: 400, fields: {} }
          : null,
      }));
      throw error;
    }
  }, [client]);

  // Sign out handler
  const signOut = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true }));
    await client.logout();
  }, [client]);

  // Context value
  const contextValue: ZaltContextValue = useMemo(() => ({
    client,
    state,
    signIn,
    signUp,
    signOut,
  }), [client, state, signIn, signUp, signOut]);

  // Apply appearance CSS variables
  const style = useMemo(() => {
    if (!appearance) return undefined;

    return {
      '--zalt-primary': appearance.primaryColor || '#10b981',
      '--zalt-bg': appearance.backgroundColor || '#0a0a0a',
      '--zalt-text': appearance.textColor || '#ffffff',
      '--zalt-radius': appearance.borderRadius || '0.5rem',
      '--zalt-font': appearance.fontFamily || 'system-ui, sans-serif',
    } as React.CSSProperties;
  }, [appearance]);

  return (
    <ZaltContext.Provider value={contextValue}>
      <div style={style} data-zalt-provider>
        {children}
      </div>
    </ZaltContext.Provider>
  );
}

export default ZaltProvider;
