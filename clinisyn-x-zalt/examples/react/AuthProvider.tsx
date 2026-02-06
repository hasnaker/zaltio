/**
 * Clinisyn x Zalt.io - React Auth Context Provider
 * 
 * Kullanım:
 * // App.tsx
 * <ZaltAuthProvider>
 *   <App />
 * </ZaltAuthProvider>
 * 
 * // Component
 * const { user, login, logout } = useAuth();
 */

import React, { createContext, useContext, ReactNode } from 'react';
import { useZaltAuth } from './useZaltAuth';

// Types
interface User {
  id: string;
  email: string;
  realmId: string;
}

interface MfaChallenge {
  sessionId: string;
  methods: string[];
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<MfaChallenge | null>;
  logout: () => Promise<void>;
  verifyMfa: (sessionId: string, code: string, method?: string) => Promise<void>;
  refreshSession: () => Promise<boolean>;
  clearError: () => void;
}

// Context
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Provider
interface ZaltAuthProviderProps {
  children: ReactNode;
}

export function ZaltAuthProvider({ children }: ZaltAuthProviderProps) {
  const auth = useZaltAuth();

  return (
    <AuthContext.Provider value={auth}>
      {children}
    </AuthContext.Provider>
  );
}

// Hook
export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  
  if (context === undefined) {
    throw new Error('useAuth must be used within a ZaltAuthProvider');
  }
  
  return context;
}

// HOC for protected routes
interface WithAuthProps {
  fallback?: ReactNode;
  redirectTo?: string;
}

export function withAuth<P extends object>(
  Component: React.ComponentType<P>,
  options: WithAuthProps = {}
) {
  const { fallback = null, redirectTo } = options;

  return function AuthenticatedComponent(props: P) {
    const { isAuthenticated, isLoading } = useAuth();

    if (isLoading) {
      return fallback;
    }

    if (!isAuthenticated) {
      if (redirectTo && typeof window !== 'undefined') {
        window.location.href = redirectTo;
        return null;
      }
      return fallback;
    }

    return <Component {...props} />;
  };
}

// Protected Route Component
interface ProtectedRouteProps {
  children: ReactNode;
  fallback?: ReactNode;
  redirectTo?: string;
}

export function ProtectedRoute({ children, fallback = null, redirectTo }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <>{fallback}</>;
  }

  if (!isAuthenticated) {
    if (redirectTo && typeof window !== 'undefined') {
      window.location.href = redirectTo;
      return null;
    }
    return <>{fallback}</>;
  }

  return <>{children}</>;
}

export default ZaltAuthProvider;
