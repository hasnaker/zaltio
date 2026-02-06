'use client';

import React, { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react';
import type { ThemeMode, ThemeContextValue, ThemeConfig } from './types';
import { defaultTheme } from './default';
import { darkTheme } from './dark';

const ThemeContext = createContext<ThemeContextValue | null>(null);

/**
 * Hook to access the current theme
 */
export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
}

interface ThemeProviderProps {
  children: React.ReactNode;
  /** Default theme mode */
  defaultMode?: ThemeMode;
  /** Custom theme configuration */
  theme?: ThemeConfig;
  /** Storage key for persisting theme preference */
  storageKey?: string;
  /** Disable system theme detection */
  disableSystemTheme?: boolean;
}

/**
 * ThemeProvider - Provides theme context to all Zalt UI components
 * 
 * @example
 * ```tsx
 * <ThemeProvider defaultMode="system">
 *   <SignIn />
 * </ThemeProvider>
 * ```
 */
export function ThemeProvider({
  children,
  defaultMode = 'system',
  theme: themeConfig,
  storageKey = 'zalt-theme-mode',
  disableSystemTheme = false,
}: ThemeProviderProps) {
  const [mode, setModeState] = useState<ThemeMode>(defaultMode);
  const [systemMode, setSystemMode] = useState<'light' | 'dark'>('light');

  // Detect system theme preference
  useEffect(() => {
    if (disableSystemTheme) return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    setSystemMode(mediaQuery.matches ? 'dark' : 'light');

    const handler = (e: MediaQueryListEvent) => {
      setSystemMode(e.matches ? 'dark' : 'light');
    };

    mediaQuery.addEventListener('change', handler);
    return () => mediaQuery.removeEventListener('change', handler);
  }, [disableSystemTheme]);

  // Load persisted theme preference
  useEffect(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      if (stored && ['light', 'dark', 'system'].includes(stored)) {
        setModeState(stored as ThemeMode);
      }
    } catch {
      // localStorage not available
    }
  }, [storageKey]);

  const setMode = useCallback((newMode: ThemeMode) => {
    setModeState(newMode);
    try {
      localStorage.setItem(storageKey, newMode);
    } catch {
      // localStorage not available
    }
  }, [storageKey]);

  const resolvedMode = mode === 'system' ? systemMode : mode;

  // Build the final theme
  const theme = useMemo(() => {
    const baseTheme = resolvedMode === 'dark' ? darkTheme : defaultTheme;
    
    if (!themeConfig) return baseTheme;

    return {
      ...baseTheme,
      name: themeConfig.baseTheme?.name ?? baseTheme.name,
      colors: { ...baseTheme.colors, ...themeConfig.colors },
      spacing: { ...baseTheme.spacing, ...themeConfig.spacing },
      radius: { ...baseTheme.radius, ...themeConfig.radius },
      fonts: { ...baseTheme.fonts, ...themeConfig.fonts },
      shadows: { ...baseTheme.shadows, ...themeConfig.shadows },
    };
  }, [resolvedMode, themeConfig]);

  // Apply CSS variables to document
  useEffect(() => {
    const root = document.documentElement;
    
    // Set color mode class
    root.classList.remove('light', 'dark');
    root.classList.add(resolvedMode);

    // Set CSS variables
    Object.entries(theme.colors).forEach(([key, value]) => {
      root.style.setProperty(`--zalt-${camelToKebab(key)}`, value);
    });

    Object.entries(theme.spacing).forEach(([key, value]) => {
      root.style.setProperty(`--zalt-spacing-${key}`, value);
    });

    Object.entries(theme.radius).forEach(([key, value]) => {
      root.style.setProperty(`--zalt-radius-${key}`, value);
    });

    Object.entries(theme.shadows).forEach(([key, value]) => {
      root.style.setProperty(`--zalt-shadow-${key}`, value);
    });

    root.style.setProperty('--zalt-font-sans', theme.fonts.sans);
    root.style.setProperty('--zalt-font-mono', theme.fonts.mono);
  }, [theme, resolvedMode]);

  const value = useMemo<ThemeContextValue>(() => ({
    theme,
    mode,
    setMode,
    resolvedMode,
  }), [theme, mode, setMode, resolvedMode]);

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
}

// Helper to convert camelCase to kebab-case
function camelToKebab(str: string): string {
  return str.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
}
