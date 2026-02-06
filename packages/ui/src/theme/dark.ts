import type { Theme } from './types';

/**
 * Dark theme for @zalt/ui
 * 
 * Modern dark mode with Zalt.io brand colors
 */
export const darkTheme: Theme = {
  name: 'zalt-dark',
  mode: 'dark',
  colors: {
    // Primary - Zalt.io brand blue (slightly lighter for dark mode)
    primary: '#3b82f6',
    primaryForeground: '#ffffff',
    primaryHover: '#2563eb',
    
    // Secondary
    secondary: '#1e293b',
    secondaryForeground: '#e2e8f0',
    secondaryHover: '#334155',
    
    // Background
    background: '#0f172a',
    foreground: '#f8fafc',
    
    // Card
    card: '#1e293b',
    cardForeground: '#f8fafc',
    
    // Muted
    muted: '#1e293b',
    mutedForeground: '#94a3b8',
    
    // Border
    border: '#334155',
    borderHover: '#475569',
    
    // Input
    input: '#1e293b',
    inputForeground: '#f8fafc',
    inputPlaceholder: '#64748b',
    inputBorder: '#334155',
    inputFocus: '#3b82f6',
    
    // Status
    success: '#22c55e',
    successForeground: '#ffffff',
    warning: '#f59e0b',
    warningForeground: '#ffffff',
    error: '#ef4444',
    errorForeground: '#ffffff',
    info: '#3b82f6',
    infoForeground: '#ffffff',
    
    // Ring
    ring: '#3b82f6',
  },
  spacing: {
    xs: '0.25rem',
    sm: '0.5rem',
    md: '1rem',
    lg: '1.5rem',
    xl: '2rem',
    '2xl': '3rem',
  },
  radius: {
    none: '0',
    sm: '0.25rem',
    md: '0.375rem',
    lg: '0.5rem',
    xl: '0.75rem',
    full: '9999px',
  },
  fonts: {
    sans: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    mono: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
  },
  shadows: {
    sm: '0 1px 2px 0 rgb(0 0 0 / 0.3)',
    md: '0 4px 6px -1px rgb(0 0 0 / 0.4), 0 2px 4px -2px rgb(0 0 0 / 0.3)',
    lg: '0 10px 15px -3px rgb(0 0 0 / 0.4), 0 4px 6px -4px rgb(0 0 0 / 0.3)',
    xl: '0 20px 25px -5px rgb(0 0 0 / 0.4), 0 8px 10px -6px rgb(0 0 0 / 0.3)',
  },
};
