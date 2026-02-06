import type { Theme } from './types';

/**
 * Default light theme for @zalt/ui
 * 
 * Clean, professional look with Zalt.io brand colors
 */
export const defaultTheme: Theme = {
  name: 'zalt-light',
  mode: 'light',
  colors: {
    // Primary - Zalt.io brand blue
    primary: '#2563eb',
    primaryForeground: '#ffffff',
    primaryHover: '#1d4ed8',
    
    // Secondary
    secondary: '#f1f5f9',
    secondaryForeground: '#475569',
    secondaryHover: '#e2e8f0',
    
    // Background
    background: '#ffffff',
    foreground: '#0f172a',
    
    // Card
    card: '#ffffff',
    cardForeground: '#0f172a',
    
    // Muted
    muted: '#f1f5f9',
    mutedForeground: '#64748b',
    
    // Border
    border: '#e2e8f0',
    borderHover: '#cbd5e1',
    
    // Input
    input: '#ffffff',
    inputForeground: '#0f172a',
    inputPlaceholder: '#94a3b8',
    inputBorder: '#e2e8f0',
    inputFocus: '#2563eb',
    
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
    ring: '#2563eb',
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
    sm: '0 1px 2px 0 rgb(0 0 0 / 0.05)',
    md: '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
    lg: '0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)',
    xl: '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)',
  },
};
