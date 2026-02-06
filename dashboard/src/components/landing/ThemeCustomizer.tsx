'use client';

import React from 'react';
import { useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';

export interface ThemeConfig {
  primaryColor: string;
  accentColor: string;
  borderRadius: 'sm' | 'md' | 'lg' | 'xl';
  darkMode: boolean;
}

export interface ThemeCustomizerProps {
  /** Current theme configuration */
  theme: ThemeConfig;
  /** Callback when theme changes */
  onChange: (updates: Partial<ThemeConfig>) => void;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

const presetColors = [
  { name: 'Zalt Purple', primary: '#6C47FF', accent: '#00D4FF' },
  { name: 'Ocean Blue', primary: '#0066FF', accent: '#00CCFF' },
  { name: 'Forest Green', primary: '#059669', accent: '#34D399' },
  { name: 'Sunset Orange', primary: '#EA580C', accent: '#FBBF24' },
  { name: 'Rose Pink', primary: '#DB2777', accent: '#F472B6' },
];

const radiusOptions: { value: ThemeConfig['borderRadius']; label: string }[] = [
  { value: 'sm', label: 'Small' },
  { value: 'md', label: 'Medium' },
  { value: 'lg', label: 'Large' },
  { value: 'xl', label: 'Extra Large' },
];

/**
 * Theme Customizer Component
 * Allows users to customize the theme of preview components
 * Includes color picker, border radius selector, and dark mode toggle
 */
export function ThemeCustomizer({
  theme,
  onChange,
  className,
  'data-testid': testId = 'theme-customizer',
}: ThemeCustomizerProps) {
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  return (
    <div 
      className={cn(
        'p-6 rounded-xl border',
        theme.darkMode ? 'bg-neutral-800 border-neutral-700' : 'bg-white border-neutral-200',
        className
      )}
      data-testid={testId}
      data-reduced-motion={reducedMotion ? 'true' : 'false'}
    >
      <h3 className={cn('text-lg font-semibold mb-6', theme.darkMode ? 'text-white' : 'text-neutral-900')}>
        Customize Theme
      </h3>

      {/* Color Presets */}
      <div className="mb-6">
        <label className={cn('block text-sm font-medium mb-3', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
          Color Preset
        </label>
        <div className="grid grid-cols-5 gap-2">
          {presetColors.map((preset) => (
            <button
              key={preset.name}
              onClick={() => onChange({ primaryColor: preset.primary, accentColor: preset.accent })}
              className={cn(
                'w-full aspect-square rounded-lg transition-all',
                theme.primaryColor === preset.primary ? 'ring-2 ring-offset-2 ring-neutral-400' : ''
              )}
              style={{ backgroundColor: preset.primary }}
              title={preset.name}
              aria-label={`Select ${preset.name} color preset`}
              data-testid={`color-preset-${preset.name.toLowerCase().replace(' ', '-')}`}
            />
          ))}
        </div>
      </div>

      {/* Custom Primary Color */}
      <div className="mb-6">
        <label className={cn('block text-sm font-medium mb-2', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
          Primary Color
        </label>
        <div className="flex items-center gap-3">
          <input
            type="color"
            value={theme.primaryColor}
            onChange={(e) => onChange({ primaryColor: e.target.value })}
            className="w-10 h-10 rounded-lg cursor-pointer border-0"
            aria-label="Select primary color"
            data-testid="color-picker-primary"
          />
          <input
            type="text"
            value={theme.primaryColor}
            onChange={(e) => onChange({ primaryColor: e.target.value })}
            className={cn(
              'flex-1 px-3 py-2 rounded-lg border text-sm font-mono',
              theme.darkMode
                ? 'bg-neutral-700 border-neutral-600 text-white'
                : 'bg-neutral-50 border-neutral-200 text-neutral-900'
            )}
            aria-label="Primary color hex value"
            data-testid="color-input-primary"
          />
        </div>
      </div>

      {/* Custom Accent Color */}
      <div className="mb-6">
        <label className={cn('block text-sm font-medium mb-2', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
          Accent Color
        </label>
        <div className="flex items-center gap-3">
          <input
            type="color"
            value={theme.accentColor}
            onChange={(e) => onChange({ accentColor: e.target.value })}
            className="w-10 h-10 rounded-lg cursor-pointer border-0"
            aria-label="Select accent color"
            data-testid="color-picker-accent"
          />
          <input
            type="text"
            value={theme.accentColor}
            onChange={(e) => onChange({ accentColor: e.target.value })}
            className={cn(
              'flex-1 px-3 py-2 rounded-lg border text-sm font-mono',
              theme.darkMode
                ? 'bg-neutral-700 border-neutral-600 text-white'
                : 'bg-neutral-50 border-neutral-200 text-neutral-900'
            )}
            aria-label="Accent color hex value"
            data-testid="color-input-accent"
          />
        </div>
      </div>

      {/* Border Radius */}
      <div className="mb-6">
        <label className={cn('block text-sm font-medium mb-3', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
          Border Radius
        </label>
        <div className="grid grid-cols-4 gap-2">
          {radiusOptions.map((option) => (
            <button
              key={option.value}
              onClick={() => onChange({ borderRadius: option.value })}
              className={cn(
                'px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                theme.borderRadius === option.value
                  ? 'bg-primary text-white'
                  : theme.darkMode
                    ? 'bg-neutral-700 text-neutral-300 hover:bg-neutral-600'
                    : 'bg-neutral-100 text-neutral-700 hover:bg-neutral-200'
              )}
              aria-pressed={theme.borderRadius === option.value}
              data-testid={`radius-${option.value}`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {/* Dark Mode Toggle */}
      <div className="flex items-center justify-between">
        <label className={cn('text-sm font-medium', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
          Dark Mode
        </label>
        <button
          onClick={() => onChange({ darkMode: !theme.darkMode })}
          className={cn(
            'relative w-12 h-6 rounded-full transition-colors',
            theme.darkMode ? 'bg-primary' : 'bg-neutral-300'
          )}
          role="switch"
          aria-checked={theme.darkMode}
          aria-label="Toggle dark mode"
          data-testid="dark-mode-toggle"
        >
          <span
            className={cn(
              'absolute top-1 w-4 h-4 rounded-full bg-white transition-transform',
              reducedMotion ? '' : 'duration-200',
              theme.darkMode ? 'left-7' : 'left-1'
            )}
          />
        </button>
      </div>
    </div>
  );
}

export default ThemeCustomizer;
