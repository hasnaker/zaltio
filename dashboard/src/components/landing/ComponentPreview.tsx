'use client';

import React, { useState, useCallback } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { easings } from '@/lib/motion';
import { ThemeCustomizer, type ThemeConfig } from './ThemeCustomizer';

export type PreviewComponent = 'signin' | 'signup' | 'userbutton' | 'orgswitcher';

export type { ThemeConfig };

export interface ComponentPreviewProps {
  /** Initial active component */
  initialComponent?: PreviewComponent;
  /** Initial theme configuration */
  initialTheme?: Partial<ThemeConfig>;
  /** Show theme customizer */
  showThemeCustomizer?: boolean;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

const defaultTheme: ThemeConfig = {
  primaryColor: '#6C47FF',
  accentColor: '#00D4FF',
  borderRadius: 'lg',
  darkMode: false,
};

const componentTabs: { id: PreviewComponent; label: string; description: string }[] = [
  { id: 'signin', label: 'Sign In', description: 'Authentication form' },
  { id: 'signup', label: 'Sign Up', description: 'Registration form' },
  { id: 'userbutton', label: 'User Button', description: 'User menu dropdown' },
  { id: 'orgswitcher', label: 'Org Switcher', description: 'Organization selector' },
];

// Helper function for border radius
function getBorderRadius(radius: ThemeConfig['borderRadius']): string {
  const radiusMap = {
    sm: '0.375rem',
    md: '0.5rem',
    lg: '0.75rem',
    xl: '1rem',
  };
  return radiusMap[radius];
}

/**
 * Component Preview Section
 * Showcases Zalt authentication components with live interactive previews
 * No real API calls are made - all interactions are simulated
 */
export function ComponentPreview({
  initialComponent = 'signin',
  initialTheme,
  showThemeCustomizer = true,
  className,
  'data-testid': testId = 'component-preview',
}: ComponentPreviewProps) {
  const [activeComponent, setActiveComponent] = useState<PreviewComponent>(initialComponent);
  const [theme, setTheme] = useState<ThemeConfig>({ ...defaultTheme, ...initialTheme });
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  const handleThemeChange = useCallback((updates: Partial<ThemeConfig>) => {
    setTheme(prev => ({ ...prev, ...updates }));
  }, []);

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: reducedMotion ? 0 : 0.1,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: reducedMotion ? 0 : 20 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { duration: reducedMotion ? 0.1 : 0.5, ease: easings.smoothOut },
    },
  };

  return (
    <section
      className={cn(
        'py-20 md:py-32 bg-neutral-50 dark:bg-neutral-900/50',
        className
      )}
      data-testid={testId}
      data-reduced-motion={reducedMotion ? 'true' : 'false'}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-100px' }}
        >
          {/* Section Header */}
          <motion.div variants={itemVariants} className="text-center mb-12">
            <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary/10 text-primary text-sm font-medium mb-4">
              Pre-built Components
            </span>
            <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-neutral-900 dark:text-white mb-4">
              Beautiful, customizable UI
            </h2>
            <p className="text-lg text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto">
              Drop-in authentication components that match your brand. 
              Fully customizable, accessible, and secure by default.
            </p>
          </motion.div>

          {/* Component Tabs */}
          <motion.div variants={itemVariants} className="flex justify-center mb-8">
            <div className="inline-flex items-center gap-1 p-1.5 bg-white dark:bg-neutral-800 rounded-xl shadow-sm border border-neutral-200 dark:border-neutral-700">
              {componentTabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveComponent(tab.id)}
                  className={cn(
                    'px-4 py-2.5 rounded-lg text-sm font-medium transition-all',
                    activeComponent === tab.id
                      ? 'bg-primary text-white shadow-sm'
                      : 'text-neutral-600 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white hover:bg-neutral-100 dark:hover:bg-neutral-700'
                  )}
                  aria-label={`View ${tab.label} component`}
                  aria-pressed={activeComponent === tab.id}
                  data-testid={`tab-${tab.id}`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </motion.div>

          {/* Preview Container */}
          <motion.div variants={itemVariants} className="grid lg:grid-cols-3 gap-8">
            {/* Preview Panel */}
            <div className="lg:col-span-2">
              <div 
                className={cn(
                  'relative rounded-2xl border overflow-hidden',
                  theme.darkMode 
                    ? 'bg-neutral-900 border-neutral-700' 
                    : 'bg-white border-neutral-200'
                )}
                style={{
                  '--preview-primary': theme.primaryColor,
                  '--preview-accent': theme.accentColor,
                  '--preview-radius': getBorderRadius(theme.borderRadius),
                } as React.CSSProperties}
              >
                {/* Browser chrome */}
                <div className={cn(
                  'flex items-center gap-2 px-4 py-3 border-b',
                  theme.darkMode ? 'border-neutral-700 bg-neutral-800' : 'border-neutral-200 bg-neutral-50'
                )}>
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-500" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                    <div className="w-3 h-3 rounded-full bg-green-500" />
                  </div>
                  <div className={cn(
                    'flex-1 mx-4 px-3 py-1 rounded-md text-xs',
                    theme.darkMode ? 'bg-neutral-700 text-neutral-400' : 'bg-neutral-200 text-neutral-500'
                  )}>
                    your-app.com/auth
                  </div>
                </div>

                {/* Component Preview Area */}
                <div className="p-8 md:p-12 min-h-[400px] flex items-center justify-center">
                  <PreviewContent 
                    component={activeComponent} 
                    theme={theme}
                    reducedMotion={reducedMotion}
                  />
                </div>
              </div>
            </div>

            {/* Theme Customizer */}
            {showThemeCustomizer && (
              <div className="lg:col-span-1">
                <ThemeCustomizer 
                  theme={theme} 
                  onChange={handleThemeChange}
                />
              </div>
            )}
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}

// Preview content renderer
function PreviewContent({
  component,
  theme,
  reducedMotion,
}: {
  component: PreviewComponent;
  theme: ThemeConfig;
  reducedMotion: boolean;
}) {
  const contentVariants = {
    hidden: { opacity: 0, scale: reducedMotion ? 1 : 0.95 },
    visible: { 
      opacity: 1, 
      scale: 1,
      transition: { duration: reducedMotion ? 0.1 : 0.3 },
    },
    exit: { 
      opacity: 0, 
      scale: reducedMotion ? 1 : 0.95,
      transition: { duration: reducedMotion ? 0.1 : 0.2 },
    },
  };

  return (
    <motion.div
      key={component}
      variants={contentVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
      className="w-full max-w-sm"
      data-testid={`preview-${component}`}
    >
      {component === 'signin' && <MockSignIn theme={theme} />}
      {component === 'signup' && <MockSignUp theme={theme} />}
      {component === 'userbutton' && <MockUserButton theme={theme} />}
      {component === 'orgswitcher' && <MockOrgSwitcher theme={theme} />}
    </motion.div>
  );
}


// Mock SignIn Component (no real API calls)
function MockSignIn({ theme }: { theme: ThemeConfig }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const inputClasses = cn(
    'w-full px-4 py-3 rounded-lg border text-sm transition-colors',
    theme.darkMode
      ? 'bg-neutral-800 border-neutral-600 text-white placeholder-neutral-400 focus:border-[var(--preview-primary)]'
      : 'bg-white border-neutral-300 text-neutral-900 placeholder-neutral-500 focus:border-[var(--preview-primary)]'
  );

  return (
    <div className={cn(
      'p-6 rounded-xl border shadow-lg',
      theme.darkMode ? 'bg-neutral-800 border-neutral-700' : 'bg-white border-neutral-200'
    )} style={{ borderRadius: 'var(--preview-radius)' }}>
      <div className="text-center mb-6">
        <div 
          className="w-10 h-10 rounded-lg mx-auto mb-3 flex items-center justify-center text-white font-bold"
          style={{ backgroundColor: theme.primaryColor }}
        >
          Z
        </div>
        <h3 className={cn('text-lg font-semibold', theme.darkMode ? 'text-white' : 'text-neutral-900')}>
          Sign in to Zalt
        </h3>
        <p className={cn('text-sm mt-1', theme.darkMode ? 'text-neutral-400' : 'text-neutral-500')}>
          Welcome back! Please sign in to continue
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label className={cn('block text-sm font-medium mb-1.5', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
            Email address
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
            className={inputClasses}
            style={{ borderRadius: 'var(--preview-radius)' }}
          />
        </div>

        <div>
          <label className={cn('block text-sm font-medium mb-1.5', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
            Password
          </label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              className={inputClasses}
              style={{ borderRadius: 'var(--preview-radius)' }}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className={cn(
                'absolute right-3 top-1/2 -translate-y-1/2 text-sm',
                theme.darkMode ? 'text-neutral-400' : 'text-neutral-500'
              )}
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>

        <button
          type="button"
          className="w-full py-3 rounded-lg text-white font-medium transition-opacity hover:opacity-90"
          style={{ 
            backgroundColor: theme.primaryColor,
            borderRadius: 'var(--preview-radius)',
          }}
          onClick={() => {/* No real API call - preview only */}}
        >
          Continue
        </button>

        <div className="relative my-4">
          <div className={cn('absolute inset-0 flex items-center', theme.darkMode ? 'text-neutral-600' : 'text-neutral-300')}>
            <div className="w-full border-t" style={{ borderColor: 'currentColor' }} />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className={cn('px-2', theme.darkMode ? 'bg-neutral-800 text-neutral-400' : 'bg-white text-neutral-500')}>
              or continue with
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <SocialButton theme={theme} provider="Google" />
          <SocialButton theme={theme} provider="GitHub" />
        </div>
      </div>

      <p className={cn('text-center text-sm mt-6', theme.darkMode ? 'text-neutral-400' : 'text-neutral-500')}>
        Don&apos;t have an account?{' '}
        <span style={{ color: theme.primaryColor }} className="font-medium cursor-pointer">
          Sign up
        </span>
      </p>
    </div>
  );
}

// Mock SignUp Component
function MockSignUp({ theme }: { theme: ThemeConfig }) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const inputClasses = cn(
    'w-full px-4 py-3 rounded-lg border text-sm transition-colors',
    theme.darkMode
      ? 'bg-neutral-800 border-neutral-600 text-white placeholder-neutral-400 focus:border-[var(--preview-primary)]'
      : 'bg-white border-neutral-300 text-neutral-900 placeholder-neutral-500 focus:border-[var(--preview-primary)]'
  );

  return (
    <div className={cn(
      'p-6 rounded-xl border shadow-lg',
      theme.darkMode ? 'bg-neutral-800 border-neutral-700' : 'bg-white border-neutral-200'
    )} style={{ borderRadius: 'var(--preview-radius)' }}>
      <div className="text-center mb-6">
        <div 
          className="w-10 h-10 rounded-lg mx-auto mb-3 flex items-center justify-center text-white font-bold"
          style={{ backgroundColor: theme.primaryColor }}
        >
          Z
        </div>
        <h3 className={cn('text-lg font-semibold', theme.darkMode ? 'text-white' : 'text-neutral-900')}>
          Create your account
        </h3>
        <p className={cn('text-sm mt-1', theme.darkMode ? 'text-neutral-400' : 'text-neutral-500')}>
          Get started with Zalt in seconds
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label className={cn('block text-sm font-medium mb-1.5', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
            Full name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Enter your name"
            className={inputClasses}
            style={{ borderRadius: 'var(--preview-radius)' }}
          />
        </div>

        <div>
          <label className={cn('block text-sm font-medium mb-1.5', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
            Email address
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
            className={inputClasses}
            style={{ borderRadius: 'var(--preview-radius)' }}
          />
        </div>

        <div>
          <label className={cn('block text-sm font-medium mb-1.5', theme.darkMode ? 'text-neutral-300' : 'text-neutral-700')}>
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Create a password"
            className={inputClasses}
            style={{ borderRadius: 'var(--preview-radius)' }}
          />
          <p className={cn('text-xs mt-1', theme.darkMode ? 'text-neutral-500' : 'text-neutral-400')}>
            Must be at least 8 characters
          </p>
        </div>

        <button
          type="button"
          className="w-full py-3 rounded-lg text-white font-medium transition-opacity hover:opacity-90"
          style={{ 
            backgroundColor: theme.primaryColor,
            borderRadius: 'var(--preview-radius)',
          }}
          onClick={() => {/* No real API call - preview only */}}
        >
          Create account
        </button>

        <div className="grid grid-cols-2 gap-3 mt-4">
          <SocialButton theme={theme} provider="Google" />
          <SocialButton theme={theme} provider="GitHub" />
        </div>
      </div>

      <p className={cn('text-center text-sm mt-6', theme.darkMode ? 'text-neutral-400' : 'text-neutral-500')}>
        Already have an account?{' '}
        <span style={{ color: theme.primaryColor }} className="font-medium cursor-pointer">
          Sign in
        </span>
      </p>
    </div>
  );
}

// Mock UserButton Component
function MockUserButton({ theme }: { theme: ThemeConfig }) {
  const [isOpen, setIsOpen] = useState(true);

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2"
      >
        <div 
          className="w-10 h-10 rounded-full flex items-center justify-center text-white font-medium"
          style={{ backgroundColor: theme.primaryColor }}
        >
          JD
        </div>
      </button>

      {isOpen && (
        <div 
          className={cn(
            'absolute top-12 right-0 w-64 rounded-xl border shadow-xl overflow-hidden',
            theme.darkMode ? 'bg-neutral-800 border-neutral-700' : 'bg-white border-neutral-200'
          )}
          style={{ borderRadius: 'var(--preview-radius)' }}
        >
          <div className={cn(
            'p-4 border-b',
            theme.darkMode ? 'border-neutral-700' : 'border-neutral-200'
          )}>
            <div className="flex items-center gap-3">
              <div 
                className="w-10 h-10 rounded-full flex items-center justify-center text-white font-medium"
                style={{ backgroundColor: theme.primaryColor }}
              >
                JD
              </div>
              <div>
                <p className={cn('font-medium', theme.darkMode ? 'text-white' : 'text-neutral-900')}>
                  John Doe
                </p>
                <p className={cn('text-sm', theme.darkMode ? 'text-neutral-400' : 'text-neutral-500')}>
                  john@example.com
                </p>
              </div>
            </div>
          </div>

          <div className="py-2">
            <MenuItem theme={theme} icon="👤" label="Manage account" />
            <MenuItem theme={theme} icon="🔒" label="Security" />
            <MenuItem theme={theme} icon="🏢" label="Organizations" />
          </div>

          <div className={cn('border-t py-2', theme.darkMode ? 'border-neutral-700' : 'border-neutral-200')}>
            <MenuItem theme={theme} icon="🚪" label="Sign out" danger />
          </div>
        </div>
      )}
    </div>
  );
}


// Mock OrgSwitcher Component
function MockOrgSwitcher({ theme }: { theme: ThemeConfig }) {
  const [isOpen, setIsOpen] = useState(true);
  const [selectedOrg, setSelectedOrg] = useState('Acme Corp');

  const orgs = [
    { name: 'Acme Corp', role: 'Admin', members: 24 },
    { name: 'Startup Inc', role: 'Member', members: 8 },
    { name: 'Personal', role: 'Owner', members: 1 },
  ];

  return (
    <div className="relative w-full max-w-xs">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          'w-full flex items-center justify-between gap-3 px-4 py-3 rounded-lg border transition-colors',
          theme.darkMode 
            ? 'bg-neutral-800 border-neutral-700 hover:border-neutral-600' 
            : 'bg-white border-neutral-200 hover:border-neutral-300'
        )}
        style={{ borderRadius: 'var(--preview-radius)' }}
      >
        <div className="flex items-center gap-3">
          <div 
            className="w-8 h-8 rounded-lg flex items-center justify-center text-white text-sm font-medium"
            style={{ backgroundColor: theme.primaryColor }}
          >
            {selectedOrg.charAt(0)}
          </div>
          <span className={cn('font-medium', theme.darkMode ? 'text-white' : 'text-neutral-900')}>
            {selectedOrg}
          </span>
        </div>
        <svg className={cn('w-4 h-4', theme.darkMode ? 'text-neutral-400' : 'text-neutral-500')} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isOpen && (
        <div 
          className={cn(
            'absolute top-14 left-0 right-0 rounded-xl border shadow-xl overflow-hidden',
            theme.darkMode ? 'bg-neutral-800 border-neutral-700' : 'bg-white border-neutral-200'
          )}
          style={{ borderRadius: 'var(--preview-radius)' }}
        >
          <div className={cn(
            'px-3 py-2 text-xs font-medium uppercase tracking-wider',
            theme.darkMode ? 'text-neutral-500' : 'text-neutral-400'
          )}>
            Organizations
          </div>
          
          {orgs.map((org) => (
            <button
              key={org.name}
              onClick={() => setSelectedOrg(org.name)}
              className={cn(
                'w-full flex items-center gap-3 px-3 py-2.5 transition-colors',
                selectedOrg === org.name
                  ? theme.darkMode ? 'bg-neutral-700' : 'bg-neutral-100'
                  : theme.darkMode ? 'hover:bg-neutral-700/50' : 'hover:bg-neutral-50'
              )}
            >
              <div 
                className="w-8 h-8 rounded-lg flex items-center justify-center text-white text-sm font-medium"
                style={{ backgroundColor: selectedOrg === org.name ? theme.primaryColor : theme.darkMode ? '#525252' : '#a3a3a3' }}
              >
                {org.name.charAt(0)}
              </div>
              <div className="flex-1 text-left">
                <p className={cn('font-medium text-sm', theme.darkMode ? 'text-white' : 'text-neutral-900')}>
                  {org.name}
                </p>
                <p className={cn('text-xs', theme.darkMode ? 'text-neutral-400' : 'text-neutral-500')}>
                  {org.role} · {org.members} members
                </p>
              </div>
              {selectedOrg === org.name && (
                <svg className="w-4 h-4" style={{ color: theme.primaryColor }} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              )}
            </button>
          ))}

          <div className={cn('border-t p-2', theme.darkMode ? 'border-neutral-700' : 'border-neutral-200')}>
            <button
              className={cn(
                'w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors',
                theme.darkMode ? 'hover:bg-neutral-700 text-neutral-300' : 'hover:bg-neutral-100 text-neutral-600'
              )}
              style={{ borderRadius: 'var(--preview-radius)' }}
            >
              <span style={{ color: theme.primaryColor }}>+</span>
              Create organization
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// Helper Components
function SocialButton({ theme, provider }: { theme: ThemeConfig; provider: string }) {
  return (
    <button
      type="button"
      className={cn(
        'flex items-center justify-center gap-2 py-2.5 rounded-lg border text-sm font-medium transition-colors',
        theme.darkMode
          ? 'bg-neutral-700 border-neutral-600 text-white hover:bg-neutral-600'
          : 'bg-white border-neutral-300 text-neutral-700 hover:bg-neutral-50'
      )}
      style={{ borderRadius: 'var(--preview-radius)' }}
      onClick={() => {/* No real API call - preview only */}}
    >
      {provider === 'Google' && (
        <svg className="w-4 h-4" viewBox="0 0 24 24">
          <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
          <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
          <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
          <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
        </svg>
      )}
      {provider === 'GitHub' && (
        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
        </svg>
      )}
      {provider}
    </button>
  );
}

function MenuItem({ theme, icon, label, danger }: { theme: ThemeConfig; icon: string; label: string; danger?: boolean }) {
  return (
    <button
      className={cn(
        'w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors',
        danger
          ? 'text-red-500 hover:bg-red-500/10'
          : theme.darkMode 
            ? 'text-neutral-300 hover:bg-neutral-700' 
            : 'text-neutral-700 hover:bg-neutral-100'
      )}
    >
      <span>{icon}</span>
      {label}
    </button>
  );
}

export default ComponentPreview;
