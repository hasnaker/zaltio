'use client';

import React from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { easings, springs } from '@/lib/motion';

export interface DeviceMockupsProps {
  /** Show desktop device */
  showDesktop?: boolean;
  /** Show tablet device */
  showTablet?: boolean;
  /** Show mobile device */
  showMobile?: boolean;
  /** Active device for highlighting */
  activeDevice?: 'desktop' | 'tablet' | 'mobile';
  /** Callback when device is clicked */
  onDeviceClick?: (device: 'desktop' | 'tablet' | 'mobile') => void;
  /** Additional CSS classes */
  className?: string;
  /** Test ID for testing */
  'data-testid'?: string;
}

// Mock authentication UI content
const AuthUIContent = ({ variant }: { variant: 'desktop' | 'tablet' | 'mobile' }) => {
  const isCompact = variant === 'mobile';
  
  return (
    <div className={cn(
      'bg-white dark:bg-neutral-900 rounded-lg shadow-xl p-4',
      isCompact ? 'w-full' : 'w-full max-w-sm mx-auto'
    )}>
      {/* Logo */}
      <div className="flex items-center justify-center mb-4">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-purple-600 flex items-center justify-center">
          <span className="text-white font-bold text-sm">Z</span>
        </div>
        <span className="ml-2 font-semibold text-neutral-900 dark:text-white">Zalt</span>
      </div>

      {/* Title */}
      <h3 className={cn(
        'font-semibold text-center text-neutral-900 dark:text-white mb-4',
        isCompact ? 'text-sm' : 'text-base'
      )}>
        Sign in to continue
      </h3>

      {/* Social buttons */}
      <div className="space-y-2 mb-4">
        <button className="w-full flex items-center justify-center gap-2 px-3 py-2 border border-neutral-200 dark:border-neutral-700 rounded-lg text-sm hover:bg-neutral-50 dark:hover:bg-neutral-800 transition-colors">
          <svg className="w-4 h-4" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          <span className="text-neutral-700 dark:text-neutral-300">Continue with Google</span>
        </button>
        <button className="w-full flex items-center justify-center gap-2 px-3 py-2 border border-neutral-200 dark:border-neutral-700 rounded-lg text-sm hover:bg-neutral-50 dark:hover:bg-neutral-800 transition-colors">
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
          </svg>
          <span className="text-neutral-700 dark:text-neutral-300">Continue with GitHub</span>
        </button>
      </div>

      {/* Divider */}
      <div className="relative my-4">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-neutral-200 dark:border-neutral-700" />
        </div>
        <div className="relative flex justify-center text-xs">
          <span className="px-2 bg-white dark:bg-neutral-900 text-neutral-500">or</span>
        </div>
      </div>

      {/* Email input */}
      <div className="space-y-3">
        <input
          type="email"
          placeholder="Email address"
          className="w-full px-3 py-2 border border-neutral-200 dark:border-neutral-700 rounded-lg text-sm bg-white dark:bg-neutral-800 text-neutral-900 dark:text-white placeholder-neutral-400"
          readOnly
        />
        <button className="w-full px-3 py-2 bg-gradient-to-r from-primary to-purple-600 text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity">
          Continue
        </button>
      </div>

      {/* Footer */}
      <p className="mt-4 text-center text-xs text-neutral-500">
        Don't have an account?{' '}
        <span className="text-primary hover:underline cursor-pointer">Sign up</span>
      </p>
    </div>
  );
};

// Desktop device frame
const DesktopFrame = ({ 
  isActive, 
  onClick,
  reducedMotion,
}: { 
  isActive: boolean; 
  onClick?: () => void;
  reducedMotion: boolean;
}) => {
  const content = (
    <div 
      className={cn(
        'relative cursor-pointer transition-all duration-300',
        isActive ? 'scale-105 z-20' : 'scale-100 z-10 opacity-80 hover:opacity-100'
      )}
      onClick={onClick}
    >
      {/* Monitor frame */}
      <div className="relative bg-neutral-800 rounded-xl p-2 shadow-2xl">
        {/* Screen bezel */}
        <div className="bg-neutral-900 rounded-lg overflow-hidden">
          {/* Browser chrome */}
          <div className="bg-neutral-800 px-3 py-2 flex items-center gap-2">
            <div className="flex gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
              <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
            </div>
            <div className="flex-1 bg-neutral-700 rounded px-2 py-1 text-xs text-neutral-400 text-center">
              app.zalt.io/sign-in
            </div>
          </div>
          {/* Screen content */}
          <div className="bg-gradient-to-br from-neutral-100 to-neutral-200 dark:from-neutral-800 dark:to-neutral-900 p-6 min-h-[280px] flex items-center justify-center">
            <AuthUIContent variant="desktop" />
          </div>
        </div>
      </div>
      {/* Monitor stand */}
      <div className="mx-auto w-16 h-4 bg-neutral-700 rounded-b-lg" />
      <div className="mx-auto w-24 h-2 bg-neutral-600 rounded-b-lg" />
    </div>
  );

  if (reducedMotion) {
    return content;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 40, scale: 0.9 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.8, ease: easings.smoothOut, delay: 0.2 }}
      whileHover={{ y: -5 }}
    >
      {content}
    </motion.div>
  );
};

// Tablet device frame
const TabletFrame = ({ 
  isActive, 
  onClick,
  reducedMotion,
}: { 
  isActive: boolean; 
  onClick?: () => void;
  reducedMotion: boolean;
}) => {
  const content = (
    <div 
      className={cn(
        'relative cursor-pointer transition-all duration-300',
        isActive ? 'scale-105 z-20' : 'scale-100 z-10 opacity-80 hover:opacity-100'
      )}
      onClick={onClick}
    >
      {/* Tablet frame */}
      <div className="relative bg-neutral-800 rounded-2xl p-3 shadow-2xl w-[200px]">
        {/* Camera notch */}
        <div className="absolute top-1.5 left-1/2 -translate-x-1/2 w-2 h-2 rounded-full bg-neutral-700" />
        {/* Screen */}
        <div className="bg-gradient-to-br from-neutral-100 to-neutral-200 dark:from-neutral-800 dark:to-neutral-900 rounded-xl overflow-hidden min-h-[260px] flex items-center justify-center p-3">
          <AuthUIContent variant="tablet" />
        </div>
        {/* Home button */}
        <div className="absolute bottom-1.5 left-1/2 -translate-x-1/2 w-8 h-1 rounded-full bg-neutral-700" />
      </div>
    </div>
  );

  if (reducedMotion) {
    return content;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 40, scale: 0.9 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.8, ease: easings.smoothOut, delay: 0.4 }}
      whileHover={{ y: -5 }}
    >
      {content}
    </motion.div>
  );
};

// Mobile device frame
const MobileFrame = ({ 
  isActive, 
  onClick,
  reducedMotion,
}: { 
  isActive: boolean; 
  onClick?: () => void;
  reducedMotion: boolean;
}) => {
  const content = (
    <div 
      className={cn(
        'relative cursor-pointer transition-all duration-300',
        isActive ? 'scale-105 z-20' : 'scale-100 z-10 opacity-80 hover:opacity-100'
      )}
      onClick={onClick}
    >
      {/* Phone frame */}
      <div className="relative bg-neutral-800 rounded-[2rem] p-2 shadow-2xl w-[140px]">
        {/* Dynamic island */}
        <div className="absolute top-3 left-1/2 -translate-x-1/2 w-16 h-5 rounded-full bg-neutral-900 z-10" />
        {/* Screen */}
        <div className="bg-gradient-to-br from-neutral-100 to-neutral-200 dark:from-neutral-800 dark:to-neutral-900 rounded-[1.5rem] overflow-hidden min-h-[280px] flex items-center justify-center p-2 pt-8">
          <AuthUIContent variant="mobile" />
        </div>
        {/* Home indicator */}
        <div className="absolute bottom-2 left-1/2 -translate-x-1/2 w-20 h-1 rounded-full bg-neutral-600" />
      </div>
    </div>
  );

  if (reducedMotion) {
    return content;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 40, scale: 0.9 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.8, ease: easings.smoothOut, delay: 0.6 }}
      whileHover={{ y: -5 }}
    >
      {content}
    </motion.div>
  );
};

export function DeviceMockups({
  showDesktop = true,
  showTablet = true,
  showMobile = true,
  activeDevice = 'desktop',
  onDeviceClick,
  className,
  'data-testid': testId = 'device-mockups',
}: DeviceMockupsProps) {
  const shouldReduceMotion = useReducedMotion();
  const reducedMotion = shouldReduceMotion ?? false;

  return (
    <div 
      className={cn(
        'flex items-end justify-center gap-4 md:gap-8',
        className
      )}
      data-testid={testId}
      data-reduced-motion={reducedMotion ? 'true' : 'false'}
    >
      {showDesktop && (
        <DesktopFrame 
          isActive={activeDevice === 'desktop'} 
          onClick={() => onDeviceClick?.('desktop')}
          reducedMotion={reducedMotion}
        />
      )}
      {showTablet && (
        <TabletFrame 
          isActive={activeDevice === 'tablet'} 
          onClick={() => onDeviceClick?.('tablet')}
          reducedMotion={reducedMotion}
        />
      )}
      {showMobile && (
        <MobileFrame 
          isActive={activeDevice === 'mobile'} 
          onClick={() => onDeviceClick?.('mobile')}
          reducedMotion={reducedMotion}
        />
      )}
    </div>
  );
}

export default DeviceMockups;
