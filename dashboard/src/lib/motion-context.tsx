'use client';

import React, { createContext, useContext, useEffect, useState, useMemo, ReactNode } from 'react';
import { reducedMotionVariants, scrollAnimations, staggerVariants, staggerItemVariants } from './motion';

/**
 * Motion Context Provider
 * 
 * Provides reduced motion support across the application.
 * Detects prefers-reduced-motion media query and provides
 * appropriate animation variants.
 */

interface MotionContextValue {
  prefersReducedMotion: boolean;
  // Animation helpers that respect reduced motion
  getScrollAnimation: (animationKey: keyof typeof scrollAnimations) => typeof scrollAnimations[keyof typeof scrollAnimations] | typeof reducedMotionVariants;
  getStaggerVariants: () => typeof staggerVariants | typeof reducedMotionStaggerVariants;
  getStaggerItemVariants: () => typeof staggerItemVariants | typeof reducedMotionItemVariants;
  // Simple fade for reduced motion
  fadeAnimation: typeof reducedMotionVariants;
}

// Reduced motion stagger variants (no stagger, just fade)
const reducedMotionStaggerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      duration: 0.3,
    },
  },
};

const reducedMotionItemVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      duration: 0.2,
    },
  },
};

const MotionContext = createContext<MotionContextValue | undefined>(undefined);

interface MotionProviderProps {
  children: ReactNode;
  /** Force reduced motion for testing */
  forceReducedMotion?: boolean;
}

export function MotionProvider({ children, forceReducedMotion }: MotionProviderProps) {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    // Check if forced
    if (forceReducedMotion !== undefined) {
      setPrefersReducedMotion(forceReducedMotion);
      return;
    }

    // Check media query
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    // Listen for changes
    const handleChange = (event: MediaQueryListEvent) => {
      setPrefersReducedMotion(event.matches);
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [forceReducedMotion]);

  const value = useMemo<MotionContextValue>(() => ({
    prefersReducedMotion,
    
    getScrollAnimation: (animationKey) => {
      if (prefersReducedMotion) {
        return reducedMotionVariants;
      }
      return scrollAnimations[animationKey];
    },
    
    getStaggerVariants: () => {
      if (prefersReducedMotion) {
        return reducedMotionStaggerVariants;
      }
      return staggerVariants;
    },
    
    getStaggerItemVariants: () => {
      if (prefersReducedMotion) {
        return reducedMotionItemVariants;
      }
      return staggerItemVariants;
    },
    
    fadeAnimation: reducedMotionVariants,
  }), [prefersReducedMotion]);

  return (
    <MotionContext.Provider value={value}>
      {children}
    </MotionContext.Provider>
  );
}

/**
 * Hook to access motion context
 * 
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { prefersReducedMotion, getScrollAnimation } = useMotion();
 *   
 *   return (
 *     <motion.div {...getScrollAnimation('fadeUp')}>
 *       Content
 *     </motion.div>
 *   );
 * }
 * ```
 */
export function useMotion(): MotionContextValue {
  const context = useContext(MotionContext);
  
  if (context === undefined) {
    // Return default values if used outside provider
    return {
      prefersReducedMotion: false,
      getScrollAnimation: (key) => scrollAnimations[key],
      getStaggerVariants: () => staggerVariants,
      getStaggerItemVariants: () => staggerItemVariants,
      fadeAnimation: reducedMotionVariants,
    };
  }
  
  return context;
}

/**
 * Hook to check if reduced motion is preferred
 * Standalone hook that doesn't require provider
 */
export function usePrefersReducedMotion(): boolean {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    const handleChange = (event: MediaQueryListEvent) => {
      setPrefersReducedMotion(event.matches);
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  return prefersReducedMotion;
}

export default MotionProvider;
