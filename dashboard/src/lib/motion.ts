/**
 * Framer Motion Animation Presets
 * 
 * Cinematic, Apple-inspired animations for Clerk-style redesign
 * Steve Jobs presentation style with smooth, dramatic reveals
 */

import { Variants } from 'framer-motion';

// ============================================
// SPRING PHYSICS PRESETS
// ============================================

export const springs = {
  // Bouncy spring for playful interactions
  bouncy: {
    type: 'spring' as const,
    stiffness: 500,
    damping: 25,
    mass: 1,
  },
  // Smooth spring for elegant transitions
  smooth: {
    type: 'spring' as const,
    stiffness: 200,
    damping: 30,
    mass: 1,
  },
  // Snappy spring for quick feedback
  snappy: {
    type: 'spring' as const,
    stiffness: 700,
    damping: 35,
    mass: 0.5,
  },
  // Gentle spring for subtle movements
  gentle: {
    type: 'spring' as const,
    stiffness: 120,
    damping: 20,
    mass: 1,
  },
};

// ============================================
// EASING CURVES
// ============================================

export const easings = {
  // Apple-style smooth ease
  apple: [0.25, 0.46, 0.45, 0.94] as const,
  // Dramatic entrance
  dramatic: [0.16, 1, 0.3, 1] as const,
  // Smooth out
  smoothOut: [0.22, 1, 0.36, 1] as const,
  // Elastic feel
  elastic: [0.68, -0.55, 0.265, 1.55] as const,
  // Standard ease in out
  easeInOut: [0.4, 0, 0.2, 1] as const,
};

// ============================================
// CINEMATIC ENTRANCE ANIMATIONS
// ============================================

export const cinematicAnimations = {
  // Hero lock 3D transformation
  lockReveal: {
    initial: {
      opacity: 0,
      scale: 0.3,
      rotateY: -180,
    },
    animate: {
      opacity: 1,
      scale: 1,
      rotateY: 0,
    },
    transition: {
      duration: 1.2,
      ease: easings.dramatic,
      delay: 0.3,
    },
  },

  // Shield morphing animation
  shieldMorph: {
    initial: { pathLength: 0, opacity: 0 },
    animate: { pathLength: 1, opacity: 1 },
    transition: { duration: 2, ease: 'easeInOut' },
  },

  // Particle explosion on success
  particleExplosion: {
    initial: { scale: 0, opacity: 1 },
    animate: {
      scale: [0, 1.5, 2],
      opacity: [1, 0.8, 0],
    },
    transition: { duration: 0.8, ease: 'easeOut' },
  },

  // Unlock sequence
  unlockSequence: {
    shackle: {
      initial: { y: 0 },
      animate: { y: -20 },
      transition: { duration: 0.5, ease: easings.smoothOut },
    },
    glow: {
      animate: {
        boxShadow: [
          '0 0 0 rgba(108, 71, 255, 0)',
          '0 0 60px rgba(108, 71, 255, 0.6)',
          '0 0 30px rgba(108, 71, 255, 0.3)',
        ],
      },
      transition: { duration: 1, ease: 'easeInOut' },
    },
  },
};

// ============================================
// STEVE JOBS PRESENTATION STYLE
// ============================================

export const steveJobsAnimations = {
  // Dramatic fade with scale (like iPhone reveals)
  dramaticReveal: {
    initial: { opacity: 0, scale: 0.8, y: 100 },
    animate: { opacity: 1, scale: 1, y: 0 },
    transition: {
      duration: 1.5,
      ease: easings.apple,
    },
  },

  // Text character-by-character reveal
  textReveal: {
    initial: { opacity: 0, y: 50 },
    animate: { opacity: 1, y: 0 },
    transition: {
      duration: 0.8,
      ease: easings.apple,
    },
  },

  // Container for staggered children
  staggerContainer: {
    initial: { opacity: 0 },
    animate: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.2,
      },
    },
  },

  // Child item for stagger
  staggerItem: {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.5, ease: easings.smoothOut },
  },
};

// ============================================
// SECURITY THEATER ANIMATIONS
// ============================================

export const securityAnimations = {
  // Scanning line effect
  scanLine: {
    initial: { y: '-100%', opacity: 0 },
    animate: {
      y: ['0%', '100%', '0%'],
      opacity: [0, 1, 0],
    },
    transition: {
      duration: 2,
      repeat: Infinity,
      ease: 'linear',
    },
  },

  // Encryption pulse
  encryptionPulse: {
    animate: {
      boxShadow: [
        '0 0 0 0 rgba(108, 71, 255, 0.4)',
        '0 0 0 20px rgba(108, 71, 255, 0)',
        '0 0 0 0 rgba(108, 71, 255, 0)',
      ],
    },
    transition: { duration: 2, repeat: Infinity },
  },

  // Threat blocked animation
  threatBlocked: {
    initial: { scale: 1, opacity: 1 },
    animate: {
      scale: [1, 1.2, 0],
      opacity: [1, 1, 0],
      rotate: [0, 0, 45],
    },
    transition: { duration: 0.5 },
  },

  // Data flow animation
  dataFlow: {
    initial: { pathLength: 0, opacity: 0 },
    animate: { pathLength: 1, opacity: 1 },
    transition: {
      duration: 1.5,
      ease: 'easeInOut',
      repeat: Infinity,
      repeatType: 'loop' as const,
    },
  },

  // Biometric scan
  biometricScan: {
    initial: { scaleY: 0, opacity: 0 },
    animate: {
      scaleY: [0, 1, 1, 0],
      opacity: [0, 1, 1, 0],
      y: [0, 0, 100, 100],
    },
    transition: {
      duration: 2,
      repeat: Infinity,
      ease: 'linear',
    },
  },
};

// ============================================
// MICRO-INTERACTIONS
// ============================================

export const microInteractions = {
  // Button magnetic hover
  magneticHover: {
    whileHover: {
      scale: 1.05,
      boxShadow: '0 20px 40px -10px rgba(108, 71, 255, 0.4)',
    },
    whileTap: { scale: 0.95 },
    transition: springs.snappy,
  },

  // Card 3D tilt on hover
  card3DTilt: {
    whileHover: {
      rotateX: 5,
      rotateY: 5,
      scale: 1.02,
      boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
    },
    transition: springs.smooth,
  },

  // Glow pulse on focus
  glowPulse: {
    animate: {
      boxShadow: [
        '0 0 20px rgba(108, 71, 255, 0.2)',
        '0 0 40px rgba(108, 71, 255, 0.4)',
        '0 0 20px rgba(108, 71, 255, 0.2)',
      ],
    },
    transition: { duration: 2, repeat: Infinity },
  },

  // Subtle lift on hover
  lift: {
    whileHover: {
      y: -4,
      boxShadow: '0 20px 40px -10px rgba(0, 0, 0, 0.15)',
    },
    transition: springs.gentle,
  },

  // Scale bounce
  scaleBounce: {
    whileHover: { scale: 1.05 },
    whileTap: { scale: 0.95 },
    transition: springs.bouncy,
  },

  // Icon spin
  iconSpin: {
    whileHover: { rotate: 360 },
    transition: { duration: 0.5, ease: 'easeInOut' },
  },

  // Gradient shift
  gradientShift: {
    animate: {
      backgroundPosition: ['0% 50%', '100% 50%', '0% 50%'],
    },
    transition: { duration: 5, repeat: Infinity, ease: 'linear' },
  },
};

// ============================================
// SCROLL-TRIGGERED ANIMATIONS
// ============================================

export const scrollAnimations = {
  // Reveal on scroll with spring
  scrollReveal: {
    initial: { opacity: 0, y: 80 },
    whileInView: { opacity: 1, y: 0 },
    viewport: { once: true, margin: '-100px' },
    transition: springs.smooth,
  },

  // Fade up on scroll
  fadeUp: {
    initial: { opacity: 0, y: 40 },
    whileInView: { opacity: 1, y: 0 },
    viewport: { once: true, margin: '-50px' },
    transition: { duration: 0.6, ease: easings.smoothOut },
  },

  // Fade in on scroll
  fadeIn: {
    initial: { opacity: 0 },
    whileInView: { opacity: 1 },
    viewport: { once: true },
    transition: { duration: 0.8 },
  },

  // Scale up on scroll
  scaleUp: {
    initial: { opacity: 0, scale: 0.9 },
    whileInView: { opacity: 1, scale: 1 },
    viewport: { once: true, margin: '-50px' },
    transition: { duration: 0.5, ease: easings.smoothOut },
  },

  // Slide from left
  slideFromLeft: {
    initial: { opacity: 0, x: -60 },
    whileInView: { opacity: 1, x: 0 },
    viewport: { once: true },
    transition: { duration: 0.6, ease: easings.smoothOut },
  },

  // Slide from right
  slideFromRight: {
    initial: { opacity: 0, x: 60 },
    whileInView: { opacity: 1, x: 0 },
    viewport: { once: true },
    transition: { duration: 0.6, ease: easings.smoothOut },
  },
};

// ============================================
// STAGGER VARIANTS
// ============================================

export const staggerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.1,
    },
  },
};

export const staggerItemVariants: Variants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.5,
      ease: easings.smoothOut,
    },
  },
};

export const staggerFastVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
      delayChildren: 0.05,
    },
  },
};

// ============================================
// COUNTER ANIMATION
// ============================================

export const counterAnimation = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  transition: { duration: 0.5 },
};

// Helper function for count-up animation
export const createCounterVariants = (
  target: number,
  duration: number = 2
): { from: number; to: number; duration: number } => ({
  from: 0,
  to: target,
  duration,
});

// ============================================
// FLOATING ANIMATION
// ============================================

export const floatingAnimation = {
  animate: {
    y: [-5, 5, -5],
  },
  transition: {
    duration: 3,
    repeat: Infinity,
    ease: 'easeInOut',
  },
};

// ============================================
// TYPING ANIMATION HELPER
// ============================================

export const createTypingVariants = (text: string, speed: number = 0.05): Variants => ({
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: speed,
    },
  },
});

export const letterVariants: Variants = {
  hidden: { opacity: 0, y: 10 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.1,
    },
  },
};

// ============================================
// REDUCED MOTION SUPPORT
// ============================================

export const reducedMotionVariants = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  transition: { duration: 0.3 },
};

// Hook to check for reduced motion preference
export const prefersReducedMotion = (): boolean => {
  if (typeof window === 'undefined') return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
};

// Get animation based on motion preference
export const getMotionProps = <T extends object>(
  fullMotion: T,
  reducedMotion: T = reducedMotionVariants as T
): T => {
  if (prefersReducedMotion()) {
    return reducedMotion;
  }
  return fullMotion;
};

// ============================================
// EXPORT ALL
// ============================================

export default {
  springs,
  easings,
  cinematicAnimations,
  steveJobsAnimations,
  securityAnimations,
  microInteractions,
  scrollAnimations,
  staggerVariants,
  staggerItemVariants,
  staggerFastVariants,
  counterAnimation,
  floatingAnimation,
  letterVariants,
  reducedMotionVariants,
  prefersReducedMotion,
  getMotionProps,
};
