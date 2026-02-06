/**
 * Clerk-Style Design System Theme
 * 
 * Modern, Apple-inspired design tokens matching Clerk.com aesthetic
 * Primary: Purple (#6C47FF)
 * Accent: Blue (#00D4FF)
 * Clean whites, soft shadows, gradient accents
 */

export interface ClerkTheme {
  colors: {
    primary: Record<string, string>;
    accent: Record<string, string>;
    neutral: Record<string, string>;
    success: string;
    warning: string;
    error: string;
    info: string;
  };
  gradients: Record<string, string>;
  typography: {
    fontFamily: Record<string, string>;
    fontSize: Record<string, string>;
    fontWeight: Record<string, number>;
    lineHeight: Record<string, number>;
  };
  spacing: Record<string, string>;
  borderRadius: Record<string, string>;
  shadows: Record<string, string>;
}

export const clerkTheme: ClerkTheme = {
  colors: {
    // Primary purple palette
    primary: {
      50: '#F5F3FF',
      100: '#EDE9FE',
      200: '#DDD6FE',
      300: '#C4B5FD',
      400: '#A78BFA',
      500: '#8B5CF6',
      600: '#7C3AED',
      700: '#6D28D9',
      800: '#5B21B6',
      900: '#4C1D95',
      DEFAULT: '#6C47FF',
    },
    // Accent blue palette
    accent: {
      300: '#7DD3FC',
      400: '#38BDF8',
      500: '#0EA5E9',
      600: '#0284C7',
      700: '#0369A1',
      DEFAULT: '#00D4FF',
    },
    // Neutral grays
    neutral: {
      50: '#FAFAFA',
      100: '#F4F4F5',
      200: '#E4E4E7',
      300: '#D4D4D8',
      400: '#A1A1AA',
      500: '#71717A',
      600: '#52525B',
      700: '#3F3F46',
      800: '#27272A',
      900: '#18181B',
      950: '#0F0F10',
    },
    // Semantic colors
    success: '#22C55E',
    warning: '#F59E0B',
    error: '#EF4444',
    info: '#3B82F6',
  },

  gradients: {
    // Primary gradient (purple to blue)
    primary: 'linear-gradient(135deg, #6C47FF 0%, #00D4FF 100%)',
    primaryHover: 'linear-gradient(135deg, #5B3DE8 0%, #00BFE8 100%)',
    primarySubtle: 'linear-gradient(135deg, rgba(108, 71, 255, 0.1) 0%, rgba(0, 212, 255, 0.1) 100%)',
    
    // Text gradients
    text: 'linear-gradient(90deg, #6C47FF 0%, #00D4FF 100%)',
    textReverse: 'linear-gradient(90deg, #00D4FF 0%, #6C47FF 100%)',
    
    // Card backgrounds
    card: 'linear-gradient(180deg, rgba(108, 71, 255, 0.05) 0%, rgba(0, 212, 255, 0.05) 100%)',
    cardHover: 'linear-gradient(180deg, rgba(108, 71, 255, 0.1) 0%, rgba(0, 212, 255, 0.1) 100%)',
    
    // Border gradients
    border: 'linear-gradient(135deg, #6C47FF 0%, #00D4FF 100%)',
    borderSubtle: 'linear-gradient(135deg, rgba(108, 71, 255, 0.3) 0%, rgba(0, 212, 255, 0.3) 100%)',
    
    // Background mesh
    mesh: 'radial-gradient(at 40% 20%, rgba(108, 71, 255, 0.15) 0px, transparent 50%), radial-gradient(at 80% 0%, rgba(0, 212, 255, 0.1) 0px, transparent 50%), radial-gradient(at 0% 50%, rgba(108, 71, 255, 0.1) 0px, transparent 50%)',
    
    // Hero background
    hero: 'linear-gradient(180deg, #FFFFFF 0%, #F5F3FF 50%, #EDE9FE 100%)',
    
    // Dark section background
    dark: 'linear-gradient(180deg, #18181B 0%, #0F0F10 100%)',
    
    // Rainbow (for special effects)
    rainbow: 'linear-gradient(90deg, #6C47FF 0%, #00D4FF 25%, #22C55E 50%, #F59E0B 75%, #EF4444 100%)',
    
    // Fire (for alerts/warnings)
    fire: 'linear-gradient(90deg, #F59E0B 0%, #EF4444 100%)',
    
    // Ocean (alternative accent)
    ocean: 'linear-gradient(90deg, #0EA5E9 0%, #06B6D4 100%)',
  },

  typography: {
    fontFamily: {
      sans: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      mono: 'JetBrains Mono, Menlo, Monaco, "Courier New", monospace',
      display: 'Inter, -apple-system, BlinkMacSystemFont, sans-serif',
    },
    fontSize: {
      xs: '0.75rem',     // 12px
      sm: '0.875rem',    // 14px
      base: '1rem',      // 16px
      lg: '1.125rem',    // 18px
      xl: '1.25rem',     // 20px
      '2xl': '1.5rem',   // 24px
      '3xl': '1.875rem', // 30px
      '4xl': '2.25rem',  // 36px
      '5xl': '3rem',     // 48px
      '6xl': '3.75rem',  // 60px
      '7xl': '4.5rem',   // 72px
      '8xl': '6rem',     // 96px
    },
    fontWeight: {
      normal: 400,
      medium: 500,
      semibold: 600,
      bold: 700,
      extrabold: 800,
    },
    lineHeight: {
      none: 1,
      tight: 1.1,
      snug: 1.25,
      normal: 1.5,
      relaxed: 1.625,
      loose: 2,
    },
  },

  // 4px base unit spacing scale
  spacing: {
    0: '0',
    px: '1px',
    0.5: '0.125rem',  // 2px
    1: '0.25rem',     // 4px
    1.5: '0.375rem',  // 6px
    2: '0.5rem',      // 8px
    2.5: '0.625rem',  // 10px
    3: '0.75rem',     // 12px
    3.5: '0.875rem',  // 14px
    4: '1rem',        // 16px
    5: '1.25rem',     // 20px
    6: '1.5rem',      // 24px
    7: '1.75rem',     // 28px
    8: '2rem',        // 32px
    9: '2.25rem',     // 36px
    10: '2.5rem',     // 40px
    11: '2.75rem',    // 44px
    12: '3rem',       // 48px
    14: '3.5rem',     // 56px
    16: '4rem',       // 64px
    20: '5rem',       // 80px
    24: '6rem',       // 96px
    28: '7rem',       // 112px
    32: '8rem',       // 128px
    36: '9rem',       // 144px
    40: '10rem',      // 160px
    44: '11rem',      // 176px
    48: '12rem',      // 192px
    52: '13rem',      // 208px
    56: '14rem',      // 224px
    60: '15rem',      // 240px
    64: '16rem',      // 256px
    72: '18rem',      // 288px
    80: '20rem',      // 320px
    96: '24rem',      // 384px
  },

  borderRadius: {
    none: '0',
    sm: '0.25rem',    // 4px
    DEFAULT: '0.375rem', // 6px
    md: '0.5rem',     // 8px
    lg: '0.75rem',    // 12px
    xl: '1rem',       // 16px
    '2xl': '1.5rem',  // 24px
    '3xl': '2rem',    // 32px
    full: '9999px',
  },

  shadows: {
    // Standard shadows
    sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
    DEFAULT: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1)',
    md: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1)',
    lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)',
    xl: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)',
    '2xl': '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
    inner: 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.05)',
    none: 'none',
    
    // Glow effects (purple)
    glow: '0 0 40px rgba(108, 71, 255, 0.15)',
    glowMd: '0 0 60px rgba(108, 71, 255, 0.2)',
    glowLg: '0 0 80px rgba(108, 71, 255, 0.25)',
    glowXl: '0 0 100px rgba(108, 71, 255, 0.3)',
    
    // Card hover effects
    cardHover: '0 20px 40px -10px rgba(108, 71, 255, 0.2)',
    cardHoverLg: '0 25px 50px -12px rgba(108, 71, 255, 0.25)',
    
    // Button effects
    button: '0 4px 14px 0 rgba(108, 71, 255, 0.25)',
    buttonHover: '0 6px 20px 0 rgba(108, 71, 255, 0.35)',
    
    // Focus ring
    focus: '0 0 0 3px rgba(108, 71, 255, 0.4)',
    focusError: '0 0 0 3px rgba(239, 68, 68, 0.4)',
    focusSuccess: '0 0 0 3px rgba(34, 197, 94, 0.4)',
  },
};

// CSS custom properties for runtime theming
export const cssVariables = {
  '--color-primary': clerkTheme.colors.primary.DEFAULT,
  '--color-primary-50': clerkTheme.colors.primary[50],
  '--color-primary-100': clerkTheme.colors.primary[100],
  '--color-primary-500': clerkTheme.colors.primary[500],
  '--color-primary-600': clerkTheme.colors.primary[600],
  '--color-primary-700': clerkTheme.colors.primary[700],
  '--color-accent': clerkTheme.colors.accent.DEFAULT,
  '--color-accent-500': clerkTheme.colors.accent[500],
  '--gradient-primary': clerkTheme.gradients.primary,
  '--gradient-text': clerkTheme.gradients.text,
  '--shadow-glow': clerkTheme.shadows.glow,
  '--shadow-card-hover': clerkTheme.shadows.cardHover,
};

// Tailwind CSS class utilities
export const tailwindClasses = {
  // Gradient text
  gradientText: 'bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent',
  
  // Gradient backgrounds
  gradientBg: 'bg-gradient-to-br from-primary to-accent',
  gradientBgSubtle: 'bg-gradient-to-br from-primary/10 to-accent/10',
  
  // Gradient borders (using pseudo-element technique)
  gradientBorder: 'relative before:absolute before:inset-0 before:rounded-[inherit] before:p-[1px] before:bg-gradient-to-br before:from-primary before:to-accent before:-z-10',
  
  // Glow effects
  glow: 'shadow-[0_0_40px_rgba(108,71,255,0.15)]',
  glowHover: 'hover:shadow-[0_0_60px_rgba(108,71,255,0.25)]',
  
  // Card styles
  card: 'bg-white rounded-xl shadow-md border border-neutral-200/50',
  cardHover: 'hover:shadow-cardHover hover:-translate-y-1 transition-all duration-300',
  
  // Button styles
  buttonPrimary: 'bg-gradient-to-r from-primary to-primary-600 text-white font-semibold rounded-xl px-6 py-3 shadow-button hover:shadow-buttonHover transition-all duration-200',
  buttonSecondary: 'bg-white text-neutral-700 font-medium rounded-xl px-6 py-3 border border-neutral-200 hover:border-primary/30 hover:bg-primary/5 transition-all duration-200',
  buttonOutline: 'bg-transparent text-primary font-medium rounded-xl px-6 py-3 border-2 border-primary hover:bg-primary hover:text-white transition-all duration-200',
  
  // Focus states
  focusRing: 'focus:outline-none focus:ring-2 focus:ring-primary/40 focus:ring-offset-2',
};

export default clerkTheme;
