/**
 * NEXUS Theme Configuration
 * Neural EXtended Unified Security - Theme System
 * 
 * This file exports the NEXUS theme colors and configuration
 * for use in components and property-based testing.
 */

export const nexusTheme = {
  colors: {
    // Cosmic colors - Deep space palette
    cosmic: {
      black: '#0A0E1A',      // Primary background
      deep: '#0D1220',       // Secondary background
      nebula: '#1A1F35',     // Card backgrounds
      void: '#141824',       // Sidebar background
    },
    // Glow colors - Bioluminescent accents
    glow: {
      cyan: '#00F5D4',       // Primary accent
      purple: '#7B2FFF',     // Secondary accent
      pink: '#FF006E',       // Tertiary accent
      blue: '#00D4FF',       // Info states
    },
    // Semantic colors
    semantic: {
      success: '#00F5A0',
      warning: '#FFB800',
      error: '#FF4757',
    },
    // Text colors
    text: {
      primary: '#FFFFFF',
      secondary: '#A0AEC0',
      muted: '#64748B',
      disabled: '#475569',
    },
  },
  // Required color values from Requirements 1.1
  requiredColors: {
    cosmicBlack: '#0A0E1A',
    nebulaBlue: '#1A1F35',
    bioluminescentCyan: '#00F5D4',
    quantumPurple: '#7B2FFF',
    plasmaPink: '#FF006E',
  },
  // Typography configuration from Requirements 1.3
  typography: {
    fontFamily: {
      heading: 'Space Grotesk',
      body: 'Inter',
      mono: 'JetBrains Mono',
    },
    // CSS variable names used in the application
    cssVariables: {
      heading: '--font-space-grotesk',
      body: '--font-inter',
      mono: '--font-jetbrains-mono',
    },
    // Tailwind class names
    tailwindClasses: {
      heading: 'font-heading',
      body: 'font-body',
      mono: 'font-mono',
    },
  },
  // Required typography values from Requirements 1.3
  requiredTypography: {
    headingFont: 'Space Grotesk',
    bodyFont: 'Inter',
  },
} as const;

/**
 * Validates if a string is a valid hex color code
 */
export function isValidHexColor(color: string): boolean {
  return /^#[0-9A-Fa-f]{6}$/.test(color);
}

/**
 * Gets all color values from a nested color object
 */
export function getAllColorValues(obj: Record<string, unknown>, prefix = ''): Array<{ path: string; value: string }> {
  const colors: Array<{ path: string; value: string }> = [];
  
  for (const [key, value] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;
    
    if (typeof value === 'string') {
      colors.push({ path, value });
    } else if (typeof value === 'object' && value !== null) {
      colors.push(...getAllColorValues(value as Record<string, unknown>, path));
    }
  }
  
  return colors;
}

/**
 * Validates if a font family string is valid (non-empty and contains expected font name)
 */
export function isValidFontFamily(fontFamily: string): boolean {
  return typeof fontFamily === 'string' && fontFamily.trim().length > 0;
}

/**
 * Checks if a font family string contains the expected font name
 */
export function fontFamilyContains(fontFamily: string, expectedFont: string): boolean {
  return fontFamily.toLowerCase().includes(expectedFont.toLowerCase());
}

/**
 * Gets all typography font family values from the theme
 */
export function getAllTypographyValues(): Array<{ type: string; fontName: string }> {
  return [
    { type: 'heading', fontName: nexusTheme.typography.fontFamily.heading },
    { type: 'body', fontName: nexusTheme.typography.fontFamily.body },
    { type: 'mono', fontName: nexusTheme.typography.fontFamily.mono },
  ];
}

export type NexusTheme = typeof nexusTheme;
