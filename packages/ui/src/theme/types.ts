/**
 * Theme types for @zalt/ui
 */

export type ThemeMode = 'light' | 'dark' | 'system';

export interface ThemeColors {
  // Primary brand colors
  primary: string;
  primaryForeground: string;
  primaryHover: string;
  
  // Secondary colors
  secondary: string;
  secondaryForeground: string;
  secondaryHover: string;
  
  // Background colors
  background: string;
  foreground: string;
  
  // Card/Surface colors
  card: string;
  cardForeground: string;
  
  // Muted colors (for subtle elements)
  muted: string;
  mutedForeground: string;
  
  // Border colors
  border: string;
  borderHover: string;
  
  // Input colors
  input: string;
  inputForeground: string;
  inputPlaceholder: string;
  inputBorder: string;
  inputFocus: string;
  
  // Status colors
  success: string;
  successForeground: string;
  warning: string;
  warningForeground: string;
  error: string;
  errorForeground: string;
  info: string;
  infoForeground: string;
  
  // Ring (focus outline)
  ring: string;
}

export interface ThemeSpacing {
  xs: string;
  sm: string;
  md: string;
  lg: string;
  xl: string;
  '2xl': string;
}

export interface ThemeRadius {
  none: string;
  sm: string;
  md: string;
  lg: string;
  xl: string;
  full: string;
}

export interface ThemeFonts {
  sans: string;
  mono: string;
}

export interface ThemeShadows {
  sm: string;
  md: string;
  lg: string;
  xl: string;
}

export interface Theme {
  name: string;
  mode: 'light' | 'dark';
  colors: ThemeColors;
  spacing: ThemeSpacing;
  radius: ThemeRadius;
  fonts: ThemeFonts;
  shadows: ThemeShadows;
}

export interface ThemeConfig {
  /** Base theme to use */
  baseTheme?: Theme;
  /** Override specific colors */
  colors?: Partial<ThemeColors>;
  /** Override spacing */
  spacing?: Partial<ThemeSpacing>;
  /** Override border radius */
  radius?: Partial<ThemeRadius>;
  /** Override fonts */
  fonts?: Partial<ThemeFonts>;
  /** Override shadows */
  shadows?: Partial<ThemeShadows>;
}

export interface ThemeContextValue {
  theme: Theme;
  mode: ThemeMode;
  setMode: (mode: ThemeMode) => void;
  resolvedMode: 'light' | 'dark';
}
