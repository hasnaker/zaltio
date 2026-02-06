/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Zalt.io brand colors - these map to CSS variables
        zalt: {
          primary: 'var(--zalt-primary)',
          'primary-foreground': 'var(--zalt-primary-foreground)',
          secondary: 'var(--zalt-secondary)',
          'secondary-foreground': 'var(--zalt-secondary-foreground)',
          background: 'var(--zalt-background)',
          foreground: 'var(--zalt-foreground)',
          card: 'var(--zalt-card)',
          'card-foreground': 'var(--zalt-card-foreground)',
          muted: 'var(--zalt-muted)',
          'muted-foreground': 'var(--zalt-muted-foreground)',
          border: 'var(--zalt-border)',
          input: 'var(--zalt-input)',
          ring: 'var(--zalt-ring)',
          success: 'var(--zalt-success)',
          warning: 'var(--zalt-warning)',
          error: 'var(--zalt-error)',
        },
      },
      fontFamily: {
        sans: ['var(--zalt-font-sans)'],
        mono: ['var(--zalt-font-mono)'],
      },
      borderRadius: {
        zalt: {
          sm: 'var(--zalt-radius-sm)',
          md: 'var(--zalt-radius-md)',
          lg: 'var(--zalt-radius-lg)',
          xl: 'var(--zalt-radius-xl)',
        },
      },
      boxShadow: {
        zalt: {
          sm: 'var(--zalt-shadow-sm)',
          md: 'var(--zalt-shadow-md)',
          lg: 'var(--zalt-shadow-lg)',
          xl: 'var(--zalt-shadow-xl)',
        },
      },
    },
  },
  plugins: [],
};
