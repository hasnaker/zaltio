/**
 * @zalt/ui - Pre-built UI components for Zalt.io authentication
 * 
 * Drop-in authentication components like Clerk, but open source.
 */

// Theme
export { ThemeProvider, useTheme } from './theme/ThemeProvider';
export type { Theme, ThemeConfig, ThemeMode } from './theme/types';
export { defaultTheme } from './theme/default';
export { darkTheme } from './theme/dark';

// Components
export { SignIn } from './components/SignIn';
export { SignUp } from './components/SignUp';
export { UserButton } from './components/UserButton';
export { UserProfile } from './components/UserProfile';
export { MFASetup } from './components/MFASetup';
export { OrganizationSwitcher } from './components/OrganizationSwitcher';
export { ProtectedRoute } from './components/ProtectedRoute';

// Primitives (for custom implementations)
export { Button } from './primitives/Button';
export { Input } from './primitives/Input';
export { Card } from './primitives/Card';
export { Avatar } from './primitives/Avatar';
export { Spinner } from './primitives/Spinner';

// Utilities
export { cn } from './utils/cn';
