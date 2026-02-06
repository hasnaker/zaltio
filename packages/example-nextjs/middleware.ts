import { zaltMiddleware } from '@zalt/next';

export default zaltMiddleware({
  publicRoutes: ['/', '/sign-in', '/sign-up'],
  signInUrl: '/sign-in',
  afterSignInUrl: '/dashboard',
});

export const config = {
  matcher: ['/((?!_next|.*\\..*).*)'],
};
