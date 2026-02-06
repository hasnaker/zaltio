'use client';

import { useEffect } from 'react';
import { usePathname } from 'next/navigation';
import { trackPageView, trackCTAClick } from '@/lib/analytics';
import { ScrollTracker } from './ScrollTracker';

interface AnalyticsProviderProps {
  children: React.ReactNode;
  enableScrollTracking?: boolean;
}

/**
 * AnalyticsProvider component
 * Provides automatic page view tracking and CTA click tracking
 */
export function AnalyticsProvider({ 
  children, 
  enableScrollTracking = true 
}: AnalyticsProviderProps) {
  const pathname = usePathname();

  // Track page views on route change
  useEffect(() => {
    trackPageView({
      path: pathname,
      title: document.title,
      referrer: document.referrer,
    });
  }, [pathname]);

  // Set up global CTA click tracking
  useEffect(() => {
    const handleClick = (event: MouseEvent) => {
      const target = event.target as HTMLElement;
      const ctaElement = target.closest('[data-cta]');
      
      if (ctaElement) {
        const ctaName = ctaElement.getAttribute('data-cta') || 'unknown';
        const ctaLocation = ctaElement.getAttribute('data-cta-location') || pathname;
        const ctaDestination = ctaElement.getAttribute('href') || undefined;
        
        trackCTAClick(ctaName, ctaLocation, ctaDestination);
      }
    };

    document.addEventListener('click', handleClick);
    return () => document.removeEventListener('click', handleClick);
  }, [pathname]);

  return (
    <>
      {enableScrollTracking && <ScrollTracker pagePath={pathname} />}
      {children}
    </>
  );
}

export default AnalyticsProvider;
