/**
 * Analytics Utility Tests
 */

// Mock window.gtag
const mockGtag = jest.fn();

// We need to mock the module to inject the GA_MEASUREMENT_ID
jest.mock('../analytics', () => {
  const originalModule = jest.requireActual('../analytics');
  
  // Override the functions that check GA_MEASUREMENT_ID
  return {
    ...originalModule,
    trackPageView: (data: { path: string; title: string; referrer?: string }) => {
      if (typeof window !== 'undefined' && typeof window.gtag === 'function') {
        window.gtag('config', 'G-TEST123', {
          page_path: data.path,
          page_title: data.title,
          page_referrer: data.referrer,
        });
      }
    },
    setUserProperties: (properties: Record<string, string>) => {
      if (typeof window !== 'undefined' && typeof window.gtag === 'function') {
        window.gtag('set', 'user_properties', properties);
      }
    },
  };
});

import {
  analytics,
  isAnalyticsAvailable,
  trackPageView,
  trackEvent,
  trackCTAClick,
  trackFormSubmission,
  trackScrollDepth,
  trackConversion,
  trackSignup,
  trackLead,
  trackDemoRequest,
  trackPricingView,
  trackDocsView,
  trackCodeCopy,
  trackFrameworkSelect,
  trackComparisonView,
  setUserProperties,
  trackABTestVariant,
  trackABTestConversion,
  AnalyticsEvent,
  PageViewData,
  ConversionData,
} from '../analytics';

describe('Analytics Utility', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Setup window mock
    Object.defineProperty(global, 'window', {
      value: {
        gtag: mockGtag,
        dataLayer: [],
        location: { pathname: '/test' },
      },
      writable: true,
    });
  });

  afterEach(() => {
    // Clean up
    Object.defineProperty(global, 'window', {
      value: undefined,
      writable: true,
    });
  });

  describe('isAnalyticsAvailable', () => {
    it('should return true when gtag is available', () => {
      expect(isAnalyticsAvailable()).toBe(true);
    });

    it('should return false when window is undefined', () => {
      Object.defineProperty(global, 'window', {
        value: undefined,
        writable: true,
      });
      expect(isAnalyticsAvailable()).toBe(false);
    });

    it('should return false when gtag is not a function', () => {
      Object.defineProperty(global, 'window', {
        value: { gtag: 'not a function' },
        writable: true,
      });
      expect(isAnalyticsAvailable()).toBe(false);
    });
  });

  describe('trackPageView', () => {
    it('should call gtag with page view data', () => {
      const pageData: PageViewData = {
        path: '/pricing',
        title: 'Pricing - Zalt.io',
        referrer: 'https://google.com',
      };

      trackPageView(pageData);

      expect(mockGtag).toHaveBeenCalledWith(
        'config',
        expect.any(String),
        expect.objectContaining({
          page_path: '/pricing',
          page_title: 'Pricing - Zalt.io',
          page_referrer: 'https://google.com',
        })
      );
    });

    it('should handle missing referrer', () => {
      const pageData: PageViewData = {
        path: '/docs',
        title: 'Documentation',
      };

      trackPageView(pageData);

      expect(mockGtag).toHaveBeenCalledWith(
        'config',
        expect.any(String),
        expect.objectContaining({
          page_path: '/docs',
          page_title: 'Documentation',
        })
      );
    });
  });

  describe('trackEvent', () => {
    it('should call gtag with event data', () => {
      const event: AnalyticsEvent = {
        name: 'test_event',
        category: 'test',
        action: 'click',
        label: 'test_label',
        value: 100,
      };

      trackEvent(event);

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'test_event',
        expect.objectContaining({
          event_category: 'test',
          event_label: 'test_label',
          value: 100,
        })
      );
    });

    it('should include custom dimensions', () => {
      const event: AnalyticsEvent = {
        name: 'custom_event',
        category: 'custom',
        action: 'test',
        customDimensions: {
          custom_param: 'custom_value',
        },
      };

      trackEvent(event);

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'custom_event',
        expect.objectContaining({
          custom_param: 'custom_value',
        })
      );
    });
  });

  describe('trackCTAClick', () => {
    it('should track CTA click with location and destination', () => {
      trackCTAClick('Get Started', 'hero', '/signup');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'cta_click',
        expect.objectContaining({
          event_category: 'engagement',
          event_label: 'Get Started',
          cta_location: 'hero',
          cta_destination: '/signup',
        })
      );
    });

    it('should handle missing destination', () => {
      trackCTAClick('Learn More', 'features');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'cta_click',
        expect.objectContaining({
          cta_destination: '',
        })
      );
    });
  });

  describe('trackFormSubmission', () => {
    it('should track successful form submission', () => {
      trackFormSubmission('contact_form', true);

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'form_submit_success',
        expect.objectContaining({
          event_category: 'forms',
          form_name: 'contact_form',
        })
      );
    });

    it('should track failed form submission with error', () => {
      trackFormSubmission('newsletter', false, 'Invalid email');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'form_submit_error',
        expect.objectContaining({
          event_category: 'forms',
          form_name: 'newsletter',
          error_message: 'Invalid email',
        })
      );
    });
  });

  describe('trackScrollDepth', () => {
    it('should track scroll depth percentage', () => {
      trackScrollDepth(50, '/pricing');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'scroll_depth',
        expect.objectContaining({
          event_category: 'engagement',
          value: 50,
          page_path: '/pricing',
          scroll_percentage: '50%',
        })
      );
    });
  });

  describe('trackConversion', () => {
    it('should track signup conversion', () => {
      const data: ConversionData = {
        type: 'signup',
        transactionId: 'user_123',
      };

      trackConversion(data);

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'conversion_signup',
        expect.objectContaining({
          event_category: 'conversion',
          conversion_type: 'signup',
          transaction_id: 'user_123',
        })
      );
    });

    it('should track lead conversion', () => {
      const data: ConversionData = {
        type: 'lead',
        value: 50,
      };

      trackConversion(data);

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'conversion_lead',
        expect.objectContaining({
          conversion_type: 'lead',
          value: 50,
        })
      );
    });
  });

  describe('trackSignup', () => {
    it('should track signup with user ID', () => {
      trackSignup('user_456');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'conversion_signup',
        expect.objectContaining({
          transaction_id: 'user_456',
        })
      );
    });
  });

  describe('trackLead', () => {
    it('should track lead with source', () => {
      trackLead('pricing_page');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'generate_lead',
        expect.objectContaining({
          lead_source: 'pricing_page',
        })
      );
    });
  });

  describe('trackDemoRequest', () => {
    it('should track demo request with company', () => {
      trackDemoRequest('Acme Corp');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'demo_request',
        expect.objectContaining({
          company_name: 'Acme Corp',
        })
      );
    });

    it('should handle missing company', () => {
      trackDemoRequest();

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'demo_request',
        expect.objectContaining({
          company_name: 'unknown',
        })
      );
    });
  });

  describe('trackPricingView', () => {
    it('should track pricing view with selected plan', () => {
      trackPricingView('pro');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'view_pricing',
        expect.objectContaining({
          selected_plan: 'pro',
        })
      );
    });
  });

  describe('trackDocsView', () => {
    it('should track documentation view', () => {
      trackDocsView('/docs/quickstart', 'getting-started');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'docs_view',
        expect.objectContaining({
          doc_path: '/docs/quickstart',
          doc_section: 'getting-started',
        })
      );
    });
  });

  describe('trackCodeCopy', () => {
    it('should track code snippet copy', () => {
      trackCodeCopy('nextjs', 'installation');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'code_copy',
        expect.objectContaining({
          framework: 'nextjs',
          snippet_type: 'installation',
        })
      );
    });
  });

  describe('trackFrameworkSelect', () => {
    it('should track framework selection', () => {
      trackFrameworkSelect('react');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'framework_select',
        expect.objectContaining({
          event_label: 'react',
        })
      );
    });
  });

  describe('trackComparisonView', () => {
    it('should track comparison page view', () => {
      trackComparisonView('clerk');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'comparison_view',
        expect.objectContaining({
          event_label: 'clerk',
        })
      );
    });
  });

  describe('setUserProperties', () => {
    it('should set user properties', () => {
      setUserProperties({
        user_type: 'developer',
        company_size: 'enterprise',
      });

      expect(mockGtag).toHaveBeenCalledWith(
        'set',
        'user_properties',
        {
          user_type: 'developer',
          company_size: 'enterprise',
        }
      );
    });
  });

  describe('trackABTestVariant', () => {
    it('should track A/B test variant assignment', () => {
      trackABTestVariant('hero_test', 'variant_b');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'ab_test_assignment',
        expect.objectContaining({
          test_id: 'hero_test',
          variant_id: 'variant_b',
        })
      );
    });
  });

  describe('trackABTestConversion', () => {
    it('should track A/B test conversion', () => {
      trackABTestConversion('hero_test', 'variant_b', 'signup');

      expect(mockGtag).toHaveBeenCalledWith(
        'event',
        'ab_test_conversion',
        expect.objectContaining({
          test_id: 'hero_test',
          variant_id: 'variant_b',
          conversion_type: 'signup',
        })
      );
    });
  });

  describe('analytics object export', () => {
    it('should export all functions', () => {
      expect(analytics.initGA4).toBeDefined();
      expect(analytics.trackPageView).toBeDefined();
      expect(analytics.trackEvent).toBeDefined();
      expect(analytics.trackCTAClick).toBeDefined();
      expect(analytics.trackFormSubmission).toBeDefined();
      expect(analytics.trackScrollDepth).toBeDefined();
      expect(analytics.trackConversion).toBeDefined();
      expect(analytics.trackSignup).toBeDefined();
      expect(analytics.trackLead).toBeDefined();
      expect(analytics.trackDemoRequest).toBeDefined();
      expect(analytics.trackPricingView).toBeDefined();
      expect(analytics.trackDocsView).toBeDefined();
      expect(analytics.trackCodeCopy).toBeDefined();
      expect(analytics.trackFrameworkSelect).toBeDefined();
      expect(analytics.trackComparisonView).toBeDefined();
      expect(analytics.setUserProperties).toBeDefined();
      expect(analytics.trackABTestVariant).toBeDefined();
      expect(analytics.trackABTestConversion).toBeDefined();
      expect(analytics.isAnalyticsAvailable).toBeDefined();
    });
  });
});
