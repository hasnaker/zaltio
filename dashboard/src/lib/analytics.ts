/**
 * Zalt.io Analytics Utility Library
 * 
 * Provides Google Analytics 4 integration, event tracking,
 * and conversion tracking for Google Ads.
 */

// GA4 Measurement ID - set via environment variable
const GA_MEASUREMENT_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID || '';

// Google Ads Conversion ID
const GOOGLE_ADS_ID = process.env.NEXT_PUBLIC_GOOGLE_ADS_ID || '';

// Type definitions
export interface AnalyticsEvent {
  name: string;
  category: string;
  action: string;
  label?: string;
  value?: number;
  customDimensions?: Record<string, string>;
}

export interface PageViewData {
  path: string;
  title: string;
  referrer?: string;
}

export interface ConversionData {
  type: 'signup' | 'lead' | 'demo_request' | 'pricing_view' | 'contact_form';
  value?: number;
  currency?: string;
  transactionId?: string;
}

// Declare gtag for TypeScript
declare global {
  interface Window {
    gtag: (
      command: 'config' | 'event' | 'js' | 'set',
      targetId: string,
      config?: Record<string, unknown>
    ) => void;
    dataLayer: unknown[];
  }
}

/**
 * Check if analytics is available (client-side and gtag loaded)
 */
export function isAnalyticsAvailable(): boolean {
  return typeof window !== 'undefined' && typeof window.gtag === 'function';
}

/**
 * Initialize Google Analytics 4
 * Should be called once in the app layout
 */
export function initGA4(): void {
  if (typeof window === 'undefined' || !GA_MEASUREMENT_ID) {
    return;
  }

  // Initialize dataLayer
  window.dataLayer = window.dataLayer || [];
  
  // Define gtag function
  window.gtag = function gtag(...args: unknown[]) {
    window.dataLayer.push(args);
  };

  window.gtag('js', new Date().toISOString());
  window.gtag('config', GA_MEASUREMENT_ID, {
    page_path: window.location.pathname,
    send_page_view: true,
  });
}

/**
 * Track a page view
 */
export function trackPageView(data: PageViewData): void {
  if (!isAnalyticsAvailable() || !GA_MEASUREMENT_ID) {
    return;
  }

  window.gtag('config', GA_MEASUREMENT_ID, {
    page_path: data.path,
    page_title: data.title,
    page_referrer: data.referrer,
  });
}

/**
 * Track a custom event
 */
export function trackEvent(event: AnalyticsEvent): void {
  if (!isAnalyticsAvailable()) {
    return;
  }

  const eventParams: Record<string, unknown> = {
    event_category: event.category,
    event_label: event.label,
    value: event.value,
    ...event.customDimensions,
  };

  window.gtag('event', event.name, eventParams);
}

/**
 * Track CTA button clicks
 */
export function trackCTAClick(
  buttonName: string,
  location: string,
  destination?: string
): void {
  trackEvent({
    name: 'cta_click',
    category: 'engagement',
    action: 'click',
    label: buttonName,
    customDimensions: {
      cta_location: location,
      cta_destination: destination || '',
    },
  });
}

/**
 * Track form submissions
 */
export function trackFormSubmission(
  formName: string,
  success: boolean,
  errorMessage?: string
): void {
  trackEvent({
    name: success ? 'form_submit_success' : 'form_submit_error',
    category: 'forms',
    action: success ? 'submit_success' : 'submit_error',
    label: formName,
    customDimensions: {
      form_name: formName,
      error_message: errorMessage || '',
    },
  });
}

/**
 * Track scroll depth
 */
export function trackScrollDepth(percentage: number, pagePath: string): void {
  trackEvent({
    name: 'scroll_depth',
    category: 'engagement',
    action: 'scroll',
    value: percentage,
    customDimensions: {
      page_path: pagePath,
      scroll_percentage: `${percentage}%`,
    },
  });
}

/**
 * Track conversion for Google Ads
 */
export function trackConversion(data: ConversionData): void {
  if (!isAnalyticsAvailable()) {
    return;
  }

  // GA4 conversion event
  trackEvent({
    name: `conversion_${data.type}`,
    category: 'conversion',
    action: data.type,
    value: data.value,
    customDimensions: {
      conversion_type: data.type,
      transaction_id: data.transactionId || '',
    },
  });

  // Google Ads conversion tracking
  if (GOOGLE_ADS_ID) {
    const conversionLabel = getConversionLabel(data.type);
    if (conversionLabel) {
      window.gtag('event', 'conversion', {
        send_to: `${GOOGLE_ADS_ID}/${conversionLabel}`,
        value: data.value,
        currency: data.currency || 'USD',
        transaction_id: data.transactionId,
      });
    }
  }
}

/**
 * Get Google Ads conversion label based on conversion type
 */
function getConversionLabel(type: ConversionData['type']): string {
  const labels: Record<ConversionData['type'], string> = {
    signup: process.env.NEXT_PUBLIC_GADS_SIGNUP_LABEL || '',
    lead: process.env.NEXT_PUBLIC_GADS_LEAD_LABEL || '',
    demo_request: process.env.NEXT_PUBLIC_GADS_DEMO_LABEL || '',
    pricing_view: process.env.NEXT_PUBLIC_GADS_PRICING_LABEL || '',
    contact_form: process.env.NEXT_PUBLIC_GADS_CONTACT_LABEL || '',
  };
  return labels[type];
}

/**
 * Track signup completion
 */
export function trackSignup(userId?: string): void {
  trackConversion({
    type: 'signup',
    transactionId: userId,
  });
}

/**
 * Track lead generation
 */
export function trackLead(source: string, email?: string): void {
  trackConversion({
    type: 'lead',
    transactionId: email ? btoa(email).slice(0, 16) : undefined,
  });
  
  trackEvent({
    name: 'generate_lead',
    category: 'conversion',
    action: 'lead_capture',
    customDimensions: {
      lead_source: source,
    },
  });
}

/**
 * Track demo request
 */
export function trackDemoRequest(company?: string): void {
  trackConversion({
    type: 'demo_request',
  });
  
  trackEvent({
    name: 'demo_request',
    category: 'conversion',
    action: 'request_demo',
    customDimensions: {
      company_name: company || 'unknown',
    },
  });
}

/**
 * Track pricing page view
 */
export function trackPricingView(selectedPlan?: string): void {
  trackConversion({
    type: 'pricing_view',
  });
  
  trackEvent({
    name: 'view_pricing',
    category: 'engagement',
    action: 'view_pricing',
    customDimensions: {
      selected_plan: selectedPlan || 'none',
    },
  });
}

/**
 * Track documentation page view
 */
export function trackDocsView(docPath: string, section: string): void {
  trackEvent({
    name: 'docs_view',
    category: 'documentation',
    action: 'view',
    customDimensions: {
      doc_path: docPath,
      doc_section: section,
    },
  });
}

/**
 * Track code snippet copy
 */
export function trackCodeCopy(framework: string, snippetType: string): void {
  trackEvent({
    name: 'code_copy',
    category: 'engagement',
    action: 'copy_code',
    customDimensions: {
      framework,
      snippet_type: snippetType,
    },
  });
}

/**
 * Track framework selection in code showcase
 */
export function trackFrameworkSelect(framework: string): void {
  trackEvent({
    name: 'framework_select',
    category: 'engagement',
    action: 'select_framework',
    label: framework,
  });
}

/**
 * Track comparison page view
 */
export function trackComparisonView(competitor: string): void {
  trackEvent({
    name: 'comparison_view',
    category: 'engagement',
    action: 'view_comparison',
    label: competitor,
  });
}

/**
 * Set user properties for analytics
 */
export function setUserProperties(properties: Record<string, string>): void {
  if (!isAnalyticsAvailable() || !GA_MEASUREMENT_ID) {
    return;
  }

  window.gtag('set', 'user_properties', properties);
}

/**
 * Track A/B test variant assignment
 */
export function trackABTestVariant(
  testId: string,
  variantId: string
): void {
  trackEvent({
    name: 'ab_test_assignment',
    category: 'experiment',
    action: 'assign_variant',
    customDimensions: {
      test_id: testId,
      variant_id: variantId,
    },
  });
}

/**
 * Track A/B test conversion
 */
export function trackABTestConversion(
  testId: string,
  variantId: string,
  conversionType: string
): void {
  trackEvent({
    name: 'ab_test_conversion',
    category: 'experiment',
    action: 'convert',
    customDimensions: {
      test_id: testId,
      variant_id: variantId,
      conversion_type: conversionType,
    },
  });
}

// Export all functions for testing
export const analytics = {
  initGA4,
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
  isAnalyticsAvailable,
};

export default analytics;
