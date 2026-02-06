# Implementation Plan: Zalt Enterprise Landing Page

## Overview

This implementation plan creates a production-ready enterprise landing page and marketing website for Zalt.io. The plan builds incrementally, starting with core infrastructure and progressing through landing page sections, documentation, and marketing pages.

## Tasks

- [x] 1. Set up core infrastructure and utilities
  - [x] 1.1 Create analytics utility library at `dashboard/src/lib/analytics.ts`
    - Implement GA4 initialization and page view tracking
    - Create event tracking functions for CTA clicks and form submissions
    - Add conversion tracking for Google Ads
    - _Requirements: 12.1, 12.2, 12.3_

  - [x] 1.2 Create SEO utility library at `dashboard/src/lib/seo.ts`
    - Implement meta tag generation functions
    - Create Open Graph and Twitter Card helpers
    - Add JSON-LD structured data generators
    - _Requirements: 11.1, 11.2, 11.3, 11.6_

  - [x] 1.3 Create form validation utility at `dashboard/src/lib/validation.ts`
    - Implement email validation with regex
    - Implement required field validation
    - Create validation result types and error messages
    - _Requirements: 13.2, 13.3_

  - [x] 1.4 Write property test for form validation
    - **Property 14: Form validation rejects invalid input**
    - **Validates: Requirements 13.2, 13.3, 17.6**

- [x] 2. Checkpoint - Ensure utilities are working
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Implement enhanced Hero Section
  - [x] 3.1 Create animated 3D security lock component at `dashboard/src/components/landing/SecurityLock3D.tsx`
    - Implement CSS/SVG animation for rotating lock
    - Add gradient glow effects
    - Support reduced motion preferences
    - _Requirements: 1.2, 1.6_

  - [x] 3.2 Create device mockups component at `dashboard/src/components/landing/DeviceMockups.tsx`
    - Display desktop, tablet, and mobile device frames
    - Show authentication UI screenshots inside frames
    - Implement responsive sizing
    - _Requirements: 1.3_

  - [x] 3.3 Update HeroSection with new components
    - Integrate SecurityLock3D and DeviceMockups
    - Add animated gradient text headline
    - Implement primary and secondary CTA buttons
    - _Requirements: 1.1, 1.4, 1.5_

  - [x] 3.4 Write property test for reduced motion support
    - **Property 1: Reduced motion disables animations**
    - **Validates: Requirements 1.6, 15.6, 18.6**

- [x] 4. Implement Component Preview Section
  - [x] 4.1 Create ComponentPreview container at `dashboard/src/components/landing/ComponentPreview.tsx`
    - Implement tab navigation for component selection
    - Create preview container with mock data
    - Ensure no real API calls are made
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 4.2 Create ThemeCustomizer component at `dashboard/src/components/landing/ThemeCustomizer.tsx`
    - Implement color picker for primary/accent colors
    - Add border radius selector
    - Add dark mode toggle
    - _Requirements: 2.6_

  - [x] 4.3 Wire theme customizer to preview components
    - Implement theme context for real-time updates
    - Apply theme changes to all preview components
    - _Requirements: 2.7_

  - [x] 4.4 Write property test for component preview isolation
    - **Property 2: Component preview isolation**
    - **Validates: Requirements 2.5**

  - [x] 4.5 Write property test for theme synchronization
    - **Property 3: Theme synchronization**
    - **Validates: Requirements 2.7**

- [x] 5. Checkpoint - Ensure hero and preview sections work
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement enhanced Features Section
  - [x] 6.1 Create SecurityVisualization component at `dashboard/src/components/landing/SecurityVisualization.tsx`
    - Implement animated encryption flow visualization
    - Add threat detection animation
    - Support reduced motion
    - _Requirements: 3.4_

  - [x] 6.2 Create StatsCounter component at `dashboard/src/components/landing/StatsCounter.tsx`
    - Implement animated number counting
    - Add scroll-triggered animation
    - Display uptime, latency, auth/day, countries stats
    - _Requirements: 3.5, 3.6_

  - [x] 6.3 Update FeaturesSection with new components
    - Integrate SecurityVisualization
    - Add StatsCounter with scroll trigger
    - Ensure 6 feature cards are displayed
    - _Requirements: 3.1, 3.2, 3.3_

- [x] 7. Implement Organizations Showcase Section
  - [x] 7.1 Create OrganizationsSection at `dashboard/src/components/landing/OrganizationsSection.tsx`
    - Implement organization hierarchy visualization
    - Add RBAC capabilities demo
    - Show team invitation workflow
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [x] 7.2 Create OrgCard component at `dashboard/src/components/landing/OrgCard.tsx`
    - Display sample organization with realistic data
    - Show member count and role badges
    - _Requirements: 4.5_

- [x] 8. Implement enhanced Pricing Section
  - [x] 8.1 Create PricingCalculator component at `dashboard/src/components/landing/PricingCalculator.tsx`
    - Implement MAU input slider/field
    - Calculate and display monthly/annual costs
    - Show tier recommendations based on MAU
    - _Requirements: 5.4, 5.5_

  - [x] 8.2 Create FeatureComparisonTable at `dashboard/src/components/landing/FeatureComparisonTable.tsx`
    - Display feature matrix across all tiers
    - Add checkmarks and partial support indicators
    - _Requirements: 5.6_

  - [x] 8.3 Update PricingSection with calculator and table
    - Ensure exactly 3 pricing tiers displayed
    - Implement billing toggle with 20% discount
    - Add Contact Sales CTA for enterprise
    - _Requirements: 5.1, 5.2, 5.3, 5.7_

  - [x] 8.4 Write property test for pricing tier count
    - **Property 4: Pricing tier count invariant**
    - **Validates: Requirements 5.1**

  - [x] 8.5 Write property test for billing toggle
    - **Property 5: Billing toggle state change**
    - **Validates: Requirements 5.3**

  - [x] 8.6 Write property test for pricing calculator
    - **Property 6: Pricing calculator accuracy**
    - **Validates: Requirements 5.5**

- [x] 9. Checkpoint - Ensure pricing section works
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Implement Code Showcase Section
  - [x] 10.1 Create FrameworkLogos component at `dashboard/src/components/landing/FrameworkLogos.tsx`
    - Display logo grid for all supported frameworks
    - Implement click handler for framework selection
    - _Requirements: 6.1_

  - [x] 10.2 Create CodeShowcase component at `dashboard/src/components/landing/CodeShowcase.tsx`
    - Implement syntax highlighting with language detection
    - Add copy to clipboard functionality
    - Show installation commands per SDK
    - Display success toast on copy
    - _Requirements: 6.2, 6.3, 6.4, 6.5, 6.6_

  - [x] 10.3 Create code snippets data file at `dashboard/src/data/codeSnippets.ts`
    - Add integration code for each framework
    - Add installation commands for each SDK
    - _Requirements: 6.2, 6.6_

  - [x] 10.4 Write property test for code showcase content
    - **Property 7: Code showcase content mapping**
    - **Validates: Requirements 6.2, 6.3, 6.6**

- [x] 11. Implement Testimonials Section
  - [x] 11.1 Update TestimonialsSection at `dashboard/src/components/landing/TestimonialsSection.tsx`
    - Display at least 3 testimonials with company logos
    - Add Clinisyn case study highlight
    - Implement fade-in animations
    - _Requirements: 7.1, 7.2, 7.5_

  - [x] 11.2 Create TrustBadges component at `dashboard/src/components/landing/TrustBadges.tsx`
    - Display SOC 2, HIPAA, GDPR, ISO 27001 badges
    - Show aggregate statistics
    - _Requirements: 7.3, 7.4_

- [x] 12. Implement Navigation and Footer
  - [x] 12.1 Create enhanced Navbar at `dashboard/src/components/shared/Navbar.tsx`
    - Implement sticky navigation with blur on scroll
    - Add dropdown menus for Product, Resources, Company
    - Include CTA buttons
    - _Requirements: 17.1, 17.2, 17.3_

  - [x] 12.2 Update Footer with newsletter form
    - Add newsletter subscription with email validation
    - Organize links by category
    - Add social media links
    - Display compliance badges
    - _Requirements: 17.4, 17.5, 17.6, 17.7_

- [x] 13. Checkpoint - Ensure landing page sections complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Implement Documentation Hub
  - [x] 14.1 Create DocsLayout at `dashboard/src/components/docs/DocsLayout.tsx`
    - Implement sidebar navigation with collapsible sections
    - Add breadcrumb navigation
    - Create responsive layout
    - _Requirements: 8.2_

  - [x] 14.2 Create DocsSearch component at `dashboard/src/components/docs/DocsSearch.tsx`
    - Implement search input with keyboard shortcuts
    - Display search results with relevance ranking
    - Add search result highlighting
    - _Requirements: 8.1, 8.6_

  - [x] 14.3 Create docs index page at `dashboard/src/app/docs/page.tsx`
    - Display documentation categories
    - Show popular guides and quickstart
    - _Requirements: 8.1_

  - [x] 14.4 Create quickstart page at `dashboard/src/app/docs/quickstart/page.tsx`
    - Implement 5-minute integration guide
    - Add step-by-step instructions with code
    - _Requirements: 8.3_

  - [x] 14.5 Write property test for documentation search
    - **Property 8: Documentation search functionality**
    - **Validates: Requirements 8.6**

- [x] 15. Implement API Playground
  - [x] 15.1 Create APIPlayground component at `dashboard/src/components/docs/APIPlayground.tsx`
    - Display endpoint list with methods
    - Implement request parameter inputs
    - Show response with syntax highlighting
    - Display timing information
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [x] 15.2 Create API endpoint data at `dashboard/src/data/apiEndpoints.ts`
    - Define all API endpoints with parameters
    - Add example requests for each endpoint
    - _Requirements: 9.5_

  - [x] 15.3 Create API playground page at `dashboard/src/app/docs/playground/page.tsx`
    - Integrate APIPlayground component
    - Handle API request execution
    - Display error messages on failure
    - _Requirements: 9.1, 9.6_

  - [x] 15.4 Write property test for API playground completeness
    - **Property 9: API playground completeness**
    - **Validates: Requirements 9.5**

  - [x] 15.5 Write property test for error handling
    - **Property 10: Error handling display**
    - **Validates: Requirements 9.6, 13.5**

- [x] 16. Checkpoint - Ensure documentation hub works
  - Ensure all tests pass, ask the user if questions arise.

- [x] 17. Implement Comparison Pages
  - [x] 17.1 Create ComparisonPage component at `dashboard/src/components/marketing/ComparisonPage.tsx`
    - Implement feature-by-feature comparison table
    - Add pricing comparison section
    - Highlight Zalt advantages
    - _Requirements: 10.3, 10.4_

  - [x] 17.2 Create Clerk comparison page at `dashboard/src/app/compare/clerk/page.tsx`
    - Display Clerk vs Zalt comparison
    - Add migration guide section
    - _Requirements: 10.1, 10.5_

  - [x] 17.3 Create Auth0 comparison page at `dashboard/src/app/compare/auth0/page.tsx`
    - Display Auth0 vs Zalt comparison
    - Add migration guide section
    - _Requirements: 10.2, 10.5_

- [x] 18. Implement Blog and Changelog
  - [x] 18.1 Create BlogLayout at `dashboard/src/components/blog/BlogLayout.tsx`
    - Implement article list with categories
    - Add tag filtering
    - _Requirements: 16.4_

  - [x] 18.2 Create BlogCard component at `dashboard/src/components/blog/BlogCard.tsx`
    - Display title, date, author, reading time
    - Add category badge
    - _Requirements: 16.3_

  - [x] 18.3 Create blog index page at `dashboard/src/app/blog/page.tsx`
    - Display article list
    - Implement category filtering
    - _Requirements: 16.1_

  - [x] 18.4 Create changelog page at `dashboard/src/app/changelog/page.tsx`
    - Display updates in reverse chronological order
    - Show version numbers and change types
    - _Requirements: 16.2, 16.5_

  - [x] 18.5 Write property test for blog article structure
    - **Property 18: Blog article structure**
    - **Validates: Requirements 16.3**

  - [x] 18.6 Write property test for changelog ordering
    - **Property 19: Changelog ordering**
    - **Validates: Requirements 16.5**

- [x] 19. Implement Lead Capture Forms
  - [x] 19.1 Create ContactForm component at `dashboard/src/components/forms/ContactForm.tsx`
    - Implement name, email, company, message fields
    - Add client-side validation
    - Display success/error states
    - Retain input on error
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

  - [x] 19.2 Create contact API route at `dashboard/src/app/api/contact/route.ts`
    - Implement rate limiting
    - Validate and process form submissions
    - _Requirements: 13.6_

  - [x] 19.3 Create contact page at `dashboard/src/app/contact/page.tsx`
    - Integrate ContactForm
    - Add company information
    - _Requirements: 13.1_

  - [x] 19.4 Write property test for rate limiting
    - **Property 15: Rate limiting**
    - **Validates: Requirements 13.6**

- [x] 20. Checkpoint - Ensure forms and marketing pages work
  - Ensure all tests pass, ask the user if questions arise.

- [x] 21. Implement Legal Pages
  - [x] 21.1 Create legal page template at `dashboard/src/components/legal/LegalPageLayout.tsx`
    - Implement consistent legal page styling
    - Add table of contents navigation
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

  - [x] 21.2 Create privacy policy page at `dashboard/src/app/privacy/page.tsx`
    - _Requirements: 14.1_

  - [x] 21.3 Create terms of service page at `dashboard/src/app/terms/page.tsx`
    - _Requirements: 14.2_

  - [x] 21.4 Create security policy page at `dashboard/src/app/security/page.tsx`
    - _Requirements: 14.3_

  - [x] 21.5 Create DPA page at `dashboard/src/app/dpa/page.tsx`
    - _Requirements: 14.4_

  - [x] 21.6 Create cookie policy page at `dashboard/src/app/cookies/page.tsx`
    - _Requirements: 14.5_

- [x] 22. Implement SEO and Analytics Integration
  - [x] 22.1 Create SEO component at `dashboard/src/components/shared/SEO.tsx`
    - Implement meta tag rendering
    - Add Open Graph and Twitter Card support
    - Include JSON-LD structured data
    - _Requirements: 11.1, 11.2, 11.3, 11.6_

  - [x] 22.2 Create sitemap generator at `dashboard/src/app/sitemap.ts`
    - Generate sitemap.xml for all public pages
    - _Requirements: 11.4_

  - [x] 22.3 Create robots.txt at `dashboard/public/robots.txt`
    - Add appropriate crawl directives
    - _Requirements: 11.5_

  - [x] 22.4 Integrate analytics across all pages
    - Add GA4 tracking to layout
    - Implement CTA click tracking
    - Add scroll depth tracking
    - _Requirements: 12.1, 12.2, 12.5_

  - [x] 22.5 Write property test for SEO meta tags
    - **Property 11: SEO meta tags presence**
    - **Validates: Requirements 11.1, 11.2, 11.3**

  - [x] 22.6 Write property test for image lazy loading
    - **Property 12: Image lazy loading**
    - **Validates: Requirements 11.8**

  - [x] 22.7 Write property test for analytics tracking
    - **Property 13: Analytics event tracking**
    - **Validates: Requirements 12.2, 12.6**

- [x] 23. Implement Accessibility and Responsive Design
  - [x] 23.1 Add ARIA labels to all interactive elements
    - Audit and add missing labels
    - Ensure screen reader compatibility
    - _Requirements: 15.4_

  - [x] 23.2 Implement keyboard navigation
    - Add focus management
    - Ensure all elements are keyboard accessible
    - _Requirements: 15.3_

  - [x] 23.3 Verify responsive layouts
    - Test at 320px, 768px, 1280px breakpoints
    - Fix any overflow or clipping issues
    - _Requirements: 15.1_

  - [x] 23.4 Verify color contrast
    - Audit all text elements
    - Ensure 4.5:1 minimum contrast ratio
    - _Requirements: 15.5_

  - [x] 23.5 Write property test for responsive layout
    - **Property 16: Responsive layout**
    - **Validates: Requirements 15.1**

  - [x] 23.6 Write property test for accessibility compliance
    - **Property 17: Accessibility compliance**
    - **Validates: Requirements 15.2, 15.3, 15.4, 15.5**

- [x] 24. Final Checkpoint - Complete integration testing
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- All tasks including property tests are required for comprehensive coverage
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- The implementation builds on existing dashboard components and theme system
