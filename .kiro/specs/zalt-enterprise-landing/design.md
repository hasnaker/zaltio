# Design Document: Zalt Enterprise Landing Page

## Overview

The Zalt.io Enterprise Landing Page is a Next.js 14 application built with TypeScript, Tailwind CSS, and Framer Motion. It serves as the primary marketing and documentation platform for Zalt.io, designed to convert enterprise prospects into customers through compelling visuals, interactive demos, and comprehensive documentation.

The design follows the existing Clerk-style theme system already established in the dashboard, extending it with new marketing-focused components while maintaining visual consistency.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Next.js 14 App Router                     │
├─────────────────────────────────────────────────────────────────┤
│  Pages                                                           │
│  ├── / (Landing Page)                                           │
│  ├── /docs/* (Documentation Hub)                                │
│  ├── /pricing (Pricing Page)                                    │
│  ├── /compare/* (Comparison Pages)                              │
│  ├── /blog/* (Blog)                                             │
│  ├── /changelog (Changelog)                                     │
│  └── /legal/* (Privacy, Terms, Security, DPA)                   │
├─────────────────────────────────────────────────────────────────┤
│  Components                                                      │
│  ├── landing/ (Hero, Features, Pricing, Testimonials, etc.)     │
│  ├── docs/ (DocsSidebar, SearchBar, CodeBlock, APIPlayground)   │
│  ├── ui/ (Button, Card, Input, Badge, etc.)                     │
│  └── shared/ (Navbar, Footer, SEO, Analytics)                   │
├─────────────────────────────────────────────────────────────────┤
│  Libraries                                                       │
│  ├── motion.ts (Framer Motion utilities)                        │
│  ├── analytics.ts (GA4, conversion tracking)                    │
│  ├── seo.ts (Meta tags, structured data)                        │
│  └── utils.ts (Helpers, cn(), formatters)                       │
├─────────────────────────────────────────────────────────────────┤
│  Styles                                                          │
│  ├── globals.css (Tailwind base, custom properties)             │
│  ├── clerk-theme.ts (Design tokens)                             │
│  └── tailwind.config.js (Extended theme)                        │
└─────────────────────────────────────────────────────────────────┘
```

### Page Structure

```
Landing Page (/)
├── Navbar (sticky)
├── HeroSection
│   ├── AnimatedHeadline
│   ├── SecurityLockAnimation
│   ├── DeviceMockups
│   └── CTAButtons
├── ComponentPreviewSection
│   ├── SignInPreview
│   ├── SignUpPreview
│   ├── UserButtonPreview
│   └── ThemeCustomizer
├── FeaturesSection
│   ├── FeatureCards (6)
│   ├── SecurityVisualization
│   └── StatsCounter
├── OrganizationsSection
│   ├── OrgHierarchyViz
│   └── RBACDemo
├── PricingSection
│   ├── BillingToggle
│   ├── PricingCards (3)
│   └── PricingCalculator
├── FrameworksSection
│   ├── LogoGrid
│   └── CodeShowcase
├── TestimonialsSection
│   ├── TestimonialCards
│   └── TrustBadges
├── FinalCTA
└── Footer
```

## Components and Interfaces

### Core Landing Components

```typescript
// Hero Section Component
interface HeroSectionProps {
  headline: string;
  subheadline: string;
  primaryCTA: CTAButton;
  secondaryCTA: CTAButton;
}

interface CTAButton {
  label: string;
  href: string;
  variant: 'primary' | 'secondary' | 'outline';
}

// Component Preview Section
interface ComponentPreviewProps {
  activeComponent: 'signin' | 'signup' | 'userbutton' | 'orgswitcher';
  theme: ThemeConfig;
  onThemeChange: (theme: ThemeConfig) => void;
}

interface ThemeConfig {
  primaryColor: string;
  accentColor: string;
  borderRadius: 'sm' | 'md' | 'lg' | 'xl';
  darkMode: boolean;
}

// Features Section
interface Feature {
  id: string;
  icon: React.ComponentType;
  title: string;
  description: string;
  gradient: string;
  learnMoreHref: string;
}

interface FeaturesSectionProps {
  features: Feature[];
  stats: StatItem[];
}

interface StatItem {
  value: string;
  label: string;
  animateFrom?: number;
}

// Pricing Section
interface PricingPlan {
  id: string;
  name: string;
  description: string;
  price: {
    monthly: number | 'Custom';
    annual: number | 'Custom';
  };
  features: string[];
  highlighted?: boolean;
  badge?: string;
  cta: CTAButton;
}

interface PricingCalculatorProps {
  mau: number;
  onMAUChange: (mau: number) => void;
  selectedPlan: string;
}

// Code Showcase
interface CodeShowcaseProps {
  framework: Framework;
  snippets: CodeSnippet[];
  onFrameworkChange: (framework: Framework) => void;
}

interface CodeSnippet {
  language: string;
  code: string;
  filename: string;
}

type Framework = 'nextjs' | 'react' | 'vue' | 'angular' | 'svelte' | 'python' | 'go' | 'ruby' | 'php';

// Testimonials
interface Testimonial {
  id: string;
  quote: string;
  author: {
    name: string;
    title: string;
    company: string;
    avatar: string;
  };
  companyLogo: string;
}
```

### Documentation Components

```typescript
// Documentation Hub
interface DocsLayoutProps {
  children: React.ReactNode;
  sidebar: SidebarSection[];
  breadcrumbs: Breadcrumb[];
}

interface SidebarSection {
  title: string;
  items: SidebarItem[];
  collapsed?: boolean;
}

interface SidebarItem {
  label: string;
  href: string;
  icon?: React.ComponentType;
  badge?: string;
}

// Search
interface SearchResult {
  title: string;
  excerpt: string;
  href: string;
  section: string;
  relevanceScore: number;
}

interface DocsSearchProps {
  onSearch: (query: string) => Promise<SearchResult[]>;
  placeholder?: string;
}

// API Playground
interface APIEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  description: string;
  parameters: APIParameter[];
  requestBody?: JSONSchema;
  responses: APIResponse[];
}

interface APIParameter {
  name: string;
  in: 'path' | 'query' | 'header';
  required: boolean;
  type: string;
  description: string;
}

interface APIResponse {
  status: number;
  description: string;
  schema: JSONSchema;
  example: object;
}

interface APIPlaygroundProps {
  endpoint: APIEndpoint;
  onExecute: (request: APIRequest) => Promise<APIResponseResult>;
}

interface APIRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: object;
}

interface APIResponseResult {
  status: number;
  headers: Record<string, string>;
  body: object;
  timing: number;
}
```

### Shared Components

```typescript
// Navigation
interface NavbarProps {
  logo: string;
  menuItems: MenuItem[];
  ctaButtons: CTAButton[];
  sticky?: boolean;
}

interface MenuItem {
  label: string;
  href?: string;
  dropdown?: DropdownSection[];
}

interface DropdownSection {
  title?: string;
  items: DropdownItem[];
}

interface DropdownItem {
  label: string;
  description?: string;
  href: string;
  icon?: React.ComponentType;
}

// Footer
interface FooterProps {
  logo: string;
  columns: FooterColumn[];
  socialLinks: SocialLink[];
  complianceBadges: string[];
  newsletter: boolean;
}

interface FooterColumn {
  title: string;
  links: FooterLink[];
}

// SEO
interface SEOProps {
  title: string;
  description: string;
  canonical?: string;
  openGraph?: OpenGraphData;
  twitter?: TwitterCardData;
  jsonLd?: StructuredData[];
}

interface OpenGraphData {
  type: 'website' | 'article';
  title: string;
  description: string;
  image: string;
  url: string;
}

// Analytics
interface AnalyticsEvent {
  name: string;
  category: string;
  action: string;
  label?: string;
  value?: number;
  customDimensions?: Record<string, string>;
}

// Lead Capture Form
interface LeadFormData {
  name: string;
  email: string;
  company: string;
  message: string;
  source?: string;
}

interface LeadFormProps {
  onSubmit: (data: LeadFormData) => Promise<void>;
  submitLabel?: string;
  showCompanyField?: boolean;
  showMessageField?: boolean;
}
```

### Motion System

```typescript
// Animation Variants
interface MotionConfig {
  reducedMotion: boolean;
  defaultDuration: number;
  defaultEasing: string;
}

// Scroll Animation Hook
interface UseScrollAnimationOptions {
  threshold?: number;
  once?: boolean;
  rootMargin?: string;
}

interface ScrollAnimationResult {
  ref: React.RefObject<HTMLElement>;
  isInView: boolean;
  controls: AnimationControls;
}

// Predefined Variants
const fadeInUp: Variants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0 }
};

const staggerContainer: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1 }
  }
};
```

## Data Models

### Content Models

```typescript
// Blog Post
interface BlogPost {
  slug: string;
  title: string;
  excerpt: string;
  content: string; // MDX
  author: Author;
  publishedAt: Date;
  updatedAt?: Date;
  category: string;
  tags: string[];
  readingTime: number; // minutes
  featured: boolean;
  coverImage: string;
}

interface Author {
  name: string;
  avatar: string;
  title: string;
  twitter?: string;
}

// Changelog Entry
interface ChangelogEntry {
  version: string;
  date: Date;
  title: string;
  description: string;
  changes: Change[];
  breaking?: boolean;
}

interface Change {
  type: 'feature' | 'improvement' | 'fix' | 'deprecation';
  description: string;
  prNumber?: number;
}

// Documentation Page
interface DocPage {
  slug: string;
  title: string;
  description: string;
  content: string; // MDX
  section: string;
  order: number;
  lastUpdated: Date;
  contributors: string[];
}

// Comparison Data
interface ComparisonData {
  competitor: string;
  features: ComparisonFeature[];
  pricing: PricingComparison;
  migrationGuide: string; // MDX
}

interface ComparisonFeature {
  name: string;
  category: string;
  zalt: FeatureSupport;
  competitor: FeatureSupport;
  notes?: string;
}

type FeatureSupport = 'full' | 'partial' | 'none' | 'enterprise';
```

### Analytics Models

```typescript
// Page View
interface PageView {
  path: string;
  title: string;
  referrer?: string;
  timestamp: Date;
  sessionId: string;
  userId?: string;
}

// Conversion Event
interface ConversionEvent {
  type: 'signup' | 'lead' | 'demo_request' | 'pricing_view';
  source: string;
  medium?: string;
  campaign?: string;
  timestamp: Date;
  metadata?: Record<string, string>;
}

// A/B Test Variant
interface ABTestVariant {
  testId: string;
  variantId: string;
  userId: string;
  assignedAt: Date;
  converted: boolean;
  conversionAt?: Date;
}
```

### Form Models

```typescript
// Contact Form Submission
interface ContactSubmission {
  id: string;
  name: string;
  email: string;
  company?: string;
  message: string;
  source: string;
  submittedAt: Date;
  ipAddress?: string; // hashed for rate limiting
  status: 'pending' | 'processed' | 'spam';
}

// Newsletter Subscription
interface NewsletterSubscription {
  email: string;
  subscribedAt: Date;
  source: string;
  confirmed: boolean;
  confirmedAt?: Date;
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*



### Property 1: Reduced Motion Support

*For any* animated component in the application, when the user has `prefers-reduced-motion: reduce` enabled, the component SHALL render without animations and without animation delays.

**Validates: Requirements 1.6, 15.6, 18.6**

### Property 2: Component Preview Isolation

*For any* user interaction with preview components (SignIn, SignUp, UserButton, OrganizationSwitcher), the system SHALL NOT make any real API calls to the backend.

**Validates: Requirements 2.5**

### Property 3: Theme Synchronization

*For any* theme configuration change in the theme customizer, ALL preview components SHALL update their styling to reflect the new theme values within the same render cycle.

**Validates: Requirements 2.7**

### Property 4: Pricing Tier Count Invariant

*For any* render of the pricing section, exactly THREE pricing tiers (Free, Pro, Enterprise) SHALL be displayed.

**Validates: Requirements 5.1**

### Property 5: Billing Toggle State Change

*For any* toggle between monthly and annual billing, the displayed prices SHALL update to reflect the correct billing period with annual prices showing a 20% discount.

**Validates: Requirements 5.3**

### Property 6: Pricing Calculator Accuracy

*For any* valid MAU (Monthly Active Users) input value, the pricing calculator SHALL display the correct estimated monthly and annual costs based on the pricing formula.

**Validates: Requirements 5.5**

### Property 7: Code Showcase Content Mapping

*For any* framework selection (Next.js, React, Vue, Angular, Svelte, Python, Go, Ruby, PHP), the code showcase SHALL display:
- Framework-specific integration code
- Syntax highlighting appropriate to the language
- Correct installation commands for the SDK

**Validates: Requirements 6.2, 6.3, 6.6**

### Property 8: Documentation Search Functionality

*For any* non-empty search query in the documentation hub, the search SHALL return relevant results sorted by relevance score.

**Validates: Requirements 8.6**

### Property 9: API Playground Completeness

*For any* API endpoint displayed in the playground, example requests with valid parameters SHALL be available.

**Validates: Requirements 9.5**

### Property 10: Error Handling Display

*For any* failed operation (API request failure, form submission failure), the system SHALL display a descriptive error message and retain user input where applicable.

**Validates: Requirements 9.6, 13.5**

### Property 11: SEO Meta Tags Presence

*For any* public page in the application, the page SHALL include:
- Meta title and description tags
- Open Graph tags (og:title, og:description, og:image, og:url)
- Twitter Card meta tags (twitter:card, twitter:title, twitter:description)

**Validates: Requirements 11.1, 11.2, 11.3**

### Property 12: Image Lazy Loading

*For any* image element below the initial viewport fold, the image SHALL have `loading="lazy"` attribute applied.

**Validates: Requirements 11.8**

### Property 13: Analytics Event Tracking

*For any* CTA button click or form submission, an analytics event SHALL be fired with appropriate event name, category, and action.

**Validates: Requirements 12.2, 12.6**

### Property 14: Form Validation

*For any* form input:
- Invalid email formats SHALL be rejected with validation error
- Empty required fields SHALL be rejected with validation error
- Valid inputs SHALL pass validation

**Validates: Requirements 13.2, 13.3, 17.6**

### Property 15: Rate Limiting

*For any* form submission endpoint, requests exceeding the rate limit threshold SHALL be rejected with an appropriate error message.

**Validates: Requirements 13.6**

### Property 16: Responsive Layout

*For any* viewport width (320px mobile, 768px tablet, 1280px+ desktop), the layout SHALL adapt appropriately without horizontal overflow or content clipping.

**Validates: Requirements 15.1**

### Property 17: Accessibility Compliance

*For any* interactive element:
- Keyboard navigation SHALL be functional (focusable, activatable)
- ARIA labels SHALL be present for screen readers
- Color contrast ratio SHALL meet minimum 4.5:1 for text

**Validates: Requirements 15.2, 15.3, 15.4, 15.5**

### Property 18: Blog Article Structure

*For any* blog article, the rendered output SHALL include: title, publication date, author name, and reading time estimate.

**Validates: Requirements 16.3**

### Property 19: Changelog Ordering

*For any* changelog page render, entries SHALL be displayed in reverse chronological order (newest first) with version numbers.

**Validates: Requirements 16.5**

## Error Handling

### Client-Side Errors

```typescript
// Form validation errors
interface ValidationError {
  field: string;
  message: string;
  code: 'required' | 'invalid_format' | 'too_short' | 'too_long';
}

// API errors
interface APIError {
  status: number;
  message: string;
  code: string;
  details?: Record<string, unknown>;
}

// Error boundary for component failures
interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
  errorInfo?: React.ErrorInfo;
}
```

### Error Handling Strategies

1. **Form Validation**: Client-side validation with immediate feedback, server-side validation as backup
2. **API Playground Errors**: Display error response with status code and message, retain request for retry
3. **Component Render Errors**: Error boundaries catch failures, display fallback UI
4. **Network Errors**: Retry with exponential backoff, show offline indicator
5. **Rate Limiting**: Display friendly message with retry countdown

### Error Messages

```typescript
const errorMessages = {
  validation: {
    required: 'This field is required',
    invalidEmail: 'Please enter a valid email address',
    invalidPhone: 'Please enter a valid phone number',
  },
  api: {
    networkError: 'Unable to connect. Please check your internet connection.',
    serverError: 'Something went wrong. Please try again later.',
    rateLimited: 'Too many requests. Please wait before trying again.',
  },
  form: {
    submitFailed: 'Failed to submit. Please try again.',
    submitSuccess: 'Thank you! We\'ll be in touch soon.',
  },
};
```

## Testing Strategy

### Dual Testing Approach

The testing strategy employs both unit tests and property-based tests for comprehensive coverage:

- **Unit tests**: Verify specific examples, edge cases, and integration points
- **Property tests**: Verify universal properties across all valid inputs using fast-check

### Property-Based Testing Configuration

- **Library**: fast-check (already in project dependencies)
- **Minimum iterations**: 100 per property test
- **Tag format**: `Feature: zalt-enterprise-landing, Property {number}: {property_text}`

### Test Categories

#### 1. Component Unit Tests
- Render tests for all landing page sections
- Interaction tests for buttons, forms, toggles
- Snapshot tests for visual regression

#### 2. Property Tests (fast-check)
```typescript
// Example: Form validation property test
describe('Form Validation Properties', () => {
  it('Property 14: rejects invalid email formats', () => {
    fc.assert(
      fc.property(
        fc.string().filter(s => !s.includes('@') || !s.includes('.')),
        (invalidEmail) => {
          const result = validateEmail(invalidEmail);
          return result.valid === false;
        }
      ),
      { numRuns: 100 }
    );
  });
});
```

#### 3. Accessibility Tests
- axe-core integration for WCAG compliance
- Keyboard navigation tests
- Screen reader compatibility tests

#### 4. Visual Regression Tests
- Responsive layout tests at breakpoints
- Theme consistency tests
- Animation state tests

### Test File Structure

```
dashboard/src/
├── components/
│   └── landing/
│       ├── __tests__/
│       │   ├── HeroSection.test.tsx
│       │   ├── HeroSection.property.test.tsx
│       │   ├── PricingSection.test.tsx
│       │   ├── PricingSection.property.test.tsx
│       │   ├── CodeShowcase.test.tsx
│       │   ├── CodeShowcase.property.test.tsx
│       │   └── ...
├── lib/
│   └── __tests__/
│       ├── analytics.test.ts
│       ├── seo.test.ts
│       └── validation.property.test.ts
└── app/
    └── __tests__/
        ├── page.test.tsx
        └── accessibility.test.tsx
```

### Coverage Requirements

- Minimum 80% code coverage for new components
- 100% coverage for validation and calculation logic
- All 19 correctness properties implemented as property tests
