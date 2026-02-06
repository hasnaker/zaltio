/**
 * SEO Utility Tests
 */

import {
  seo,
  generateTitle,
  generateCanonicalUrl,
  generateOpenGraph,
  generateTwitterCard,
  generateOrganizationSchema,
  generateSoftwareSchema,
  generateWebPageSchema,
  generateArticleSchema,
  generateFAQSchema,
  generateProductSchema,
  generateBreadcrumbSchema,
  generateMetadata,
  generateJsonLd,
  defaultPageSEO,
  SEOProps,
} from '../seo';

describe('SEO Utility', () => {
  describe('generateTitle', () => {
    it('should generate title with site name', () => {
      const title = generateTitle('Pricing');
      expect(title).toBe('Pricing | Zalt.io');
    });

    it('should generate title without site name when specified', () => {
      const title = generateTitle('Pricing', false);
      expect(title).toBe('Pricing');
    });
  });

  describe('generateCanonicalUrl', () => {
    it('should generate canonical URL with leading slash', () => {
      const url = generateCanonicalUrl('/pricing');
      expect(url).toContain('/pricing');
    });

    it('should add leading slash if missing', () => {
      const url = generateCanonicalUrl('pricing');
      expect(url).toContain('/pricing');
    });
  });

  describe('generateOpenGraph', () => {
    it('should generate Open Graph data with defaults', () => {
      const props: SEOProps = {
        title: 'Test Page',
        description: 'Test description',
      };

      const og = generateOpenGraph(props);

      expect(og.type).toBe('website');
      expect(og.title).toBe('Test Page');
      expect(og.description).toBe('Test description');
      expect(og.siteName).toBe('Zalt.io');
      expect(og.locale).toBe('en_US');
    });

    it('should use custom Open Graph values', () => {
      const props: SEOProps = {
        title: 'Test Page',
        openGraph: {
          type: 'article',
          title: 'Custom OG Title',
          image: 'https://example.com/image.png',
        },
      };

      const og = generateOpenGraph(props);

      expect(og.type).toBe('article');
      expect(og.title).toBe('Custom OG Title');
      expect(og.image).toBe('https://example.com/image.png');
    });

    it('should use default description when not provided', () => {
      const props: SEOProps = {
        title: 'Test Page',
      };

      const og = generateOpenGraph(props);

      expect(og.description).toContain('Enterprise-grade authentication');
    });
  });

  describe('generateTwitterCard', () => {
    it('should generate Twitter Card data with defaults', () => {
      const props: SEOProps = {
        title: 'Test Page',
        description: 'Test description',
      };

      const twitter = generateTwitterCard(props);

      expect(twitter.card).toBe('summary_large_image');
      expect(twitter.site).toBe('@zaltio');
      expect(twitter.creator).toBe('@zaltio');
      expect(twitter.title).toBe('Test Page');
      expect(twitter.description).toBe('Test description');
    });

    it('should use custom Twitter Card values', () => {
      const props: SEOProps = {
        title: 'Test Page',
        twitter: {
          card: 'summary',
          creator: '@customcreator',
        },
      };

      const twitter = generateTwitterCard(props);

      expect(twitter.card).toBe('summary');
      expect(twitter.creator).toBe('@customcreator');
    });
  });

  describe('generateOrganizationSchema', () => {
    it('should generate valid Organization schema', () => {
      const schema = generateOrganizationSchema();

      expect(schema['@context']).toBe('https://schema.org');
      expect(schema['@type']).toBe('Organization');
      expect(schema.name).toBe('Zalt.io');
      expect(schema.url).toBeDefined();
      expect(schema.logo).toBeDefined();
      expect(schema.sameAs).toBeInstanceOf(Array);
      expect(schema.contactPoint).toBeDefined();
    });
  });

  describe('generateSoftwareSchema', () => {
    it('should generate valid SoftwareApplication schema', () => {
      const schema = generateSoftwareSchema();

      expect(schema['@context']).toBe('https://schema.org');
      expect(schema['@type']).toBe('SoftwareApplication');
      expect(schema.applicationCategory).toBe('DeveloperApplication');
      expect(schema.offers).toBeDefined();
      expect(schema.aggregateRating).toBeDefined();
    });
  });

  describe('generateWebPageSchema', () => {
    it('should generate valid WebPage schema', () => {
      const schema = generateWebPageSchema({
        title: 'Test Page',
        description: 'Test description',
        url: 'https://zalt.io/test',
      });

      expect(schema['@context']).toBe('https://schema.org');
      expect(schema['@type']).toBe('WebPage');
      expect(schema.name).toBe('Test Page');
      expect(schema.description).toBe('Test description');
      expect(schema.url).toBe('https://zalt.io/test');
      expect(schema.isPartOf).toBeDefined();
    });

    it('should include dates when provided', () => {
      const schema = generateWebPageSchema({
        title: 'Test Page',
        description: 'Test description',
        url: 'https://zalt.io/test',
        datePublished: '2024-01-01',
        dateModified: '2024-01-15',
      });

      expect(schema.datePublished).toBe('2024-01-01');
      expect(schema.dateModified).toBe('2024-01-15');
    });
  });

  describe('generateArticleSchema', () => {
    it('should generate valid Article schema', () => {
      const schema = generateArticleSchema({
        title: 'Test Article',
        description: 'Article description',
        url: 'https://zalt.io/blog/test',
        image: 'https://zalt.io/images/test.png',
        datePublished: '2024-01-01',
        author: {
          name: 'John Doe',
          url: 'https://twitter.com/johndoe',
        },
      });

      expect(schema['@context']).toBe('https://schema.org');
      expect(schema['@type']).toBe('Article');
      expect(schema.headline).toBe('Test Article');
      expect(schema.author).toBeDefined();
      expect((schema.author as Record<string, unknown>)['@type']).toBe('Person');
      expect(schema.publisher).toBeDefined();
    });

    it('should use datePublished as dateModified when not provided', () => {
      const schema = generateArticleSchema({
        title: 'Test Article',
        description: 'Article description',
        url: 'https://zalt.io/blog/test',
        image: 'https://zalt.io/images/test.png',
        datePublished: '2024-01-01',
        author: { name: 'John Doe' },
      });

      expect(schema.dateModified).toBe('2024-01-01');
    });
  });

  describe('generateFAQSchema', () => {
    it('should generate valid FAQPage schema', () => {
      const faqs = [
        { question: 'What is Zalt?', answer: 'Zalt is an auth platform.' },
        { question: 'How much does it cost?', answer: 'Free tier available.' },
      ];

      const schema = generateFAQSchema(faqs);

      expect(schema['@context']).toBe('https://schema.org');
      expect(schema['@type']).toBe('FAQPage');
      expect(schema.mainEntity).toBeInstanceOf(Array);
      expect((schema.mainEntity as unknown[]).length).toBe(2);
    });
  });

  describe('generateProductSchema', () => {
    it('should generate valid Product schema', () => {
      const schema = generateProductSchema({
        name: 'Zalt Pro',
        description: 'Professional authentication plan',
        price: 49,
      });

      expect(schema['@context']).toBe('https://schema.org');
      expect(schema['@type']).toBe('Product');
      expect(schema.name).toBe('Zalt Pro');
      expect(schema.offers).toBeDefined();
      expect((schema.offers as Record<string, unknown>).price).toBe(49);
    });

    it('should use custom currency', () => {
      const schema = generateProductSchema({
        name: 'Zalt Pro',
        description: 'Professional plan',
        price: 49,
        priceCurrency: 'EUR',
      });

      expect((schema.offers as Record<string, unknown>).priceCurrency).toBe('EUR');
    });
  });

  describe('generateBreadcrumbSchema', () => {
    it('should generate valid BreadcrumbList schema', () => {
      const items = [
        { name: 'Home', url: '/' },
        { name: 'Docs', url: '/docs' },
        { name: 'Quickstart', url: '/docs/quickstart' },
      ];

      const schema = generateBreadcrumbSchema(items);

      expect(schema['@context']).toBe('https://schema.org');
      expect(schema['@type']).toBe('BreadcrumbList');
      expect(schema.itemListElement).toBeInstanceOf(Array);
      expect((schema.itemListElement as unknown[]).length).toBe(3);
    });

    it('should set correct positions', () => {
      const items = [
        { name: 'Home', url: '/' },
        { name: 'Docs', url: '/docs' },
      ];

      const schema = generateBreadcrumbSchema(items);
      const elements = schema.itemListElement as Array<Record<string, unknown>>;

      expect(elements[0].position).toBe(1);
      expect(elements[1].position).toBe(2);
    });
  });

  describe('generateMetadata', () => {
    it('should generate complete Next.js Metadata object', () => {
      const props: SEOProps = {
        title: 'Test Page',
        description: 'Test description',
        canonical: '/test',
      };

      const metadata = generateMetadata(props);

      expect(metadata.title).toBe('Test Page | Zalt.io');
      expect(metadata.description).toBe('Test description');
      expect(metadata.alternates?.canonical).toContain('/test');
      expect(metadata.openGraph).toBeDefined();
      expect(metadata.twitter).toBeDefined();
    });

    it('should set noIndex when specified', () => {
      const props: SEOProps = {
        title: 'Private Page',
        noIndex: true,
      };

      const metadata = generateMetadata(props);

      expect(metadata.robots).toEqual({ index: false, follow: false });
    });

    it('should include article metadata for articles', () => {
      const props: SEOProps = {
        title: 'Blog Post',
        openGraph: {
          type: 'article',
          article: {
            publishedTime: '2024-01-01',
            author: 'John Doe',
            tags: ['auth', 'security'],
          },
        },
      };

      const metadata = generateMetadata(props);

      expect(metadata.openGraph?.type).toBe('article');
      expect(metadata.openGraph?.publishedTime).toBe('2024-01-01');
      expect(metadata.openGraph?.tags).toContain('auth');
    });
  });

  describe('generateJsonLd', () => {
    it('should stringify single schema', () => {
      const schema = generateOrganizationSchema();
      const jsonLd = generateJsonLd(schema);

      expect(typeof jsonLd).toBe('string');
      expect(JSON.parse(jsonLd)['@type']).toBe('Organization');
    });

    it('should stringify array of schemas', () => {
      const schemas = [
        generateOrganizationSchema(),
        generateSoftwareSchema(),
      ];
      const jsonLd = generateJsonLd(schemas);

      expect(typeof jsonLd).toBe('string');
      const parsed = JSON.parse(jsonLd);
      expect(parsed).toBeInstanceOf(Array);
      expect(parsed.length).toBe(2);
    });
  });

  describe('defaultPageSEO', () => {
    it('should have home page SEO', () => {
      expect(defaultPageSEO.home).toBeDefined();
      expect(defaultPageSEO.home.title).toBeDefined();
      expect(defaultPageSEO.home.canonical).toBe('/');
    });

    it('should have pricing page SEO', () => {
      expect(defaultPageSEO.pricing).toBeDefined();
      expect(defaultPageSEO.pricing.canonical).toBe('/pricing');
    });

    it('should have docs page SEO', () => {
      expect(defaultPageSEO.docs).toBeDefined();
      expect(defaultPageSEO.docs.canonical).toBe('/docs');
    });

    it('should have blog page SEO', () => {
      expect(defaultPageSEO.blog).toBeDefined();
      expect(defaultPageSEO.blog.canonical).toBe('/blog');
    });

    it('should have contact page SEO', () => {
      expect(defaultPageSEO.contact).toBeDefined();
      expect(defaultPageSEO.contact.canonical).toBe('/contact');
    });
  });

  describe('seo object export', () => {
    it('should export all functions', () => {
      expect(seo.generateTitle).toBeDefined();
      expect(seo.generateCanonicalUrl).toBeDefined();
      expect(seo.generateOpenGraph).toBeDefined();
      expect(seo.generateTwitterCard).toBeDefined();
      expect(seo.generateOrganizationSchema).toBeDefined();
      expect(seo.generateSoftwareSchema).toBeDefined();
      expect(seo.generateWebPageSchema).toBeDefined();
      expect(seo.generateArticleSchema).toBeDefined();
      expect(seo.generateFAQSchema).toBeDefined();
      expect(seo.generateProductSchema).toBeDefined();
      expect(seo.generateBreadcrumbSchema).toBeDefined();
      expect(seo.generateMetadata).toBeDefined();
      expect(seo.generateJsonLd).toBeDefined();
      expect(seo.defaultPageSEO).toBeDefined();
    });
  });
});
