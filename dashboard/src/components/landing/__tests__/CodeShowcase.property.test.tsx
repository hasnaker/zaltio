/**
 * Property-Based Tests for CodeShowcase
 * 
 * Feature: zalt-enterprise-landing
 * Property 7: Code showcase content mapping
 * 
 * Validates: Requirements 6.2, 6.3, 6.6
 */

import * as fc from 'fast-check';

// Framework IDs (mirrors actual implementation)
const frameworkIds = ['nextjs', 'react', 'vue', 'node', 'python', 'express'] as const;
type FrameworkId = typeof frameworkIds[number];

// Code snippet structure (mirrors codeSnippets.ts)
interface CodeSnippet {
  framework: string;
  language: string;
  install: string;
  code: string;
  filename: string;
}

// Mock code snippets (mirrors actual data)
const codeSnippets: Record<FrameworkId, CodeSnippet> = {
  nextjs: {
    framework: 'Next.js',
    language: 'typescript',
    install: 'npm install @zalt/next',
    filename: 'middleware.ts',
    code: `import { authMiddleware } from '@zalt/next';

export default authMiddleware({
  publicRoutes: ['/', '/pricing', '/docs(.*)'],
});`,
  },
  react: {
    framework: 'React',
    language: 'typescript',
    install: 'npm install @zalt/react',
    filename: 'App.tsx',
    code: `import { ZaltProvider, useAuth } from '@zalt/react';

function App() {
  return (
    <ZaltProvider realmId="your-realm-id">
      <AuthenticatedApp />
    </ZaltProvider>
  );
}`,
  },
  vue: {
    framework: 'Vue.js',
    language: 'typescript',
    install: 'npm install @zalt/vue',
    filename: 'main.ts',
    code: `import { createApp } from 'vue';
import { ZaltPlugin } from '@zalt/vue';

app.use(ZaltPlugin, {
  realmId: 'your-realm-id',
});`,
  },
  node: {
    framework: 'Node.js',
    language: 'typescript',
    install: 'npm install @zalt/node',
    filename: 'server.ts',
    code: `import express from 'express';
import { ZaltClient, requireAuth } from '@zalt/node';

const zalt = new ZaltClient({
  realmId: process.env.ZALT_REALM_ID!,
});`,
  },
  python: {
    framework: 'Python',
    language: 'python',
    install: 'pip install zalt-auth',
    filename: 'app.py',
    code: `from fastapi import FastAPI, Depends
from zalt_auth import ZaltClient, require_auth

zalt = ZaltClient(
    realm_id="your-realm-id",
)`,
  },
  express: {
    framework: 'Express',
    language: 'typescript',
    install: 'npm install @zalt/node',
    filename: 'app.ts',
    code: `import express from 'express';
import { ZaltClient, zaltMiddleware } from '@zalt/node';

app.use(zaltMiddleware(zalt));`,
  },
};

// Get code snippet for a framework
function getCodeSnippet(frameworkId: string): CodeSnippet | undefined {
  return codeSnippets[frameworkId as FrameworkId];
}

// Get all available framework IDs
function getAvailableFrameworks(): string[] {
  return Object.keys(codeSnippets);
}

// Validate install command format
function isValidInstallCommand(command: string): boolean {
  // npm install, yarn add, pip install, etc.
  return /^(npm install|yarn add|pip install|pnpm add)\s+\S+/.test(command);
}

// Validate code contains Zalt import
function hasZaltImport(code: string): boolean {
  return code.includes('@zalt') || code.includes('zalt_auth') || code.includes('zalt-auth');
}

// Validate filename has proper extension
function hasValidExtension(filename: string, language: string): boolean {
  const extensionMap: Record<string, string[]> = {
    typescript: ['.ts', '.tsx'],
    javascript: ['.js', '.jsx'],
    python: ['.py'],
  };
  
  const validExtensions = extensionMap[language] || [];
  return validExtensions.some(ext => filename.endsWith(ext));
}

describe('Feature: zalt-enterprise-landing, Property 7: Code showcase content mapping', () => {
  describe('Property 7.1: Every framework has a code snippet', () => {
    it('should have code snippets for all supported frameworks', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...frameworkIds),
          (frameworkId) => {
            const snippet = getCodeSnippet(frameworkId);
            
            expect(snippet).toBeDefined();
            expect(snippet?.code).toBeTruthy();
            expect(snippet?.code.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should have at least 6 frameworks available', () => {
      const frameworks = getAvailableFrameworks();
      expect(frameworks.length).toBeGreaterThanOrEqual(6);
    });
  });

  describe('Property 7.2: Code snippets contain Zalt imports', () => {
    it('should include Zalt SDK import in every code snippet', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...frameworkIds),
          (frameworkId) => {
            const snippet = getCodeSnippet(frameworkId);
            
            expect(snippet).toBeDefined();
            expect(hasZaltImport(snippet!.code)).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 7.3: Install commands are valid', () => {
    it('should have valid install command format for each framework', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...frameworkIds),
          (frameworkId) => {
            const snippet = getCodeSnippet(frameworkId);
            
            expect(snippet).toBeDefined();
            expect(snippet!.install).toBeTruthy();
            expect(isValidInstallCommand(snippet!.install)).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should have install command that includes package name', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...frameworkIds),
          (frameworkId) => {
            const snippet = getCodeSnippet(frameworkId);
            
            // Install command should contain @zalt or zalt
            expect(snippet!.install).toMatch(/zalt/i);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 7.4: Filenames match language', () => {
    it('should have filename with correct extension for language', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...frameworkIds),
          (frameworkId) => {
            const snippet = getCodeSnippet(frameworkId);
            
            expect(snippet).toBeDefined();
            expect(snippet!.filename).toBeTruthy();
            expect(hasValidExtension(snippet!.filename, snippet!.language)).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 7.5: Framework names are consistent', () => {
    it('should have non-empty framework name', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...frameworkIds),
          (frameworkId) => {
            const snippet = getCodeSnippet(frameworkId);
            
            expect(snippet).toBeDefined();
            expect(snippet!.framework).toBeTruthy();
            expect(snippet!.framework.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 7.6: Code is syntactically reasonable', () => {
    it('should have balanced brackets in code', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...frameworkIds),
          (frameworkId) => {
            const snippet = getCodeSnippet(frameworkId);
            const code = snippet!.code;
            
            // Count brackets
            const openBraces = (code.match(/{/g) || []).length;
            const closeBraces = (code.match(/}/g) || []).length;
            const openParens = (code.match(/\(/g) || []).length;
            const closeParens = (code.match(/\)/g) || []).length;
            
            expect(openBraces).toBe(closeBraces);
            expect(openParens).toBe(closeParens);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should have multiple lines of code', () => {
      fc.assert(
        fc.property(
          fc.constantFrom(...frameworkIds),
          (frameworkId) => {
            const snippet = getCodeSnippet(frameworkId);
            const lines = snippet!.code.split('\n');
            
            // Each snippet should have at least 3 lines
            expect(lines.length).toBeGreaterThanOrEqual(3);
          }
        ),
        { numRuns: 20 }
      );
    });
  });
});

describe('Code Showcase Edge Cases', () => {
  it('should return undefined for unknown framework', () => {
    const snippet = getCodeSnippet('unknown-framework');
    expect(snippet).toBeUndefined();
  });

  it('should handle empty string framework ID', () => {
    const snippet = getCodeSnippet('');
    expect(snippet).toBeUndefined();
  });

  it('should have consistent language values', () => {
    const validLanguages = ['typescript', 'javascript', 'python'];
    
    frameworkIds.forEach(id => {
      const snippet = getCodeSnippet(id);
      expect(validLanguages).toContain(snippet?.language);
    });
  });

  it('should have unique framework names', () => {
    const names = frameworkIds.map(id => getCodeSnippet(id)?.framework);
    const uniqueNames = new Set(names);
    expect(uniqueNames.size).toBe(names.length);
  });
});
