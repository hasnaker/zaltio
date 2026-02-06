# Contributing to HSD Auth Platform

Thank you for your interest in contributing to the HSD Auth Platform!

## Development Setup

### Prerequisites

- Node.js 18+
- Python 3.9+ (for Python SDK)
- AWS CLI configured
- Docker (optional, for local testing)

### Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/hsd/auth-platform.git
   cd auth-platform
   ```

2. **Install dependencies**
   ```bash
   npm install
   cd dashboard && npm install && cd ..
   ```

3. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run tests**
   ```bash
   npm test
   ```

## Project Structure

```
zalt-platform/
├── src/
│   ├── config/          # Configuration
│   ├── docs/            # Documentation
│   ├── handlers/        # Lambda handlers
│   ├── middleware/      # Middleware
│   ├── models/          # Data models
│   ├── repositories/    # Database access
│   ├── sdk/             # JavaScript SDK
│   │   └── python/      # Python SDK
│   ├── services/        # Business logic
│   └── utils/           # Utilities
├── dashboard/           # Next.js dashboard
├── scripts/             # Deployment scripts
└── .kiro/specs/         # Feature specifications
```

## Coding Standards

### TypeScript

- Use TypeScript for all new code
- Enable strict mode
- Use interfaces for data structures
- Document public APIs with JSDoc

```typescript
/**
 * Authenticates a user with email and password
 * @param email - User's email address
 * @param password - User's password
 * @returns Authentication result with user and tokens
 * @throws AuthError if authentication fails
 */
async function login(email: string, password: string): Promise<AuthResult> {
  // Implementation
}
```

### Python

- Follow PEP 8 style guide
- Use type hints
- Document with docstrings

```python
def login(email: str, password: str) -> AuthResult:
    """
    Authenticates a user with email and password.
    
    Args:
        email: User's email address
        password: User's password
        
    Returns:
        AuthResult with user and tokens
        
    Raises:
        AuthError: If authentication fails
    """
    # Implementation
```

### React/Next.js

- Use functional components with hooks
- Use TypeScript for all components
- Follow React best practices

```tsx
interface ButtonProps {
  label: string;
  onClick: () => void;
  disabled?: boolean;
}

export function Button({ label, onClick, disabled = false }: ButtonProps) {
  return (
    <button onClick={onClick} disabled={disabled}>
      {label}
    </button>
  );
}
```

## Testing

### Unit Tests

- Write tests for all new functionality
- Use Jest for JavaScript/TypeScript
- Use pytest for Python
- Aim for 80%+ coverage

```typescript
describe('AuthService', () => {
  describe('login', () => {
    it('should return user and tokens for valid credentials', async () => {
      const result = await authService.login('user@example.com', 'password');
      expect(result.user).toBeDefined();
      expect(result.tokens.accessToken).toBeDefined();
    });

    it('should throw AuthError for invalid credentials', async () => {
      await expect(
        authService.login('user@example.com', 'wrong')
      ).rejects.toThrow(AuthError);
    });
  });
});
```

### Property-Based Tests

- Use fast-check for JavaScript
- Use Hypothesis for Python
- Test invariants and edge cases

```typescript
import fc from 'fast-check';

describe('Password validation', () => {
  it('should accept all valid passwords', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 8, maxLength: 128 }),
        (password) => {
          // Property: valid passwords should be accepted
          const result = validatePassword(password);
          return result.isValid || result.errors.length > 0;
        }
      )
    );
  });
});
```

### Running Tests

```bash
# All tests
npm test

# With coverage
npm test -- --coverage

# Specific file
npm test -- src/services/auth.service.test.ts

# Watch mode
npm test -- --watch
```

## Git Workflow

### Branches

- `main` - Production-ready code
- `develop` - Integration branch
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `hotfix/*` - Production hotfixes

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `style` - Formatting
- `refactor` - Code restructuring
- `test` - Adding tests
- `chore` - Maintenance

Examples:
```
feat(auth): add MFA support
fix(sdk): handle token refresh race condition
docs(api): update login endpoint documentation
```

### Pull Requests

1. Create feature branch from `develop`
2. Make changes and commit
3. Push branch and create PR
4. Request review from team
5. Address feedback
6. Merge after approval

PR checklist:
- [ ] Tests pass
- [ ] Code follows style guide
- [ ] Documentation updated
- [ ] No security vulnerabilities
- [ ] Reviewed by at least one team member

## Documentation

### Code Documentation

- Document all public APIs
- Include examples in docstrings
- Keep documentation up to date

### User Documentation

- Update relevant docs in `src/docs/`
- Include code examples
- Test all examples work

## Security

### Reporting Vulnerabilities

- Email: security@hsdcore.com
- Do NOT create public issues for security vulnerabilities
- Include detailed reproduction steps

### Security Guidelines

- Never commit secrets or credentials
- Use environment variables for configuration
- Validate all user input
- Use parameterized queries
- Follow OWASP guidelines

## Code Review

### What We Look For

- Correctness - Does it work?
- Security - Is it secure?
- Performance - Is it efficient?
- Readability - Is it clear?
- Maintainability - Is it easy to change?
- Tests - Is it tested?

### Giving Feedback

- Be constructive and specific
- Explain the "why"
- Suggest alternatives
- Acknowledge good work

## Release Process

1. Create release branch from `develop`
2. Update version numbers
3. Update CHANGELOG.md
4. Create PR to `main`
5. After merge, tag release
6. Deploy to production

## Getting Help

- Slack: #zalt-dev
- Email: dev@hsdcore.com
- Weekly sync: Thursdays 10:00 CET

## License

By contributing, you agree that your contributions will be licensed under the project's license.
