import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {
  console.log('Zalt Authentication extension activated');

  // Register commands
  const addAuthCommand = vscode.commands.registerCommand('zalt.addAuth', addAuthentication);
  const setupMFACommand = vscode.commands.registerCommand('zalt.setupMFA', addMFASetup);
  const addProtectedRouteCommand = vscode.commands.registerCommand('zalt.addProtectedRoute', addProtectedRoute);
  const securityCheckCommand = vscode.commands.registerCommand('zalt.checkSecurity', runSecurityCheck);

  context.subscriptions.push(addAuthCommand, setupMFACommand, addProtectedRouteCommand, securityCheckCommand);

  // Register tree views
  const statusProvider = new ZaltStatusProvider();
  const realmsProvider = new ZaltRealmsProvider();
  const docsProvider = new ZaltDocsProvider();

  vscode.window.registerTreeDataProvider('zalt-status', statusProvider);
  vscode.window.registerTreeDataProvider('zalt-realms', realmsProvider);
  vscode.window.registerTreeDataProvider('zalt-docs', docsProvider);
}

export function deactivate() {}

// ============================================================================
// Commands
// ============================================================================

async function addAuthentication() {
  const framework = await vscode.window.showQuickPick(
    ['Next.js (App Router)', 'Next.js (Pages Router)', 'React', 'Node.js'],
    { placeHolder: 'Select your framework' }
  );

  if (!framework) return;

  const realmId = await vscode.window.showInputBox({
    prompt: 'Enter your Zalt Realm ID',
    placeHolder: 'realm_xxxxxxxx',
  });

  if (!realmId) return;

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor');
    return;
  }

  let snippet = '';
  
  if (framework.includes('Next.js')) {
    snippet = getNextJsSnippet(realmId);
  } else if (framework === 'React') {
    snippet = getReactSnippet(realmId);
  } else {
    snippet = getNodeSnippet(realmId);
  }

  editor.insertSnippet(new vscode.SnippetString(snippet));
  vscode.window.showInformationMessage('Zalt authentication added! Run: npm install @zalt/core @zalt/react @zalt/next');
}

async function addMFASetup() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor');
    return;
  }

  const mfaSnippet = `import { useMFA } from '@zalt/react';

function MFASetup() {
  const { setup, verify, isLoading, qrCode } = useMFA();
  const [code, setCode] = useState('');

  const handleSetup = async () => {
    await setup('totp');
  };

  const handleVerify = async () => {
    await verify(code);
  };

  return (
    <div>
      {!qrCode ? (
        <button onClick={handleSetup} disabled={isLoading}>
          Enable Two-Factor Authentication
        </button>
      ) : (
        <div>
          <img src={qrCode} alt="Scan with authenticator app" />
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Enter 6-digit code"
            maxLength={6}
          />
          <button onClick={handleVerify} disabled={isLoading}>
            Verify
          </button>
        </div>
      )}
    </div>
  );
}`;

  editor.insertSnippet(new vscode.SnippetString(mfaSnippet));
}

async function addProtectedRoute() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor');
    return;
  }

  const middlewareSnippet = `import { zaltMiddleware } from '@zalt/next';

export default zaltMiddleware({
  publicRoutes: ['/', '/sign-in', '/sign-up', '/api/webhooks(.*)'],
  signInUrl: '/sign-in',
});

export const config = {
  matcher: ['/((?!_next|.*\\\\..*).*)'],
};`;

  editor.insertSnippet(new vscode.SnippetString(middlewareSnippet));
  vscode.window.showInformationMessage('Middleware added! Save as middleware.ts in your project root.');
}

async function runSecurityCheck() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor');
    return;
  }

  const code = editor.document.getText().toLowerCase();
  const issues: string[] = [];

  // Check for security issues
  if (code.includes('localstorage') && code.includes('token')) {
    issues.push('⚠️ Line: Storing tokens in localStorage is vulnerable to XSS');
  }

  if (code.includes('console.log') && (code.includes('token') || code.includes('password'))) {
    issues.push('🚨 CRITICAL: Never log sensitive data like tokens or passwords');
  }

  if (code.includes('sms') && code.includes('mfa') && !code.includes('acceptrisk')) {
    issues.push('⚠️ SMS MFA is vulnerable to SS7 attacks. Use TOTP or WebAuthn instead');
  }

  if (issues.length === 0) {
    vscode.window.showInformationMessage('✅ No security issues found');
  } else {
    const message = `Found ${issues.length} security issue(s):\n\n${issues.join('\n')}`;
    vscode.window.showWarningMessage(message, { modal: true });
  }
}

// ============================================================================
// Snippets
// ============================================================================

function getNextJsSnippet(realmId: string): string {
  return `// app/layout.tsx
import { ZaltProvider } from '@zalt/react';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <ZaltProvider realmId="${realmId}">
          {children}
        </ZaltProvider>
      </body>
    </html>
  );
}`;
}

function getReactSnippet(realmId: string): string {
  return `import { ZaltProvider } from '@zalt/react';

function App() {
  return (
    <ZaltProvider realmId="${realmId}">
      <YourApp />
    </ZaltProvider>
  );
}

export default App;`;
}

function getNodeSnippet(realmId: string): string {
  return `import { ZaltClient } from '@zalt/core';

const zalt = new ZaltClient({
  realmId: '${realmId}',
  apiUrl: 'https://api.zalt.io',
});

// Login
const result = await zalt.login(email, password);

// Check MFA requirement
if (result.mfaRequired) {
  // Handle MFA verification
  await zalt.mfa.verify(result.sessionId, code);
}`;
}

// ============================================================================
// Tree View Providers
// ============================================================================

class ZaltStatusProvider implements vscode.TreeDataProvider<StatusItem> {
  getTreeItem(element: StatusItem): vscode.TreeItem {
    return element;
  }

  getChildren(): StatusItem[] {
    return [
      new StatusItem('API Status', 'Connected', vscode.TreeItemCollapsibleState.None),
      new StatusItem('SDK Version', '1.0.0', vscode.TreeItemCollapsibleState.None),
    ];
  }
}

class ZaltRealmsProvider implements vscode.TreeDataProvider<RealmItem> {
  getTreeItem(element: RealmItem): vscode.TreeItem {
    return element;
  }

  getChildren(): RealmItem[] {
    return [
      new RealmItem('Configure realm in settings', '', vscode.TreeItemCollapsibleState.None),
    ];
  }
}

class ZaltDocsProvider implements vscode.TreeDataProvider<DocItem> {
  getTreeItem(element: DocItem): vscode.TreeItem {
    return element;
  }

  getChildren(): DocItem[] {
    return [
      new DocItem('Quick Start', 'https://zalt.io/docs/quickstart'),
      new DocItem('React Integration', 'https://zalt.io/docs/react'),
      new DocItem('Next.js Integration', 'https://zalt.io/docs/nextjs'),
      new DocItem('Security Best Practices', 'https://zalt.io/docs/security'),
      new DocItem('MFA Setup', 'https://zalt.io/docs/mfa'),
    ];
  }
}

class StatusItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly value: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState
  ) {
    super(label, collapsibleState);
    this.description = value;
  }
}

class RealmItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly realmId: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState
  ) {
    super(label, collapsibleState);
    this.description = realmId;
  }
}

class DocItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly url: string
  ) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.command = {
      command: 'vscode.open',
      title: 'Open Documentation',
      arguments: [vscode.Uri.parse(url)],
    };
  }
}
