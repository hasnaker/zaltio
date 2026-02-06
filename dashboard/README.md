# Zalt.io Dashboard

Administrative dashboard for the Zalt.io Authentication Platform built with Next.js.

## Features

- 🏰 **Realm Management** - Create, configure, and delete authentication realms
- 👥 **User Management** - View, search, suspend, and delete users
- 👤 **Admin Management** - Manage dashboard administrators and roles
- 🔐 **Session Management** - Monitor and revoke active sessions
- 🛡️ **Risk Analytics** - AI-powered risk assessment monitoring and alerts
- 📊 **Analytics** - View authentication statistics and trends
- 🔔 **Real-time Notifications** - Get alerts for critical events
- ⚙️ **Settings** - Configure dashboard preferences

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
# Install dependencies
npm install

# Set up environment variables
cp .env.example .env.local

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Environment Variables

Create `.env.local` with:

```bash
# API Configuration
NEXT_PUBLIC_API_URL=https://api.auth.hsdcore.com

# Authentication
JWT_SECRET=your-jwt-secret-for-dashboard

# Optional: Analytics
NEXT_PUBLIC_ANALYTICS_ID=your-analytics-id
```

## Project Structure

```
dashboard/
├── src/
│   ├── app/                    # Next.js App Router
│   │   ├── api/               # API routes
│   │   │   ├── admins/        # Admin management API
│   │   │   ├── auth/          # Authentication API
│   │   │   ├── dashboard/     # Dashboard data APIs
│   │   │   │   └── risk/      # Risk analytics API
│   │   │   ├── realms/        # Realm management API
│   │   │   ├── sessions/      # Session management API
│   │   │   └── users/         # User management API
│   │   ├── dashboard/         # Dashboard pages
│   │   │   ├── admins/        # Admin management
│   │   │   ├── analytics/     # Analytics page
│   │   │   ├── realms/        # Realm management
│   │   │   ├── risk/          # Risk analytics page
│   │   │   ├── security/      # Security pages
│   │   │   │   └── compromised-passwords/  # Compromised password management
│   │   │   ├── sessions/      # Session management
│   │   │   ├── sso/           # SSO configuration wizard
│   │   │   ├── settings/      # Settings page
│   │   │   └── users/         # User management
│   │   └── login/             # Login page
│   ├── components/            # React components
│   │   ├── NotificationBell.tsx
│   │   ├── RealmSelector.tsx
│   │   └── RoleAccessControl.tsx
│   ├── lib/                   # Utility libraries
│   ├── middleware/            # Auth middleware
│   └── types/                 # TypeScript types
├── public/                    # Static assets
└── tailwind.config.js         # Tailwind CSS config
```

## Pages

### Dashboard Home (`/dashboard`)

Overview with key metrics:
- Total users across all realms
- Active sessions
- Recent registrations
- Login statistics

### Realms (`/dashboard/realms`)

Manage authentication realms:
- List all realms with search
- Create new realms
- Edit realm settings (session timeout, MFA, password policy)
- Configure authentication providers
- View realm-specific users
- Delete realms

### Users (`/dashboard/users`)

Manage users across realms:
- Filter by realm
- Search by email
- Filter by status (active, suspended, pending)
- Sort by various fields
- Bulk actions (suspend, activate, delete)
- Edit user details

### Admins (`/dashboard/admins`)

Manage dashboard administrators:
- View all admins
- Assign roles (Super Admin, Realm Admin, Viewer)
- Configure realm access
- Add/remove admins

### Sessions (`/dashboard/sessions`)

Session management and analytics dashboard:

**Analytics Tab:**
- **Concurrent Sessions Chart** - Visual chart showing session count over time (24h/7d/30d)
- **Device Distribution** - Donut chart showing Desktop/Mobile/Tablet breakdown
- **Geographic Distribution** - Sessions by country with city breakdown
- **Real-time Session Count** - Auto-refreshing every 30 seconds

**Stats Overview:**
- Active Sessions - Real-time count of all active sessions
- Unique Users - Number of users with active sessions
- Avg Sessions/User - Average concurrent sessions per user
- Peak Concurrent - Maximum concurrent sessions in the period

**Sessions Tab:**
- View all active sessions with device, browser, IP, and location
- Search by email, IP, location, or device
- Current session indicator
- Revoke individual sessions
- Session details: device type, browser version, masked IP, geolocation

**API Endpoints:**
- `GET /api/dashboard/sessions` - Get session analytics data
  - Query params: `range` (24h, 7d, 30d), `realmId` (optional)
  - Returns: stats, sessions, concurrentSessionsChart, deviceDistribution, locationDistribution
- `DELETE /api/dashboard/sessions/{id}` - Revoke specific session

**Security:**
- Admin authentication required
- IP addresses are masked for privacy
- Audit logging for all session operations
- Auto-refresh for real-time monitoring

### Risk Analytics (`/dashboard/risk`)

AI-powered risk assessment monitoring:
- **Risk Score History** - Visual chart showing risk scores over time
- **Risk Factor Breakdown** - Pie/bar chart showing contributing factors
- **High-Risk Login Alerts** - Real-time alerts for suspicious logins
- **Stats Overview** - Total assessments, average score, blocked attempts
- **Time Range Filtering** - View data for 24h, 7d, or 30d periods
- **Search & Filter** - Search alerts by email, IP, or country

Risk levels:
- **Low (0-30)** - Normal activity, no action required
- **Medium (31-60)** - Some suspicious indicators, monitoring
- **High (61-85)** - Multiple suspicious indicators, MFA required
- **Critical (86-100)** - Strong indicators of malicious activity, blocked

### SSO Configuration (`/dashboard/sso`)

Organization-level Single Sign-On configuration wizard:

**Features:**
- **Step-by-Step Wizard** - Guided SSO setup process
- **Protocol Selection** - Choose between SAML 2.0 and OpenID Connect
- **IdP Metadata Upload** - Upload XML file, fetch from URL, or manual entry
- **Attribute Mapping** - Map IdP attributes to Zalt user profile
- **Domain Verification** - DNS TXT record verification for SSO enforcement
- **Test Connection** - Verify IdP configuration before activation
- **JIT Provisioning** - Configure Just-In-Time user creation

**Wizard Steps:**
1. **SSO Type** - Select SAML 2.0 or OIDC protocol
2. **Provider** - Configure identity provider settings
3. **Attributes** - Map user attributes and configure JIT provisioning
4. **Domains** - Add and verify email domains for SSO enforcement
5. **Review** - Test connection and activate SSO

**Supported SAML Providers:**
- Okta
- Azure AD / Microsoft Entra
- ADFS
- OneLogin
- PingIdentity
- Any SAML 2.0 compliant IdP

**Supported OIDC Providers:**
- Google Workspace
- Microsoft Entra (Azure AD)
- Okta
- Auth0
- OneLogin
- Custom OIDC providers

**Domain Verification:**
- Add DNS TXT record: `_zalt-verify.yourdomain.com`
- Verification token provided in wizard
- Required for SSO enforcement

**SSO Enforcement:**
- Block password login for verified domain users
- Automatic redirect to organization's IdP
- Requires at least one verified domain

**API Endpoints:**
- `GET /api/tenants/{tenantId}/sso` - Get SSO configuration
- `POST /api/tenants/{tenantId}/sso` - Create SSO configuration
- `PUT /api/tenants/{tenantId}/sso` - Update SSO configuration
- `POST /api/tenants/{tenantId}/sso/domains` - Add domain for verification
- `POST /api/tenants/{tenantId}/sso/domains/{domain}/verify` - Verify domain
- `POST /api/tenants/{tenantId}/sso/test` - Test SSO connection

**Security:**
- Admin authentication required
- Client secrets encrypted at rest
- Audit logging for all SSO configuration changes
- HTTPS required for all IdP URLs

### Security Dashboard - Compromised Passwords (`/dashboard/security/compromised-passwords`)

Monitor and manage users with compromised passwords detected via HaveIBeenPwned:

**Features:**
- **Statistics Cards** - Total users, compromised count, pending resets, resolved
- **User Table** - List of users with compromised passwords
- **Status Filtering** - Filter by compromised, pending reset, or resolved
- **Search** - Search by email or name
- **Force Password Reset** - Force individual user to reset password
- **Mass Password Reset** - Force all users to reset passwords (security incident)

**User Statuses:**
- **Compromised** - Password found in breach database, needs reset
- **Pending Reset** - Reset task created, waiting for user action
- **Resolved** - User has successfully reset their password

**Actions:**
- **Force Reset Button** - Creates reset_password session task for user
- **Mass Password Reset** - Critical operation for security incidents
  - Requires explicit confirmation
  - Revokes all active sessions
  - Sends notification emails to all users

**API Endpoints:**
- `GET /api/dashboard/security/compromised-passwords` - Get statistics and user list
- `POST /api/dashboard/security/compromised-passwords` - Force reset for individual user
- `POST /api/dashboard/security/compromised-passwords/all` - Mass password reset

**Security:**
- Admin authentication required
- Audit logging for all actions
- Rate limiting on mass operations
- Explicit confirmation required for mass reset

### Analytics (`/dashboard/analytics`)

View authentication metrics:
- Registration trends
- Login statistics
- Error rates
- Geographic distribution

### Settings (`/dashboard/settings`)

Configure dashboard preferences:
- Notification settings
- Display preferences
- API key management

## Role-Based Access Control

### Roles

| Role | Description |
|------|-------------|
| `super_admin` | Full access to all features and realms |
| `realm_admin` | Full access to assigned realms |
| `realm_viewer` | Read-only access to assigned realms |
| `analytics_viewer` | View analytics only |

### Permissions

| Permission | Super Admin | Realm Admin | Realm Viewer | Analytics Viewer |
|------------|-------------|-------------|--------------|------------------|
| realm:read | ✅ | ✅ | ✅ | ❌ |
| realm:write | ✅ | ✅ | ❌ | ❌ |
| realm:delete | ✅ | ❌ | ❌ | ❌ |
| user:read | ✅ | ✅ | ✅ | ❌ |
| user:write | ✅ | ✅ | ❌ | ❌ |
| user:delete | ✅ | ✅ | ❌ | ❌ |
| session:read | ✅ | ✅ | ✅ | ❌ |
| session:revoke | ✅ | ✅ | ❌ | ❌ |
| analytics:read | ✅ | ✅ | ✅ | ✅ |
| settings:read | ✅ | ✅ | ✅ | ❌ |
| settings:write | ✅ | ✅ | ❌ | ❌ |

## Components

### RealmSelector

Dropdown component for selecting realms:

```tsx
import RealmSelector from '@/components/RealmSelector';

<RealmSelector
  selectedRealmId={selectedRealm}
  onRealmChange={setSelectedRealm}
  showAllOption={true}
/>
```

### RoleAccessControl

Component for managing admin roles and permissions:

```tsx
import RoleAccessControl from '@/components/RoleAccessControl';

<RoleAccessControl
  currentRole={admin.role}
  currentRealmAccess={admin.realm_access}
  availableRealms={realms}
  onRoleChange={handleRoleChange}
  onRealmAccessChange={handleRealmAccessChange}
/>
```

### NotificationBell

Real-time notification component:

```tsx
import NotificationBell from '@/components/NotificationBell';

<NotificationBell />
```

## API Routes

### Authentication

- `POST /api/auth/login` - Admin login
- `POST /api/auth/logout` - Admin logout
- `GET /api/auth/me` - Get current admin

### Realms

- `GET /api/realms` - List realms
- `POST /api/realms` - Create realm
- `GET /api/realms/[id]` - Get realm
- `PUT /api/realms/[id]` - Update realm
- `DELETE /api/realms/[id]` - Delete realm

### Users

- `GET /api/users` - List users
- `GET /api/users/[id]` - Get user
- `PUT /api/users/[id]` - Update user
- `DELETE /api/users/[id]` - Delete user
- `POST /api/users/[id]/suspend` - Suspend user
- `POST /api/users/[id]/activate` - Activate user

### Admins

- `GET /api/admins` - List admins
- `POST /api/admins` - Create admin
- `PUT /api/admins/[id]` - Update admin
- `DELETE /api/admins/[id]` - Delete admin

### Sessions

- `GET /api/sessions` - List sessions
- `DELETE /api/sessions/[id]` - Revoke session

### Risk Analytics

- `GET /api/dashboard/risk` - Get risk analytics data
  - Query params: `range` (24h, 7d, 30d), `userId` (optional)
  - Returns: stats, history, factorBreakdown, alerts

## Development

### Running Tests

```bash
npm test
```

### Building for Production

```bash
npm run build
```

### Linting

```bash
npm run lint
```

## Deployment

### Vercel (Recommended)

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod
```

### Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

```bash
docker build -t zalt-dashboard .
docker run -p 3000:3000 zalt-dashboard
```

## Styling

The dashboard uses Tailwind CSS with custom HSD brand colors:

```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        'hsd-primary': '#3B82F6',
        'hsd-secondary': '#1D4ED8',
        'hsd-dark': '#1F2937',
      }
    }
  }
}
```

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## License

Proprietary - HSD Internal Use Only
