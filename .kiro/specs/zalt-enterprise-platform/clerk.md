
User Authentication
Everything you need. Secure by default.

Simple and secure user authentication, complete with everything you need out-of-the-box to provide a secure experience for your users.

Start building
Soc 2 Type 2
Clerk follows the highest standards in security compliance to ensure your customer data stays safe.

HIPAA
Clerk complies with the Health Insurance Portability and Accountability Act (HIPAA). This means it’s safe to store even the most sensitive user data.

Bot & Brute force detection
Let Clerk worry about every emergent security attack vector, while you focus on building your business.

Password leak protection
Enforce best practices by configuring custom password policies, and leveraging automatic HaveIBeenPwned leak detection.

Add high-conversion Social SSO to your application in seconds

When available, 53% of users choose to sign in with SSO instead of the alternatives. With Social SSO, Clerk makes it extremely simple to offer authentication the way your users want.

Convert faster with SSO
SSO averages 1.3 times faster than passwords, and 5.2 times faster than other passwordless authentication solutions like magic links.

One-click integration
Don’t spoil SSO’s impressive performance with common mistakes. Clerk handles edge cases gracefully, so you don’t have to.

Pick your providers
Clerk supports a wide range of SSO providers and is always adding more. If you need a provider that isn’t listed, please submit a request here.

Automatic Account Linking
If a user signs in with SSO after creating their account a different way, they are automatically linked to the original.

Clerk Components
Pre-built components, ready for everything

Simply add <SignIn />, <SignUp />, <UserButton />, <UserProfile /> anywhere in your React codebase. Keep users on your own domain, and bring your own CSS to align to your brand.

Explore UI components
Sign in to Acme Co
Welcome back! Please sign in to continue
Google
GitHub
or
Email address
Continue
Multi-factor authentication
MFA is the best way to prevent account takeovers.

Stop 99.9% of account takeovers in their tracks and provide the level of security your users have come to expect.

 SMS Passcodes. A text-based digital handshake, securely verifying identity with a unique, randomly generated code delivered straight to your mobile phone.
 Authenticator apps (TOTP). Personal digital locksmiths, creating dynamic, time-based one-time passwords (TOTPs) to secure your online access points.
 Hardware keys. Hardware keys are your personal digital padlocks, physically securing your data by requiring a unique key from a physical device to unlock your accounts.
 Recovery codes. Your digital lifeline, granting you access to your account when other forms of authentication are unavailable.
Passwordless
Convert your users to your product in seconds.

Eliminate forgotten passwords and credential stuffing attacks by going passwordless.

 Social SSO. Virtual passports, allowing you to swiftly navigate through various platforms using a single trusted account.
 Magic Links. One-click gateways, offering a seamless and password-free method to authenticate and access your digital domains securely.
 Email-based OTP. Exclusive digital stamps, presenting a one-time-use password for secure access, delivered directly to your inbox.
 SMS-based OTP. Your personalized digital keys, sent directly to your mobile device for secure one-time access.
Enterprise SSO
Easily implement Enterprise-grade tools like SAML and OpenID Connect

Forget the pain of having to manually implement SAML auth flows into your app. Now implementing a compliant SAML flow is as simple as filling out a form in Clerk's Dashboard.

Connection details
Service provider details
Identity provider information
Enterprise SSO
Advanced security
Take the security burden off your shoulders

Working with Clerk means integrating an enterprise-ready solution that considers security, privacy, and compliance our crucial responsibility and a top priority in everything we build.

Pen tests & source code review
Clerk commissions third-party testing and assessment based on the OWASP Testing Guide, the OWASP Application Security Verification Standard, and the NIST Technical Guide to Information Security Testing and Assessment.

XSS leak protection
Cross-Site Scripting (XSS) vulnerabilities are incredibly serious. Clerk works to minimize attack surface area by using HttpOnly cookies for authenticated requests to our Frontend API, so that credentials cannot be leaked during XSS attacks.

CSRF protection
Most Cross Site Request Forgery (CSRF) attacks can be protected against by properly configuring the way session tokens are stored. Clerk handles the necessary configuration on your behalf by configuring cookies with the SameSite flag.

Session fixation protection
Session fixation is a technique for hijacking a user session. Clerk protects against this by resetting the session token each time a user signs in or out of a browser. When the session is reset, the old session token is invalidated and can no longer be used for authentication.

Password protection and rules
Clerk uses NIST guidelines to determine the character rules for passwords and contracts with HaveIBeenPwned to review prospective passwords. Additionally, Clerk leverages bcrypt, an industry standard hashing algorithm for storage.

Session leak protection
Instead of sharing cookies across subdomains, Clerk sets multiple independent cookies (one for the main domain and one for the subdomain), so that an attack on Clerk cannot be chained into an attack on your application.

Security, Privacy, and Compliance in one tool
SOC2 Type IISOC2 Type II

HIPAAHIPAA

CCPACCPA

Session management
Speed up your application with sub-millisecond authentication

Clerk manages the full session lifecycle, including critical security features like active device monitoring and session revocation.

Don’t let auth slow your critical path
Clerk’s session architecture is purpose-built to be extremely performant and low-latency across the globe. Avoid the effort and complexity it takes to build session management infrastructure and let us obsess about it instead.

Stop account takeovers in their tracks
Our team is constantly assessing and protecting against the latest threats so you don’t have to. Never again compromise on critical features like session revocation because they take too long to build – Clerk provides them out of the box.

Multi-account, multi-device, multi-session by default
Most modern applications expect users to have separate accounts for business and personal contexts. Clerk’s session management enables users to sign into many accounts at once, and switch as needed.

Build multi-tenant SaaS the easy way
Clerk provides everything you need to onboard and manage organizations and users seamlessly in your multi-tenant SaaS application

Start building for free
Pricing details

B2B components
Turnkey simplicity for complex organization management tasks

Drop in Clerk components directly into your application for instant organization management, with best practices baked right in.


Organization settings component for a Next.js application, displaying options to manage the organization profile, verified domains, and the option to leave the organization.
<OrganizationProfile />
Fully-featured and user-friendly UI for managing organization profiles and security settings.



Create organization component for a Next.js application, featuring fields to upload a logo, enter the organization name, and set a slug, along with a button to create the organization.



Organization and account overview screen for a Next.js application, showing user roles in various organizations, including options to create a new organization.



Organization selection component for a Next.js application, allowing users to choose between their personal account and various organizations, with options to join or request access.




Invite growth
Let your customers invite their teams with one click

Fuel your application’s growth by making it easy for customers to invite their team. When a user follows their invitation link sent to their email, they’re redirected to the sign-up page with their email automatically verified.

Grow your app
Streamline enrollment
Automatically invite users by email domain

Want to restrict membership to users with a specific company email domain? Any user with an email address ending in your verified domain can be automatically invited or be suggested to join an organization with that domain.

Start building
Access control
Fully customize your app’s authorization story with custom roles and permissions

Control access to your application’s functionality based on custom roles and permissions all tailored to your application’s specific needs.

Learn more
We only want to charge you for organizations that are truly active.

Define and manage plans directly in Clerk
Set up plans in Clerk’s dashboard, create a pricing page with the <PricingTable /> component, and let customers manage their subscriptions through Clerk’s profile components.

Access user and subscription data in one place
Clerk automatically updates and stores your customers' subscription status alongside their user data, eliminating the need for complex synchronization code and the ongoing maintenance it requires.

Billing-aware authorization checks
Use Clerk’s has() helper to control access based on a customer’s plan, features, and permissions.

<Protect /> for components
import { Protect } from '@clerk/nextjs'

export default function ProtectPage() {
  return (
    <Protect
      feature="team_access"
      fallback={<p>Sorry, you don't have Team Access.</p>}
    >
      {children}
    </Protect>
  )
}
has() for everything else
import { auth } from '@clerk/nextjs/server'

export default async function Page() {
  const { has } = await auth()
  const hasBronzePlan = has({ plan: 'bronze' })

  if (!hasBronzePlan) return <h1>Sorry, only subscribers to the Bronze plan can access this content.</h1>

  return <h1>For Bronze subscribers only</h1>
}
Better subscription management, no extra cost
Costs the same as Stripe billing. See how we compare with other providers:

Clerk Billing
Stripe
Polar
Paddle
Billing fees
0.7%
Billing fees
0.7%
Billing fees
0.5%
Billing fees
N/A
Transaction fees (via Stripe)
2.9% + $0.30
Transaction fees
2.9% + $0.30
Transaction fees
4% + $0.40
Transaction fees
5% + $0.40
All in
3.6% + $0.30
All in
3.6% + $0.30
All in
4.5% + $0.40
All in
5% + $0.40
Example above is for US credit card transactions.

Integrate Clerk Billing with your framework of choice
Next.js
React
Reliability you can count on
Keep your users authenticated and engaged, even in challenging network conditions, without writing any session management code.


Established reliability
Founded in 2019, Clerk supports thousands of developers across over 10,000 active applications, managing authentication for 100+ million users across the globe.


Rigorous security standards
Security is Clerk’s top priority, with rigorous testing and certification across SOC 2 TYPE II, HIPAA, CCPA, and other industry standards.


Payment protection
Clerk does not store or process credit card information. Instead, you plug in your preferred payment provider for added protections like fraud prevention, PCI compliance, and secure transaction handling with 3Dsecure.

TrialsLive
Give customers free access to your paid subscriptions for a predefined limited time.

Per-seat billing
Charge customers a variable rate based on the number of seats they select when subscribing to your plans.

Taxes
Easily collect and manage taxes from our upcoming integrations with popular tax collection platforms.

Coupons & discounts
Easily give customers a discount when signing up for your subscription plans via discount codes.

Paid add-on features
Offer your customers paid features they can optionally add to their subscription.

Metered and usage-based billing
We’ll tally up your customer’s usage of your features, and charge them according to the variable rates you set up.


You’ve seen how easy it is, now go try for yourself. Start building your business with Clerk today.

Pricing that scales with you
You’re never charged for users who sign up and never come back. Your first 10,000 active users and 100 active organizations are free.

Free plan
Everything you need to get started.

Start building

No credit card required
10,000 monthly active users (MAUs)More info
No charge for users who sign up but never return
Pre-built components
Custom domain
US
$0
per month

Start building for free
All features free to use in development mode

Pro plan
Powerful extra features for your growing business.

Scale your app

$0.02 per MAU (your first 10,000 are free)More info
Remove Clerk branding
Allowlist / blocklist
Customizable session duration
…and much more

Enhanced authentication add-on
$100/mo

Multi-factor auth (SMS, TOTP, backup codes)
Device tracking and revocation
Satellite Domains
Simultaneous sessions
Enterprise SSO (EASIE, SAML, OIDC)

Enhanced administration add-on
$100/mo

User impersonation
Custom dashboard rolesComing soon
Audit logsComing soon
US
$25
$125$225$325
per month

Upgrade to pro

Organizations
The easy solution to multi-tenancy.

Learn more about Clerk Organizations
Organizations features in
Free plan
Purpose-built components and APIs for managing teams and organizations
100 monthly active organizations (MAOs)More info
Up to 5 members per organization
Invitation flows and basic roles
Organizations features in
Pro plan
$1 per MAO (your first 100 are free)More info
Organizations without at least one MAU are free
Unlimited members per organization

Enhanced Organizations add-on
$100/mo

Domain restrictions / Verified domains
Automatic invitations
Custom roles and permissions
Multiple role sets

Don’t get punished for your growth.
Bot and abuse protection
Dramatically reduce fraudulent sign-ups with built-in ML.

First Day Free
Users who sign up but never return to your app are free.

B2B SaaS friendly
No charge for organizations without at least one active user.

Enterprise
Need more support and compliance features or pricing doesn't work for your business?

Contact sales
99.99% Uptime SLA
Support SLA
Tiered Usage pricing available
HIPAA compliance available with BAA
Onboarding & migration supportMore info
Dedicated Slack support
Startups
Pre-negotiated startup discounts are available through our partners.

Apply now
Partners include Stripe Atlas, Y Combinator, OnDeck, Pioneer, and many more
Eligible up to 1 year after launch
Eligible up to $5 million in venture funding
Trusted by fast-growing companies around the world

Browserbase
OpenRouter
Suno
Higgsfield
Durable
Braintrust
Inngest
Upstash
Platform pricing	Free plan	Pro plan
Base price
$0/mo	$25/mo	
Monthly active users (MAUs)
A user is counted as active when they return 24+ hours after signing up.

10,000 included free	10,000 included free
+ $0.02 per additional MAU
Monthly active organizations (MAOs)
An organization is active when it has at least 2 members and at least one of those members is an active user.

100	100
+ $1 per additional MAO
Dashboard seats
Invite team members to collaborate in the Clerk dashboard.

3
+ $10/mo per additional seat
3
+ $10/mo per additional seat
Remove Clerk branding
Remove the “Secured by Clerk” branding from Clerk’s prebuilt UIs.

Not included	Included	
Authentication & user features	Free plan	Pro plan	
Pro plan with
Authentication add-on
Social connections
Let users sign in with social providers like Google, GitHub, or Facebook.

Up to 3	Unlimited	Unlimited
Usernames
A classic, tried and true method of signing in.

Included	Included	Included
Passwords
Automatically checked against leaked password databases for extra security.

Included	Included	Included
Email codes
Authenticate with a six-digit code sent to the user’s email.

Included	Included	Included
Email links
Authenticate with a link to the user’s email. Also known as “magic links.”

Included	Included	Included
SMS codes
View pricing
Authenticate with a code sent directly to the user’s phone via SMS.

Not included	Included	Included
Sign in tokens
Bypass standard sign-in and authenticate with single-use tokens generated by API.

Included	Included	Included
Web3 wallets
Authenticate with MetaMask or Coinbase Wallet.

Included	Included	Included
Automatic account linking
Ensure only one account is created when multiple authentication methods are used, like email codes and Sign in with Google.

Included	Included	Included
User metadata
Store custom data with user objects in Clerk.

Included	Included	Included
Webhooks for data sync
Synchronize Clerk user data with external systems.

Included	Included	Included
Passkeys
Authenticate with any form of passkeys.

Not included	Included	Included
Custom password requirements
By default, Clerk strictly adheres to NIST 800-63B for password requirements. This feature allows setting custom requirements.

Not included	Included	Included
Custom email & SMS templates
Tailor the messages users receive.

Not included	Included	Included
Multifactor authentication (MFA)
Allow users to enable multifactor authentication with authenticator applications, SMS codes, and backup codes.

Not included	Not included	Included
Enterprise connections
Leverage authentication with EASIE, SAML, or OIDC supported services.

Not included	Not included	Unlimited
Security features	Free plan	Pro plan	
Pro plan with
Authentication add-on
Account lockout / brute-force protection
Protect users from automated brute forcing.

Included	Included	Included
Bot protection
Ensure only real users can sign up.

Included	Included	Included
Block email subaddresses
Avoid abuse by preventing multiple sign-ups with the same email address.

Included	Included	Included
Block disposable email addresses
Block authentication attempts from known disposable email services.

Included	Included	Included
Require invitiations
Invite users who need access to an application and prevent those who don't.

Included	Included	Included
User bans
Prevent unwanted users from returning.

Not included	Included	Included
Allowlist / blocklist
Allow and deny users based on attributes such as domain, phone number, Web3 wallet address, etc.

Not included	Included	Included
Session management features	Free plan	Pro plan	
Pro plan with
Authentication add-on
Custom session tokens
Add custom data into the default authentication tokens.

Included	Included	Included
Custom JWT templates
Completely custom token claims designed for external service integration.

Included	Included	Included
Custom session duration
Set a maximum session duration, from 5 minutes to 10 years.

Fixed to 7 days	Included	Included
Device tracking and revocation
Allow users to view and log out the devices actively accessing their account.

Not included	Included	Included
Simultaneous sessions
Allow users to sign in to multiple accounts on one device.

Not included	Not included	Included
Satellite domains
Use the same session across applications hosted on different domains.

Not included	Not included	+$10 per domain
Administration & dashboard features	Free plan	Pro plan	
Pro plan with
Administration add-on
Dashboard seats
Invite team members to collaborate in the Clerk dashboard.

3	3	3
Additional seats
$10/mo/seat	$10/mo/seat	$10/mo/seat
Custom dashboard roles
Coming soon
Granular access control for dashboard members.

Not included	Not included	Included
User impersonation
Access an application as a user for easy troubleshooting.

Not included	Not included	Included
Organizations features	Free plan	Pro plan	
Pro plan with
Organizations add-on
Org Membership limit
Users who have access to a given organization.

5 members	Unlimited members	Unlimited members
Invitation emails
Easily invite users to join an organization from the dashboard or directly in the application.

Included	Included	Included
Basic RBAC
Grant users functionality by groups using Role Based Access Control (RBAC).

Included	Included	Included
Custom roles and permissions
Create unique roles and permissions for the most flexible RBAC.

Not included	Not included	Included
Multiple role sets
Create and manage multiple role sets within organizations for advanced access control scenarios.

One role set	One role set	Unlimited
Auto join / request to join
Streamline enrollment into organizations.

Not included	Not included	Included
Domain restrictions
Restrict organization members to only specific email domains.

Not included	Not included	Included
Support & compliance	Free plan	Pro plan
Full data exports
No questions asked data exports of Clerk user data.

Included	Included	
Community support
Our active Discord with over 10,000 members is supported by Clerk staff and community champions.

Included	Included	
Email support
24/7 access to our expert support staff.

Included
Billing, registration, and abuse queries only
Included	
GDPR / DPAs
Our service is built to be compliant with GDPR principles.

Included	Included	
SOC2 report
Learn about the safeguards we have in place to protect user data.

Not included	Included	
Start now, no strings attached.

Integrate complete user management in minutes. Free for your first 10,000 monthly active users and 100 monthly active orgs. No credit card required.

Start building
Frequently asked questions
Do you collect tax?
What happens when I exceed the first 10,000 monthly active users or 100 monthly active organizations?
Is there a free trial?
What happens if I am using Pro features in my development instance and I move to production?
What is "First Day Free"?
What is considered a monthly active user?
What is considered a monthly active organization?
Do you offer volume discounts?
Can I ensure my data only remains in a specific country or region?
Does Clerk offer migration assistance?
Can I export my data?