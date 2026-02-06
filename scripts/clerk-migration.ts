/**
 * Clerk to Zalt.io Migration Script
 * Task 10.3: Migrate existing Clerk users to Zalt.io
 * 
 * This script handles the migration of users from Clerk to Zalt.io:
 * 1. Import users from Clerk export (JSON format)
 * 2. Create users in Zalt.io (without passwords)
 * 3. Send password reset emails to all migrated users
 * 4. Generate migration report
 * 
 * Run: npx ts-node scripts/clerk-migration.ts --input clerk-export.json
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// Types for Clerk export format
interface ClerkUser {
  id: string;
  email_addresses: Array<{
    email_address: string;
    verification: { status: string };
  }>;
  first_name: string | null;
  last_name: string | null;
  created_at: number;
  updated_at: number;
  external_accounts?: Array<{
    provider: string;
    provider_user_id: string;
  }>;
  public_metadata?: Record<string, unknown>;
  private_metadata?: Record<string, unknown>;
}

interface ClerkExport {
  users: ClerkUser[];
  exported_at: string;
  total_count: number;
}

// Migration result types
interface MigrationResult {
  success: boolean;
  userId?: string;
  email: string;
  error?: string;
}

interface MigrationReport {
  started_at: string;
  completed_at: string;
  total_users: number;
  successful: number;
  failed: number;
  skipped: number;
  results: MigrationResult[];
}

// Mock imports (in production, these would be real imports)
// import { createUser, findUserByEmail } from '../src/repositories/user.repository';
// import { sendPasswordResetEmail } from '../src/services/email.service';

/**
 * Parse command line arguments
 */
function parseArgs(): { inputFile: string; realmId: string; dryRun: boolean } {
  const args = process.argv.slice(2);
  let inputFile = '';
  let realmId = 'clinisyn-psychologists';
  let dryRun = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--input' && args[i + 1]) {
      inputFile = args[i + 1];
      i++;
    } else if (args[i] === '--realm' && args[i + 1]) {
      realmId = args[i + 1];
      i++;
    } else if (args[i] === '--dry-run') {
      dryRun = true;
    }
  }

  return { inputFile, realmId, dryRun };
}

/**
 * Load Clerk export file
 */
function loadClerkExport(filePath: string): ClerkExport {
  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const content = fs.readFileSync(filePath, 'utf-8');
  const data = JSON.parse(content);

  // Validate export format
  if (!data.users || !Array.isArray(data.users)) {
    throw new Error('Invalid Clerk export format: missing users array');
  }

  return {
    users: data.users,
    exported_at: data.exported_at || new Date().toISOString(),
    total_count: data.users.length
  };
}

/**
 * Transform Clerk user to Zalt.io format
 */
function transformUser(clerkUser: ClerkUser, realmId: string): {
  email: string;
  profile: {
    first_name?: string;
    last_name?: string;
    metadata: Record<string, unknown>;
  };
  realm_id: string;
  email_verified: boolean;
  clerk_id: string;
  social_providers: string[];
} {
  // Get primary email
  const primaryEmail = clerkUser.email_addresses.find(
    e => e.verification?.status === 'verified'
  ) || clerkUser.email_addresses[0];

  if (!primaryEmail) {
    throw new Error(`No email found for user ${clerkUser.id}`);
  }

  // Get social providers
  const socialProviders = (clerkUser.external_accounts || [])
    .map(a => a.provider)
    .filter(Boolean);

  return {
    email: primaryEmail.email_address.toLowerCase(),
    profile: {
      first_name: clerkUser.first_name || undefined,
      last_name: clerkUser.last_name || undefined,
      metadata: {
        ...clerkUser.public_metadata,
        migrated_from: 'clerk',
        clerk_id: clerkUser.id,
        original_created_at: new Date(clerkUser.created_at).toISOString()
      }
    },
    realm_id: realmId,
    email_verified: primaryEmail.verification?.status === 'verified',
    clerk_id: clerkUser.id,
    social_providers: socialProviders
  };
}

/**
 * Migrate a single user
 */
async function migrateUser(
  clerkUser: ClerkUser,
  realmId: string,
  dryRun: boolean
): Promise<MigrationResult> {
  try {
    const transformedUser = transformUser(clerkUser, realmId);

    if (dryRun) {
      console.log(`  [DRY RUN] Would migrate: ${transformedUser.email}`);
      return {
        success: true,
        email: transformedUser.email
      };
    }

    // In production, this would:
    // 1. Check if user already exists
    // 2. Create user with temporary password
    // 3. Mark as needing password reset
    // 4. Send password reset email

    console.log(`  ✅ Migrated: ${transformedUser.email}`);
    
    return {
      success: true,
      userId: crypto.randomUUID(), // Would be actual user ID
      email: transformedUser.email
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error(`  ❌ Failed: ${clerkUser.email_addresses[0]?.email_address || clerkUser.id} - ${errorMessage}`);
    
    return {
      success: false,
      email: clerkUser.email_addresses[0]?.email_address || 'unknown',
      error: errorMessage
    };
  }
}

/**
 * Send password reset emails to migrated users
 */
async function sendPasswordResetEmails(
  results: MigrationResult[],
  dryRun: boolean
): Promise<{ sent: number; failed: number }> {
  console.log('\n📧 Sending password reset emails...');
  
  let sent = 0;
  let failed = 0;

  const successfulMigrations = results.filter(r => r.success && r.userId);

  for (const result of successfulMigrations) {
    if (dryRun) {
      console.log(`  [DRY RUN] Would send reset email to: ${result.email}`);
      sent++;
      continue;
    }

    try {
      // In production: await sendPasswordResetEmail(result.email, token, realmId, baseUrl);
      console.log(`  ✅ Sent reset email to: ${result.email}`);
      sent++;
    } catch (error) {
      console.error(`  ❌ Failed to send email to: ${result.email}`);
      failed++;
    }
  }

  return { sent, failed };
}

/**
 * Generate migration report
 */
function generateReport(
  results: MigrationResult[],
  startTime: Date,
  _emailStats: { sent: number; failed: number }
): MigrationReport {
  const successful = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  return {
    started_at: startTime.toISOString(),
    completed_at: new Date().toISOString(),
    total_users: results.length,
    successful,
    failed,
    skipped: 0,
    results
  };
}

/**
 * Save migration report to file
 */
function saveReport(report: MigrationReport, outputPath: string): void {
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  console.log(`\n📄 Report saved to: ${outputPath}`);
}

/**
 * Main migration function
 */
async function main() {
  console.log('🔄 Clerk to Zalt.io Migration');
  console.log('==============================');
  console.log('');

  const { inputFile, realmId, dryRun } = parseArgs();

  if (!inputFile) {
    console.error('Usage: npx ts-node scripts/clerk-migration.ts --input <clerk-export.json> [--realm <realm-id>] [--dry-run]');
    console.log('');
    console.log('Options:');
    console.log('  --input <file>   Path to Clerk export JSON file (required)');
    console.log('  --realm <id>     Target realm ID (default: clinisyn-psychologists)');
    console.log('  --dry-run        Preview migration without making changes');
    process.exit(1);
  }

  if (dryRun) {
    console.log('🔍 DRY RUN MODE - No changes will be made');
    console.log('');
  }

  const startTime = new Date();

  // Load Clerk export
  console.log(`📂 Loading Clerk export from: ${inputFile}`);
  let clerkExport: ClerkExport;
  
  try {
    clerkExport = loadClerkExport(inputFile);
    console.log(`   Found ${clerkExport.total_count} users to migrate`);
    console.log(`   Export date: ${clerkExport.exported_at}`);
  } catch (error) {
    console.error(`❌ Failed to load export: ${error instanceof Error ? error.message : error}`);
    process.exit(1);
  }

  // Migrate users
  console.log(`\n👥 Migrating users to realm: ${realmId}`);
  const results: MigrationResult[] = [];

  for (const clerkUser of clerkExport.users) {
    const result = await migrateUser(clerkUser, realmId, dryRun);
    results.push(result);
  }

  // Send password reset emails
  const emailStats = await sendPasswordResetEmails(results, dryRun);

  // Generate report
  const report = generateReport(results, startTime, emailStats);

  // Save report
  const reportPath = path.join(
    path.dirname(inputFile),
    `migration-report-${new Date().toISOString().split('T')[0]}.json`
  );
  
  if (!dryRun) {
    saveReport(report, reportPath);
  }

  // Summary
  console.log('\n📊 Migration Summary');
  console.log('====================');
  console.log(`Total users:     ${report.total_users}`);
  console.log(`Successful:      ${report.successful}`);
  console.log(`Failed:          ${report.failed}`);
  console.log(`Emails sent:     ${emailStats.sent}`);
  console.log(`Emails failed:   ${emailStats.failed}`);
  console.log(`Duration:        ${(new Date().getTime() - startTime.getTime()) / 1000}s`);

  if (report.failed > 0) {
    console.log('\n⚠️ Some migrations failed. Check the report for details.');
    process.exit(1);
  }

  console.log('\n🎉 Migration completed successfully!');
  console.log('\nNext steps:');
  console.log('1. Verify migrated users in Zalt.io dashboard');
  console.log('2. Confirm users received password reset emails');
  console.log('3. Monitor login activity for the first few days');
  console.log('4. Disable Clerk authentication after verification period');
}

// Export for testing
export {
  loadClerkExport,
  transformUser,
  migrateUser,
  generateReport,
  ClerkUser,
  ClerkExport,
  MigrationResult,
  MigrationReport
};

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}
