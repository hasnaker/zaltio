/**
 * E2E Tests for Clerk to Zalt.io Migration Script
 * Task 10.3: Validate migration logic and data transformation
 * 
 * These tests verify:
 * 1. Clerk export parsing
 * 2. User data transformation
 * 3. Migration report generation
 * 4. Error handling
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  loadClerkExport,
  transformUser,
  generateReport,
  ClerkUser,
  ClerkExport,
  MigrationResult
} from '../../../scripts/clerk-migration';

describe('Clerk Migration Script', () => {
  let tempDir: string;

  beforeAll(() => {
    // Create temp directory for test files
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clerk-migration-test-'));
  });

  afterAll(() => {
    // Cleanup temp directory
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('loadClerkExport', () => {
    it('should load valid Clerk export file', () => {
      const exportData: ClerkExport = {
        users: [
          {
            id: 'user_123',
            email_addresses: [
              { email_address: 'test@example.com', verification: { status: 'verified' } }
            ],
            first_name: 'Test',
            last_name: 'User',
            created_at: Date.now(),
            updated_at: Date.now()
          }
        ],
        exported_at: new Date().toISOString(),
        total_count: 1
      };

      const filePath = path.join(tempDir, 'valid-export.json');
      fs.writeFileSync(filePath, JSON.stringify(exportData));

      const result = loadClerkExport(filePath);
      expect(result.users).toHaveLength(1);
      expect(result.total_count).toBe(1);
    });

    it('should throw error for non-existent file', () => {
      expect(() => loadClerkExport('/non/existent/file.json')).toThrow('File not found');
    });

    it('should throw error for invalid JSON', () => {
      const filePath = path.join(tempDir, 'invalid.json');
      fs.writeFileSync(filePath, 'not valid json');

      expect(() => loadClerkExport(filePath)).toThrow();
    });

    it('should throw error for missing users array', () => {
      const filePath = path.join(tempDir, 'no-users.json');
      fs.writeFileSync(filePath, JSON.stringify({ exported_at: new Date().toISOString() }));

      expect(() => loadClerkExport(filePath)).toThrow('Invalid Clerk export format');
    });

    it('should handle empty users array', () => {
      const exportData = {
        users: [],
        exported_at: new Date().toISOString(),
        total_count: 0
      };

      const filePath = path.join(tempDir, 'empty-users.json');
      fs.writeFileSync(filePath, JSON.stringify(exportData));

      const result = loadClerkExport(filePath);
      expect(result.users).toHaveLength(0);
      expect(result.total_count).toBe(0);
    });
  });

  describe('transformUser', () => {
    const baseClerkUser: ClerkUser = {
      id: 'user_abc123',
      email_addresses: [
        { email_address: 'Dr.Test@Example.COM', verification: { status: 'verified' } }
      ],
      first_name: 'Test',
      last_name: 'Doctor',
      created_at: 1704067200000, // 2024-01-01
      updated_at: 1704153600000
    };

    it('should transform basic user data correctly', () => {
      const result = transformUser(baseClerkUser, 'clinisyn-psychologists');

      expect(result.email).toBe('dr.test@example.com'); // Lowercase
      expect(result.realm_id).toBe('clinisyn-psychologists');
      expect(result.profile.first_name).toBe('Test');
      expect(result.profile.last_name).toBe('Doctor');
      expect(result.email_verified).toBe(true);
      expect(result.clerk_id).toBe('user_abc123');
    });

    it('should preserve migration metadata', () => {
      const result = transformUser(baseClerkUser, 'clinisyn-psychologists');

      expect(result.profile.metadata).toBeDefined();
      expect(result.profile.metadata.migrated_from).toBe('clerk');
      expect(result.profile.metadata.clerk_id).toBe('user_abc123');
      expect(result.profile.metadata.original_created_at).toBeDefined();
    });

    it('should handle unverified email', () => {
      const unverifiedUser: ClerkUser = {
        ...baseClerkUser,
        email_addresses: [
          { email_address: 'unverified@example.com', verification: { status: 'pending' } }
        ]
      };

      const result = transformUser(unverifiedUser, 'clinisyn-students');
      expect(result.email_verified).toBe(false);
    });

    it('should extract social providers', () => {
      const socialUser: ClerkUser = {
        ...baseClerkUser,
        external_accounts: [
          { provider: 'google', provider_user_id: 'google_123' },
          { provider: 'apple', provider_user_id: 'apple_456' }
        ]
      };

      const result = transformUser(socialUser, 'clinisyn-psychologists');
      expect(result.social_providers).toContain('google');
      expect(result.social_providers).toContain('apple');
      expect(result.social_providers).toHaveLength(2);
    });

    it('should handle missing first/last name', () => {
      const noNameUser: ClerkUser = {
        ...baseClerkUser,
        first_name: null,
        last_name: null
      };

      const result = transformUser(noNameUser, 'clinisyn-students');
      expect(result.profile.first_name).toBeUndefined();
      expect(result.profile.last_name).toBeUndefined();
    });

    it('should throw error for user without email', () => {
      const noEmailUser: ClerkUser = {
        ...baseClerkUser,
        email_addresses: []
      };

      expect(() => transformUser(noEmailUser, 'clinisyn-psychologists'))
        .toThrow('No email found');
    });

    it('should use first email if none verified', () => {
      const multiEmailUser: ClerkUser = {
        ...baseClerkUser,
        email_addresses: [
          { email_address: 'first@example.com', verification: { status: 'pending' } },
          { email_address: 'second@example.com', verification: { status: 'pending' } }
        ]
      };

      const result = transformUser(multiEmailUser, 'clinisyn-students');
      expect(result.email).toBe('first@example.com');
      expect(result.email_verified).toBe(false);
    });

    it('should prefer verified email over unverified', () => {
      const multiEmailUser: ClerkUser = {
        ...baseClerkUser,
        email_addresses: [
          { email_address: 'unverified@example.com', verification: { status: 'pending' } },
          { email_address: 'verified@example.com', verification: { status: 'verified' } }
        ]
      };

      const result = transformUser(multiEmailUser, 'clinisyn-psychologists');
      expect(result.email).toBe('verified@example.com');
      expect(result.email_verified).toBe(true);
    });

    it('should preserve public metadata', () => {
      const metadataUser: ClerkUser = {
        ...baseClerkUser,
        public_metadata: {
          role: 'psychologist',
          license_number: 'PSK-12345',
          specialization: 'CBT'
        }
      };

      const result = transformUser(metadataUser, 'clinisyn-psychologists');
      expect(result.profile.metadata.role).toBe('psychologist');
      expect(result.profile.metadata.license_number).toBe('PSK-12345');
      expect(result.profile.metadata.specialization).toBe('CBT');
    });
  });

  describe('generateReport', () => {
    it('should generate correct summary for successful migrations', () => {
      const results: MigrationResult[] = [
        { success: true, userId: 'user_1', email: 'user1@example.com' },
        { success: true, userId: 'user_2', email: 'user2@example.com' },
        { success: true, userId: 'user_3', email: 'user3@example.com' }
      ];

      const startTime = new Date();
      const report = generateReport(results, startTime, { sent: 3, failed: 0 });

      expect(report.total_users).toBe(3);
      expect(report.successful).toBe(3);
      expect(report.failed).toBe(0);
      expect(report.started_at).toBeDefined();
      expect(report.completed_at).toBeDefined();
    });

    it('should generate correct summary for mixed results', () => {
      const results: MigrationResult[] = [
        { success: true, userId: 'user_1', email: 'user1@example.com' },
        { success: false, email: 'user2@example.com', error: 'Duplicate email' },
        { success: true, userId: 'user_3', email: 'user3@example.com' },
        { success: false, email: 'user4@example.com', error: 'Invalid data' }
      ];

      const startTime = new Date();
      const report = generateReport(results, startTime, { sent: 2, failed: 0 });

      expect(report.total_users).toBe(4);
      expect(report.successful).toBe(2);
      expect(report.failed).toBe(2);
    });

    it('should include all results in report', () => {
      const results: MigrationResult[] = [
        { success: true, userId: 'user_1', email: 'user1@example.com' },
        { success: false, email: 'user2@example.com', error: 'Error message' }
      ];

      const report = generateReport(results, new Date(), { sent: 1, failed: 0 });

      expect(report.results).toHaveLength(2);
      expect(report.results[0].success).toBe(true);
      expect(report.results[1].success).toBe(false);
      expect(report.results[1].error).toBe('Error message');
    });

    it('should handle empty results', () => {
      const report = generateReport([], new Date(), { sent: 0, failed: 0 });

      expect(report.total_users).toBe(0);
      expect(report.successful).toBe(0);
      expect(report.failed).toBe(0);
      expect(report.results).toHaveLength(0);
    });
  });

  describe('Migration Data Validation', () => {
    it('should handle large export files', () => {
      const users: ClerkUser[] = [];
      for (let i = 0; i < 1000; i++) {
        users.push({
          id: `user_${i}`,
          email_addresses: [
            { email_address: `user${i}@example.com`, verification: { status: 'verified' } }
          ],
          first_name: `First${i}`,
          last_name: `Last${i}`,
          created_at: Date.now(),
          updated_at: Date.now()
        });
      }

      const exportData: ClerkExport = {
        users,
        exported_at: new Date().toISOString(),
        total_count: 1000
      };

      const filePath = path.join(tempDir, 'large-export.json');
      fs.writeFileSync(filePath, JSON.stringify(exportData));

      const result = loadClerkExport(filePath);
      expect(result.users).toHaveLength(1000);
    });

    it('should handle special characters in names', () => {
      const specialUser: ClerkUser = {
        id: 'user_special',
        email_addresses: [
          { email_address: 'special@example.com', verification: { status: 'verified' } }
        ],
        first_name: 'Müller-Öztürk',
        last_name: "O'Brien",
        created_at: Date.now(),
        updated_at: Date.now()
      };

      const result = transformUser(specialUser, 'clinisyn-psychologists');
      expect(result.profile.first_name).toBe('Müller-Öztürk');
      expect(result.profile.last_name).toBe("O'Brien");
    });

    it('should handle Turkish characters in email', () => {
      const turkishUser: ClerkUser = {
        id: 'user_turkish',
        email_addresses: [
          { email_address: 'AYŞE.YILMAZ@example.com', verification: { status: 'verified' } }
        ],
        first_name: 'Ayşe',
        last_name: 'Yılmaz',
        created_at: Date.now(),
        updated_at: Date.now()
      };

      const result = transformUser(turkishUser, 'clinisyn-psychologists');
      expect(result.email).toBe('ayşe.yilmaz@example.com');
    });

    it('should preserve timestamps correctly', () => {
      const timestamp = 1704067200000; // 2024-01-01 00:00:00 UTC
      const user: ClerkUser = {
        id: 'user_timestamp',
        email_addresses: [
          { email_address: 'timestamp@example.com', verification: { status: 'verified' } }
        ],
        first_name: 'Test',
        last_name: 'User',
        created_at: timestamp,
        updated_at: timestamp + 86400000
      };

      const result = transformUser(user, 'clinisyn-students');
      expect(result.profile.metadata.original_created_at).toBe('2024-01-01T00:00:00.000Z');
    });
  });

  describe('Realm Assignment', () => {
    const testUser: ClerkUser = {
      id: 'user_realm',
      email_addresses: [
        { email_address: 'realm@example.com', verification: { status: 'verified' } }
      ],
      first_name: 'Test',
      last_name: 'User',
      created_at: Date.now(),
      updated_at: Date.now()
    };

    it('should assign to clinisyn-psychologists realm', () => {
      const result = transformUser(testUser, 'clinisyn-psychologists');
      expect(result.realm_id).toBe('clinisyn-psychologists');
    });

    it('should assign to clinisyn-students realm', () => {
      const result = transformUser(testUser, 'clinisyn-students');
      expect(result.realm_id).toBe('clinisyn-students');
    });

    it('should assign to custom realm', () => {
      const result = transformUser(testUser, 'custom-realm-id');
      expect(result.realm_id).toBe('custom-realm-id');
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed email addresses gracefully', () => {
      const malformedUser: ClerkUser = {
        id: 'user_malformed',
        email_addresses: [
          { email_address: '', verification: { status: 'verified' } }
        ],
        first_name: 'Test',
        last_name: 'User',
        created_at: Date.now(),
        updated_at: Date.now()
      };

      // Empty email should still be processed (validation happens elsewhere)
      const result = transformUser(malformedUser, 'clinisyn-students');
      expect(result.email).toBe('');
    });

    it('should handle missing verification status', () => {
      const noVerificationUser: ClerkUser = {
        id: 'user_no_verify',
        email_addresses: [
          { email_address: 'test@example.com', verification: { status: '' } }
        ],
        first_name: 'Test',
        last_name: 'User',
        created_at: Date.now(),
        updated_at: Date.now()
      };

      const result = transformUser(noVerificationUser, 'clinisyn-students');
      expect(result.email_verified).toBe(false);
    });

    it('should handle null external_accounts', () => {
      const noExternalUser: ClerkUser = {
        id: 'user_no_external',
        email_addresses: [
          { email_address: 'test@example.com', verification: { status: 'verified' } }
        ],
        first_name: 'Test',
        last_name: 'User',
        created_at: Date.now(),
        updated_at: Date.now(),
        external_accounts: undefined
      };

      const result = transformUser(noExternalUser, 'clinisyn-psychologists');
      expect(result.social_providers).toHaveLength(0);
    });
  });
});
