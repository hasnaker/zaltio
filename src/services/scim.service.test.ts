/**
 * SCIM 2.0 Service Tests
 * Validates: Requirements 31.1, 31.4-31.7
 * 
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */
import {
  SCIMUserService,
  SCIMGroupService,
  SCIMBulkService,
  SCIMFilterParser,
  SCIMAttributeMapper,
  getSCIMStorage,
  getServiceProviderConfig,
  getResourceTypes,
  getSchemas,
  SCIM_SCHEMAS,
  SCIMUser,
  SCIMGroup,
  SCIMPatchRequest,
  SCIMBulkRequest,
  ZaltUser,
} from './scim.service';

const TEST_REALM_ID = 'test-realm';
const TEST_BASE_URL = 'https://api.zalt.io';

describe('SCIM 2.0 Service', () => {
  beforeEach(() => {
    // Clear storage before each test
    getSCIMStorage().clear();
  });

  // ==========================================================================
  // SCIM FILTER PARSER TESTS
  // ==========================================================================
  describe('SCIMFilterParser', () => {
    describe('parse', () => {
      it('should parse simple equality filter', () => {
        const filters = SCIMFilterParser.parse('userName eq "john@example.com"');
        expect(filters).toHaveLength(1);
        expect(filters[0]).toEqual({
          attribute: 'userName',
          operator: 'eq',
          value: 'john@example.com',
        });
      });

      it('should parse contains filter', () => {
        const filters = SCIMFilterParser.parse('emails.value co "@example.com"');
        expect(filters).toHaveLength(1);
        expect(filters[0]).toEqual({
          attribute: 'emails.value',
          operator: 'co',
          value: '@example.com',
        });
      });

      it('should parse starts with filter', () => {
        const filters = SCIMFilterParser.parse('userName sw "john"');
        expect(filters).toHaveLength(1);
        expect(filters[0].operator).toBe('sw');
      });

      it('should parse ends with filter', () => {
        const filters = SCIMFilterParser.parse('userName ew "@example.com"');
        expect(filters).toHaveLength(1);
        expect(filters[0].operator).toBe('ew');
      });

      it('should parse present filter', () => {
        const filters = SCIMFilterParser.parse('name.familyName pr');
        expect(filters).toHaveLength(1);
        expect(filters[0]).toEqual({
          attribute: 'name.familyName',
          operator: 'pr',
        });
      });

      it('should parse boolean filter', () => {
        const filters = SCIMFilterParser.parse('active eq true');
        expect(filters).toHaveLength(1);
        expect(filters[0].value).toBe('true');
      });

      it('should parse AND combined filters', () => {
        const filters = SCIMFilterParser.parse('active eq true and userName sw "john"');
        expect(filters).toHaveLength(2);
      });

      it('should parse greater than filter', () => {
        const filters = SCIMFilterParser.parse('meta.created gt "2024-01-01"');
        expect(filters).toHaveLength(1);
        expect(filters[0].operator).toBe('gt');
      });

      it('should return empty array for empty filter', () => {
        expect(SCIMFilterParser.parse('')).toEqual([]);
        expect(SCIMFilterParser.parse('   ')).toEqual([]);
      });
    });


    describe('applyFilters', () => {
      const testUsers = [
        { userName: 'john@example.com', active: true, name: { givenName: 'John', familyName: 'Doe' } },
        { userName: 'jane@example.com', active: true, name: { givenName: 'Jane', familyName: 'Smith' } },
        { userName: 'bob@test.com', active: false, name: { givenName: 'Bob' } },
      ];

      it('should filter by equality', () => {
        const filters = SCIMFilterParser.parse('userName eq "john@example.com"');
        const result = SCIMFilterParser.applyFilters(testUsers, filters);
        expect(result).toHaveLength(1);
        expect(result[0].userName).toBe('john@example.com');
      });

      it('should filter by contains', () => {
        const filters = SCIMFilterParser.parse('userName co "@example.com"');
        const result = SCIMFilterParser.applyFilters(testUsers, filters);
        expect(result).toHaveLength(2);
      });

      it('should filter by starts with', () => {
        const filters = SCIMFilterParser.parse('userName sw "j"');
        const result = SCIMFilterParser.applyFilters(testUsers, filters);
        expect(result).toHaveLength(2);
      });

      it('should filter by ends with', () => {
        const filters = SCIMFilterParser.parse('userName ew ".com"');
        const result = SCIMFilterParser.applyFilters(testUsers, filters);
        expect(result).toHaveLength(3);
      });

      it('should filter by present', () => {
        const filters = SCIMFilterParser.parse('name.familyName pr');
        const result = SCIMFilterParser.applyFilters(testUsers, filters);
        expect(result).toHaveLength(2);
      });

      it('should filter by boolean', () => {
        const filters = SCIMFilterParser.parse('active eq true');
        const result = SCIMFilterParser.applyFilters(testUsers, filters);
        expect(result).toHaveLength(2);
      });

      it('should filter by not equal', () => {
        const filters = SCIMFilterParser.parse('active ne true');
        const result = SCIMFilterParser.applyFilters(testUsers, filters);
        expect(result).toHaveLength(1);
        expect(result[0].userName).toBe('bob@test.com');
      });

      it('should apply multiple filters (AND)', () => {
        const filters = SCIMFilterParser.parse('active eq true and userName co "@example.com"');
        const result = SCIMFilterParser.applyFilters(testUsers, filters);
        expect(result).toHaveLength(2);
      });

      it('should return all items when no filters', () => {
        const result = SCIMFilterParser.applyFilters(testUsers, []);
        expect(result).toHaveLength(3);
      });
    });
  });

  // ==========================================================================
  // SCIM ATTRIBUTE MAPPER TESTS
  // ==========================================================================
  describe('SCIMAttributeMapper', () => {
    const mapper = new SCIMAttributeMapper(TEST_BASE_URL);

    describe('scimUserToZalt', () => {
      it('should map basic SCIM user to Zalt user', () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          name: {
            givenName: 'John',
            familyName: 'Doe',
          },
          active: true,
        };

        const zaltUser = mapper.scimUserToZalt(scimUser, TEST_REALM_ID);

        expect(zaltUser.email).toBe('john@example.com');
        expect(zaltUser.profile?.first_name).toBe('John');
        expect(zaltUser.profile?.last_name).toBe('Doe');
        expect(zaltUser.status).toBe('active');
        expect(zaltUser.realm_id).toBe(TEST_REALM_ID);
      });

      it('should map emails array to primary email', () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          emails: [
            { value: 'secondary@example.com', type: 'home' },
            { value: 'primary@example.com', type: 'work', primary: true },
          ],
        };

        const zaltUser = mapper.scimUserToZalt(scimUser, TEST_REALM_ID);
        expect(zaltUser.email).toBe('primary@example.com');
      });

      it('should map phone numbers', () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          phoneNumbers: [
            { value: '+1234567890', type: 'work', primary: true },
          ],
        };

        const zaltUser = mapper.scimUserToZalt(scimUser, TEST_REALM_ID);
        expect(zaltUser.profile?.phone).toBe('+1234567890');
      });

      it('should map enterprise extension', () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER, SCIM_SCHEMAS.ENTERPRISE_USER],
          userName: 'john@example.com',
          'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': {
            employeeNumber: 'EMP001',
            department: 'Engineering',
            organization: 'Zalt Inc',
          },
        };

        const zaltUser = mapper.scimUserToZalt(scimUser, TEST_REALM_ID);
        expect(zaltUser.profile?.metadata?.employee_number).toBe('EMP001');
        expect(zaltUser.profile?.metadata?.department).toBe('Engineering');
        expect(zaltUser.profile?.metadata?.organization).toBe('Zalt Inc');
      });

      it('should map inactive status to suspended', () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          active: false,
        };

        const zaltUser = mapper.scimUserToZalt(scimUser, TEST_REALM_ID);
        expect(zaltUser.status).toBe('suspended');
      });

      it('should map externalId', () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          externalId: 'ext-123',
        };

        const zaltUser = mapper.scimUserToZalt(scimUser, TEST_REALM_ID);
        expect(zaltUser.external_id).toBe('ext-123');
      });
    });


    describe('zaltUserToScim', () => {
      it('should map Zalt user to SCIM user', () => {
        const zaltUser: ZaltUser = {
          id: 'user-123',
          realm_id: TEST_REALM_ID,
          email: 'john@example.com',
          email_verified: true,
          profile: {
            first_name: 'John',
            last_name: 'Doe',
            phone: '+1234567890',
          },
          status: 'active',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-02T00:00:00Z',
        };

        const scimUser = mapper.zaltUserToScim(zaltUser);

        expect(scimUser.schemas).toContain(SCIM_SCHEMAS.USER);
        expect(scimUser.id).toBe('user-123');
        expect(scimUser.userName).toBe('john@example.com');
        expect(scimUser.name?.givenName).toBe('John');
        expect(scimUser.name?.familyName).toBe('Doe');
        expect(scimUser.active).toBe(true);
        expect(scimUser.emails).toHaveLength(1);
        expect(scimUser.emails?.[0].value).toBe('john@example.com');
        expect(scimUser.phoneNumbers).toHaveLength(1);
        expect(scimUser.phoneNumbers?.[0].value).toBe('+1234567890');
        expect(scimUser.meta?.resourceType).toBe('User');
        expect(scimUser.meta?.location).toContain('/scim/v2/Users/user-123');
      });

      it('should include enterprise extension when metadata present', () => {
        const zaltUser: ZaltUser = {
          id: 'user-123',
          realm_id: TEST_REALM_ID,
          email: 'john@example.com',
          email_verified: true,
          profile: {
            metadata: {
              employee_number: 'EMP001',
              department: 'Engineering',
            },
          },
          status: 'active',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-02T00:00:00Z',
        };

        const scimUser = mapper.zaltUserToScim(zaltUser);

        expect(scimUser.schemas).toContain(SCIM_SCHEMAS.ENTERPRISE_USER);
        const enterprise = scimUser['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'];
        expect(enterprise?.employeeNumber).toBe('EMP001');
        expect(enterprise?.department).toBe('Engineering');
      });

      it('should map suspended status to inactive', () => {
        const zaltUser: ZaltUser = {
          id: 'user-123',
          realm_id: TEST_REALM_ID,
          email: 'john@example.com',
          email_verified: true,
          profile: {},
          status: 'suspended',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-02T00:00:00Z',
        };

        const scimUser = mapper.zaltUserToScim(zaltUser);
        expect(scimUser.active).toBe(false);
      });
    });
  });

  // ==========================================================================
  // SCIM USER SERVICE TESTS
  // ==========================================================================
  describe('SCIMUserService', () => {
    let userService: SCIMUserService;

    beforeEach(() => {
      userService = new SCIMUserService(TEST_REALM_ID, TEST_BASE_URL);
    });

    describe('createUser', () => {
      /**
       * Validates: Requirement 31.4 - User created in IdP creates corresponding user
       */
      it('should create a new user', async () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          name: {
            givenName: 'John',
            familyName: 'Doe',
          },
          active: true,
        };

        const result = await userService.createUser(scimUser);

        expect(result.success).toBe(true);
        expect(result.statusCode).toBe(201);
        expect(result.data?.id).toBeDefined();
        expect(result.data?.userName).toBe('john@example.com');
        expect(result.data?.meta?.resourceType).toBe('User');
      });

      it('should reject user without userName', async () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: '',
        };

        const result = await userService.createUser(scimUser);

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(400);
        expect(result.error?.scimType).toBe('invalidValue');
      });

      it('should reject duplicate userName', async () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
        };

        await userService.createUser(scimUser);
        const result = await userService.createUser(scimUser);

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(409);
        expect(result.error?.scimType).toBe('uniqueness');
      });

      it('should reject duplicate externalId', async () => {
        const user1: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          externalId: 'ext-123',
        };
        const user2: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'jane@example.com',
          externalId: 'ext-123',
        };

        await userService.createUser(user1);
        const result = await userService.createUser(user2);

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(409);
      });

      it('should normalize email to lowercase', async () => {
        const scimUser: SCIMUser = {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'JOHN@EXAMPLE.COM',
        };

        const result = await userService.createUser(scimUser);

        expect(result.success).toBe(true);
        expect(result.data?.userName).toBe('john@example.com');
      });
    });


    describe('getUser', () => {
      it('should get an existing user', async () => {
        const createResult = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
        });

        const result = await userService.getUser(createResult.data!.id!);

        expect(result.success).toBe(true);
        expect(result.statusCode).toBe(200);
        expect(result.data?.userName).toBe('john@example.com');
      });

      it('should return 404 for non-existent user', async () => {
        const result = await userService.getUser('non-existent-id');

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(404);
        expect(result.error?.scimType).toBe('noTarget');
      });
    });

    describe('listUsers', () => {
      beforeEach(async () => {
        // Create test users
        await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          name: { givenName: 'John', familyName: 'Doe' },
          active: true,
        });
        await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'jane@example.com',
          name: { givenName: 'Jane', familyName: 'Smith' },
          active: true,
        });
        await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'bob@test.com',
          active: false,
        });
      });

      it('should list all users', async () => {
        const result = await userService.listUsers();

        expect(result.success).toBe(true);
        expect(result.data?.totalResults).toBe(3);
        expect(result.data?.Resources).toHaveLength(3);
      });

      it('should filter users by userName', async () => {
        const result = await userService.listUsers({
          filter: 'userName eq "john@example.com"',
        });

        expect(result.success).toBe(true);
        expect(result.data?.totalResults).toBe(1);
        expect(result.data?.Resources[0].userName).toBe('john@example.com');
      });

      it('should filter users by active status', async () => {
        const result = await userService.listUsers({
          filter: 'active eq true',
        });

        expect(result.success).toBe(true);
        expect(result.data?.totalResults).toBe(2);
      });

      it('should filter users by email domain', async () => {
        const result = await userService.listUsers({
          filter: 'userName co "@example.com"',
        });

        expect(result.success).toBe(true);
        expect(result.data?.totalResults).toBe(2);
      });

      it('should paginate results', async () => {
        const result = await userService.listUsers({
          startIndex: 1,
          count: 2,
        });

        expect(result.success).toBe(true);
        expect(result.data?.itemsPerPage).toBe(2);
        expect(result.data?.startIndex).toBe(1);
      });

      it('should sort users by userName', async () => {
        const result = await userService.listUsers({
          sortBy: 'userName',
          sortOrder: 'ascending',
        });

        expect(result.success).toBe(true);
        const userNames = result.data?.Resources.map(u => u.userName);
        expect(userNames).toEqual([...userNames!].sort());
      });

      it('should sort users descending', async () => {
        const result = await userService.listUsers({
          sortBy: 'userName',
          sortOrder: 'descending',
        });

        expect(result.success).toBe(true);
        const userNames = result.data?.Resources.map(u => u.userName);
        expect(userNames).toEqual([...userNames!].sort().reverse());
      });
    });

    describe('replaceUser', () => {
      it('should replace an existing user', async () => {
        const createResult = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          name: { givenName: 'John' },
        });

        const result = await userService.replaceUser(createResult.data!.id!, {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          name: { givenName: 'Johnny', familyName: 'Doe' },
        });

        expect(result.success).toBe(true);
        expect(result.data?.name?.givenName).toBe('Johnny');
        expect(result.data?.name?.familyName).toBe('Doe');
      });

      it('should return 404 for non-existent user', async () => {
        const result = await userService.replaceUser('non-existent', {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
        });

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(404);
      });

      it('should reject duplicate userName on update', async () => {
        await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
        });
        const jane = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'jane@example.com',
        });

        const result = await userService.replaceUser(jane.data!.id!, {
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com', // Try to use John's email
        });

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(409);
      });
    });


    describe('patchUser', () => {
      it('should patch user with replace operation', async () => {
        const createResult = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          active: true,
        });

        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [
            { op: 'replace', path: 'active', value: false },
          ],
        };

        const result = await userService.patchUser(createResult.data!.id!, patchRequest);

        expect(result.success).toBe(true);
        expect(result.data?.active).toBe(false);
      });

      it('should patch user with add operation', async () => {
        const createResult = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
        });

        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [
            { op: 'add', path: 'name.givenName', value: 'John' },
          ],
        };

        const result = await userService.patchUser(createResult.data!.id!, patchRequest);

        expect(result.success).toBe(true);
        expect(result.data?.name?.givenName).toBe('John');
      });

      it('should patch user with remove operation', async () => {
        const createResult = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          name: { givenName: 'John', familyName: 'Doe' },
        });

        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [
            { op: 'remove', path: 'name.familyName' },
          ],
        };

        const result = await userService.patchUser(createResult.data!.id!, patchRequest);

        expect(result.success).toBe(true);
        expect(result.data?.name?.familyName).toBeUndefined();
      });

      it('should apply multiple patch operations', async () => {
        const createResult = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
          active: true,
        });

        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [
            { op: 'replace', path: 'active', value: false },
            { op: 'add', path: 'name.givenName', value: 'John' },
            { op: 'add', path: 'name.familyName', value: 'Doe' },
          ],
        };

        const result = await userService.patchUser(createResult.data!.id!, patchRequest);

        expect(result.success).toBe(true);
        expect(result.data?.active).toBe(false);
        expect(result.data?.name?.givenName).toBe('John');
        expect(result.data?.name?.familyName).toBe('Doe');
      });

      it('should return 404 for non-existent user', async () => {
        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [{ op: 'replace', path: 'active', value: false }],
        };

        const result = await userService.patchUser('non-existent', patchRequest);

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(404);
      });
    });

    describe('deleteUser', () => {
      /**
       * Validates: Requirement 31.5 - User deactivated in IdP suspends user
       */
      it('should soft delete a user', async () => {
        const createResult = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'john@example.com',
        });

        const result = await userService.deleteUser(createResult.data!.id!);

        expect(result.success).toBe(true);
        expect(result.statusCode).toBe(204);

        // Verify user is marked as deleted
        const getResult = await userService.getUser(createResult.data!.id!);
        expect(getResult.data?.active).toBe(false);
      });

      it('should return 404 for non-existent user', async () => {
        const result = await userService.deleteUser('non-existent');

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(404);
      });
    });
  });


  // ==========================================================================
  // SCIM GROUP SERVICE TESTS
  // ==========================================================================
  describe('SCIMGroupService', () => {
    let groupService: SCIMGroupService;
    let userService: SCIMUserService;
    let testUserId: string;

    beforeEach(async () => {
      groupService = new SCIMGroupService(TEST_REALM_ID, TEST_BASE_URL);
      userService = new SCIMUserService(TEST_REALM_ID, TEST_BASE_URL);

      // Create a test user for group membership
      const userResult = await userService.createUser({
        schemas: [SCIM_SCHEMAS.USER],
        userName: 'member@example.com',
        name: { givenName: 'Test', familyName: 'Member' },
      });
      testUserId = userResult.data!.id!;
    });

    describe('createGroup', () => {
      /**
       * Validates: Requirement 31.7 - Group sync for automatic role assignment
       */
      it('should create a new group', async () => {
        const scimGroup: SCIMGroup = {
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
        };

        const result = await groupService.createGroup(scimGroup);

        expect(result.success).toBe(true);
        expect(result.statusCode).toBe(201);
        expect(result.data?.id).toBeDefined();
        expect(result.data?.displayName).toBe('Engineering');
        expect(result.data?.meta?.resourceType).toBe('Group');
      });

      it('should create group with members', async () => {
        const scimGroup: SCIMGroup = {
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
          members: [{ value: testUserId }],
        };

        const result = await groupService.createGroup(scimGroup);

        expect(result.success).toBe(true);
        expect(result.data?.members).toHaveLength(1);
        expect(result.data?.members?.[0].value).toBe(testUserId);
      });

      it('should reject group without displayName', async () => {
        const scimGroup: SCIMGroup = {
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: '',
        };

        const result = await groupService.createGroup(scimGroup);

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(400);
      });

      it('should reject group with non-existent member', async () => {
        const scimGroup: SCIMGroup = {
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
          members: [{ value: 'non-existent-user' }],
        };

        const result = await groupService.createGroup(scimGroup);

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(400);
      });

      it('should reject duplicate externalId', async () => {
        await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Group 1',
          externalId: 'ext-group-1',
        });

        const result = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Group 2',
          externalId: 'ext-group-1',
        });

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(409);
      });
    });

    describe('getGroup', () => {
      it('should get an existing group', async () => {
        const createResult = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
        });

        const result = await groupService.getGroup(createResult.data!.id!);

        expect(result.success).toBe(true);
        expect(result.statusCode).toBe(200);
        expect(result.data?.displayName).toBe('Engineering');
      });

      it('should return 404 for non-existent group', async () => {
        const result = await groupService.getGroup('non-existent-id');

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(404);
      });

      it('should include member details', async () => {
        const createResult = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
          members: [{ value: testUserId }],
        });

        const result = await groupService.getGroup(createResult.data!.id!);

        expect(result.success).toBe(true);
        expect(result.data?.members?.[0].display).toBeDefined();
      });
    });

    describe('listGroups', () => {
      beforeEach(async () => {
        await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
        });
        await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Marketing',
        });
        await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Sales',
        });
      });

      it('should list all groups', async () => {
        const result = await groupService.listGroups();

        expect(result.success).toBe(true);
        expect(result.data?.totalResults).toBe(3);
      });

      it('should filter groups by displayName', async () => {
        const result = await groupService.listGroups({
          filter: 'displayName eq "Engineering"',
        });

        expect(result.success).toBe(true);
        expect(result.data?.totalResults).toBe(1);
        expect(result.data?.Resources[0].displayName).toBe('Engineering');
      });

      it('should paginate results', async () => {
        const result = await groupService.listGroups({
          startIndex: 1,
          count: 2,
        });

        expect(result.success).toBe(true);
        expect(result.data?.itemsPerPage).toBe(2);
      });
    });


    describe('replaceGroup', () => {
      it('should replace an existing group', async () => {
        const createResult = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
        });

        const result = await groupService.replaceGroup(createResult.data!.id!, {
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering Team',
          members: [{ value: testUserId }],
        });

        expect(result.success).toBe(true);
        expect(result.data?.displayName).toBe('Engineering Team');
        expect(result.data?.members).toHaveLength(1);
      });

      it('should return 404 for non-existent group', async () => {
        const result = await groupService.replaceGroup('non-existent', {
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
        });

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(404);
      });
    });

    describe('patchGroup', () => {
      it('should add members to group', async () => {
        const createResult = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
        });

        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [
            { op: 'add', path: 'members', value: [{ value: testUserId }] },
          ],
        };

        const result = await groupService.patchGroup(createResult.data!.id!, patchRequest);

        expect(result.success).toBe(true);
        expect(result.data?.members).toHaveLength(1);
        expect(result.data?.members?.[0].value).toBe(testUserId);
      });

      it('should remove members from group', async () => {
        const createResult = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
          members: [{ value: testUserId }],
        });

        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [
            { op: 'remove', path: `members[value eq "${testUserId}"]` },
          ],
        };

        const result = await groupService.patchGroup(createResult.data!.id!, patchRequest);

        expect(result.success).toBe(true);
        expect(result.data?.members).toHaveLength(0);
      });

      it('should replace all members', async () => {
        // Create another user
        const user2Result = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'member2@example.com',
        });

        const createResult = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
          members: [{ value: testUserId }],
        });

        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [
            { op: 'replace', path: 'members', value: [{ value: user2Result.data!.id }] },
          ],
        };

        const result = await groupService.patchGroup(createResult.data!.id!, patchRequest);

        expect(result.success).toBe(true);
        expect(result.data?.members).toHaveLength(1);
        expect(result.data?.members?.[0].value).toBe(user2Result.data!.id);
      });

      it('should update displayName', async () => {
        const createResult = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
        });

        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [
            { op: 'replace', path: 'displayName', value: 'Engineering Team' },
          ],
        };

        const result = await groupService.patchGroup(createResult.data!.id!, patchRequest);

        expect(result.success).toBe(true);
        expect(result.data?.displayName).toBe('Engineering Team');
      });

      it('should return 404 for non-existent group', async () => {
        const patchRequest: SCIMPatchRequest = {
          schemas: [SCIM_SCHEMAS.PATCH_OP],
          Operations: [{ op: 'add', path: 'members', value: [] }],
        };

        const result = await groupService.patchGroup('non-existent', patchRequest);

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(404);
      });
    });

    describe('deleteGroup', () => {
      it('should delete a group', async () => {
        const createResult = await groupService.createGroup({
          schemas: [SCIM_SCHEMAS.GROUP],
          displayName: 'Engineering',
        });

        const result = await groupService.deleteGroup(createResult.data!.id!);

        expect(result.success).toBe(true);
        expect(result.statusCode).toBe(204);

        // Verify group is deleted
        const getResult = await groupService.getGroup(createResult.data!.id!);
        expect(getResult.success).toBe(false);
        expect(getResult.statusCode).toBe(404);
      });

      it('should return 404 for non-existent group', async () => {
        const result = await groupService.deleteGroup('non-existent');

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(404);
      });
    });
  });


  // ==========================================================================
  // SCIM BULK SERVICE TESTS
  // ==========================================================================
  describe('SCIMBulkService', () => {
    let bulkService: SCIMBulkService;

    beforeEach(() => {
      bulkService = new SCIMBulkService(TEST_REALM_ID, TEST_BASE_URL);
    });

    describe('processBulk', () => {
      it('should process bulk user creation', async () => {
        const request: SCIMBulkRequest = {
          schemas: [SCIM_SCHEMAS.BULK_REQUEST],
          Operations: [
            {
              method: 'POST',
              path: '/Users',
              bulkId: 'user1',
              data: {
                schemas: [SCIM_SCHEMAS.USER],
                userName: 'john@example.com',
              },
            },
            {
              method: 'POST',
              path: '/Users',
              bulkId: 'user2',
              data: {
                schemas: [SCIM_SCHEMAS.USER],
                userName: 'jane@example.com',
              },
            },
          ],
        };

        const result = await bulkService.processBulk(request);

        expect(result.success).toBe(true);
        expect(result.data?.Operations).toHaveLength(2);
        expect(result.data?.Operations[0].status).toBe('201');
        expect(result.data?.Operations[1].status).toBe('201');
      });

      it('should process mixed operations', async () => {
        // First create a user
        const userService = new SCIMUserService(TEST_REALM_ID, TEST_BASE_URL);
        const createResult = await userService.createUser({
          schemas: [SCIM_SCHEMAS.USER],
          userName: 'existing@example.com',
        });

        const request: SCIMBulkRequest = {
          schemas: [SCIM_SCHEMAS.BULK_REQUEST],
          Operations: [
            {
              method: 'POST',
              path: '/Users',
              bulkId: 'newUser',
              data: {
                schemas: [SCIM_SCHEMAS.USER],
                userName: 'new@example.com',
              },
            },
            {
              method: 'PATCH',
              path: `/Users/${createResult.data!.id}`,
              data: {
                schemas: [SCIM_SCHEMAS.PATCH_OP],
                Operations: [{ op: 'replace', path: 'active', value: false }],
              },
            },
          ],
        };

        const result = await bulkService.processBulk(request);

        expect(result.success).toBe(true);
        expect(result.data?.Operations[0].status).toBe('201');
        expect(result.data?.Operations[1].status).toBe('200');
      });

      it('should handle errors in bulk operations', async () => {
        const request: SCIMBulkRequest = {
          schemas: [SCIM_SCHEMAS.BULK_REQUEST],
          Operations: [
            {
              method: 'POST',
              path: '/Users',
              bulkId: 'user1',
              data: {
                schemas: [SCIM_SCHEMAS.USER],
                userName: 'john@example.com',
              },
            },
            {
              method: 'POST',
              path: '/Users',
              bulkId: 'user2',
              data: {
                schemas: [SCIM_SCHEMAS.USER],
                userName: 'john@example.com', // Duplicate
              },
            },
          ],
        };

        const result = await bulkService.processBulk(request);

        expect(result.success).toBe(true);
        expect(result.data?.Operations[0].status).toBe('201');
        expect(result.data?.Operations[1].status).toBe('409');
      });

      it('should stop on failOnErrors threshold', async () => {
        const request: SCIMBulkRequest = {
          schemas: [SCIM_SCHEMAS.BULK_REQUEST],
          failOnErrors: 1,
          Operations: [
            {
              method: 'DELETE',
              path: '/Users/non-existent',
              bulkId: 'delete1',
            },
            {
              method: 'POST',
              path: '/Users',
              bulkId: 'user1',
              data: {
                schemas: [SCIM_SCHEMAS.USER],
                userName: 'john@example.com',
              },
            },
          ],
        };

        const result = await bulkService.processBulk(request);

        expect(result.success).toBe(true);
        // Should stop after first error
        expect(result.data?.Operations).toHaveLength(1);
      });

      it('should reject bulk request exceeding max operations', async () => {
        const operations = Array.from({ length: 1001 }, (_, i) => ({
          method: 'POST' as const,
          path: '/Users',
          bulkId: `user${i}`,
          data: {
            schemas: [SCIM_SCHEMAS.USER],
            userName: `user${i}@example.com`,
          },
        }));

        const request: SCIMBulkRequest = {
          schemas: [SCIM_SCHEMAS.BULK_REQUEST],
          Operations: operations,
        };

        const result = await bulkService.processBulk(request);

        expect(result.success).toBe(false);
        expect(result.statusCode).toBe(413);
      });

      it('should process group operations', async () => {
        const request: SCIMBulkRequest = {
          schemas: [SCIM_SCHEMAS.BULK_REQUEST],
          Operations: [
            {
              method: 'POST',
              path: '/Groups',
              bulkId: 'group1',
              data: {
                schemas: [SCIM_SCHEMAS.GROUP],
                displayName: 'Engineering',
              },
            },
          ],
        };

        const result = await bulkService.processBulk(request);

        expect(result.success).toBe(true);
        expect(result.data?.Operations[0].status).toBe('201');
      });
    });
  });


  // ==========================================================================
  // SERVICE PROVIDER CONFIGURATION TESTS
  // ==========================================================================
  describe('Service Provider Configuration', () => {
    describe('getServiceProviderConfig', () => {
      it('should return valid service provider config', () => {
        const config = getServiceProviderConfig(TEST_BASE_URL);

        expect(config.schemas).toContain(SCIM_SCHEMAS.SERVICE_PROVIDER_CONFIG);
        expect(config.patch.supported).toBe(true);
        expect(config.bulk.supported).toBe(true);
        expect(config.bulk.maxOperations).toBe(1000);
        expect(config.filter.supported).toBe(true);
        expect(config.sort.supported).toBe(true);
        expect(config.etag.supported).toBe(true);
        expect(config.authenticationSchemes).toHaveLength(1);
        expect(config.authenticationSchemes[0].type).toBe('oauthbearertoken');
      });
    });

    describe('getResourceTypes', () => {
      it('should return User and Group resource types', () => {
        const resourceTypes = getResourceTypes(TEST_BASE_URL);

        expect(resourceTypes).toHaveLength(2);
        
        const userType = resourceTypes.find(r => r.id === 'User');
        expect(userType).toBeDefined();
        expect(userType?.endpoint).toBe('/Users');
        expect(userType?.schema).toBe(SCIM_SCHEMAS.USER);
        expect(userType?.schemaExtensions).toContainEqual({
          schema: SCIM_SCHEMAS.ENTERPRISE_USER,
          required: false,
        });

        const groupType = resourceTypes.find(r => r.id === 'Group');
        expect(groupType).toBeDefined();
        expect(groupType?.endpoint).toBe('/Groups');
        expect(groupType?.schema).toBe(SCIM_SCHEMAS.GROUP);
      });
    });

    describe('getSchemas', () => {
      it('should return User and Group schemas', () => {
        const schemas = getSchemas();

        expect(schemas).toHaveLength(2);
        
        const userSchema = schemas.find(s => s.id === SCIM_SCHEMAS.USER);
        expect(userSchema).toBeDefined();
        expect(userSchema?.name).toBe('User');
        expect(userSchema?.attributes.find(a => a.name === 'userName')).toBeDefined();
        expect(userSchema?.attributes.find(a => a.name === 'userName')?.required).toBe(true);

        const groupSchema = schemas.find(s => s.id === SCIM_SCHEMAS.GROUP);
        expect(groupSchema).toBeDefined();
        expect(groupSchema?.name).toBe('Group');
        expect(groupSchema?.attributes.find(a => a.name === 'displayName')).toBeDefined();
      });
    });
  });

  // ==========================================================================
  // INTEGRATION TESTS
  // ==========================================================================
  describe('SCIM Integration Tests', () => {
    let userService: SCIMUserService;
    let groupService: SCIMGroupService;

    beforeEach(() => {
      userService = new SCIMUserService(TEST_REALM_ID, TEST_BASE_URL);
      groupService = new SCIMGroupService(TEST_REALM_ID, TEST_BASE_URL);
    });

    /**
     * Validates: Requirement 31.1 - SCIM 2.0 for user provisioning
     */
    it('should provision user from IdP and add to group', async () => {
      // 1. IdP creates user via SCIM
      const userResult = await userService.createUser({
        schemas: [SCIM_SCHEMAS.USER, SCIM_SCHEMAS.ENTERPRISE_USER],
        userName: 'newemployee@company.com',
        externalId: 'idp-user-123',
        name: {
          givenName: 'New',
          familyName: 'Employee',
        },
        active: true,
        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': {
          employeeNumber: 'EMP001',
          department: 'Engineering',
        },
      });

      expect(userResult.success).toBe(true);
      const userId = userResult.data!.id!;

      // 2. IdP creates group and adds user
      const groupResult = await groupService.createGroup({
        schemas: [SCIM_SCHEMAS.GROUP],
        displayName: 'Engineering Team',
        externalId: 'idp-group-456',
        members: [{ value: userId }],
      });

      expect(groupResult.success).toBe(true);
      expect(groupResult.data?.members).toHaveLength(1);

      // 3. Verify user is in group
      const getGroupResult = await groupService.getGroup(groupResult.data!.id!);
      expect(getGroupResult.data?.members?.some(m => m.value === userId)).toBe(true);
    });

    /**
     * Validates: Requirement 31.5 - User deactivated in IdP suspends user
     */
    it('should deactivate user when IdP disables account', async () => {
      // 1. Create active user
      const userResult = await userService.createUser({
        schemas: [SCIM_SCHEMAS.USER],
        userName: 'employee@company.com',
        active: true,
      });

      expect(userResult.data?.active).toBe(true);

      // 2. IdP deactivates user via PATCH
      const patchResult = await userService.patchUser(userResult.data!.id!, {
        schemas: [SCIM_SCHEMAS.PATCH_OP],
        Operations: [{ op: 'replace', path: 'active', value: false }],
      });

      expect(patchResult.success).toBe(true);
      expect(patchResult.data?.active).toBe(false);

      // 3. Verify user is inactive
      const getResult = await userService.getUser(userResult.data!.id!);
      expect(getResult.data?.active).toBe(false);
    });

    /**
     * Validates: Requirement 31.6 - Attribute mapping from IdP
     */
    it('should map IdP attributes to Zalt user profile', async () => {
      const userResult = await userService.createUser({
        schemas: [SCIM_SCHEMAS.USER, SCIM_SCHEMAS.ENTERPRISE_USER],
        userName: 'employee@company.com',
        name: {
          givenName: 'John',
          familyName: 'Doe',
          formatted: 'John Doe',
        },
        displayName: 'Johnny D',
        emails: [
          { value: 'employee@company.com', type: 'work', primary: true },
          { value: 'john.personal@gmail.com', type: 'home' },
        ],
        phoneNumbers: [
          { value: '+1234567890', type: 'work', primary: true },
        ],
        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': {
          employeeNumber: 'EMP001',
          department: 'Engineering',
          organization: 'Zalt Inc',
          division: 'Platform',
          costCenter: 'CC-100',
        },
      });

      expect(userResult.success).toBe(true);
      
      // Verify all attributes are mapped
      const user = userResult.data!;
      expect(user.name?.givenName).toBe('John');
      expect(user.name?.familyName).toBe('Doe');
      expect(user.emails?.[0].value).toBe('employee@company.com');
      expect(user.phoneNumbers?.[0].value).toBe('+1234567890');
      
      const enterprise = user['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'];
      expect(enterprise?.employeeNumber).toBe('EMP001');
      expect(enterprise?.department).toBe('Engineering');
    });

    /**
     * Validates: Requirement 31.7 - Group sync for automatic role assignment
     */
    it('should sync group membership changes', async () => {
      // 1. Create users
      const user1 = await userService.createUser({
        schemas: [SCIM_SCHEMAS.USER],
        userName: 'user1@company.com',
      });
      const user2 = await userService.createUser({
        schemas: [SCIM_SCHEMAS.USER],
        userName: 'user2@company.com',
      });

      // 2. Create group with user1
      const groupResult = await groupService.createGroup({
        schemas: [SCIM_SCHEMAS.GROUP],
        displayName: 'Admins',
        members: [{ value: user1.data!.id! }],
      });

      expect(groupResult.data?.members).toHaveLength(1);

      // 3. Add user2 to group
      const patchResult = await groupService.patchGroup(groupResult.data!.id!, {
        schemas: [SCIM_SCHEMAS.PATCH_OP],
        Operations: [
          { op: 'add', path: 'members', value: [{ value: user2.data!.id! }] },
        ],
      });

      expect(patchResult.data?.members).toHaveLength(2);

      // 4. Remove user1 from group
      const removeResult = await groupService.patchGroup(groupResult.data!.id!, {
        schemas: [SCIM_SCHEMAS.PATCH_OP],
        Operations: [
          { op: 'remove', path: `members[value eq "${user1.data!.id!}"]` },
        ],
      });

      expect(removeResult.data?.members).toHaveLength(1);
      expect(removeResult.data?.members?.[0].value).toBe(user2.data!.id!);
    });
  });
});
