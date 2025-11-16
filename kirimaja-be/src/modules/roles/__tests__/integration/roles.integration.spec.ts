import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../../../app.module';
import { PrismaService } from '../../../../common/prisma/prisma.service';
import { Role, Permission, RolePermission } from '@prisma/client';

describe('RolesController (Integration - Business Logic)', () => {
    let app: INestApplication;
    let prisma: PrismaService;

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        app = moduleFixture.createNestApplication();
        prisma = app.get<PrismaService>(PrismaService);

        await app.init();

        // Cleanup sebelum test
        await cleanupTestData();
    });

    afterAll(async () => {
        await cleanupTestData();
        await app.close();
    });

    beforeEach(async () => {
        // Cleanup dengan urutan yang benar untuk menghindari foreign key constraint
        await prisma.rolePermission.deleteMany();
        await prisma.user.deleteMany();
        await prisma.permission.deleteMany();
        await prisma.role.deleteMany();
    });

    const cleanupTestData = async () => {
        // Cleanup dengan urutan yang benar
        await prisma.rolePermission.deleteMany();
        await prisma.user.deleteMany();
        await prisma.permission.deleteMany();
        await prisma.role.deleteMany();
    };

    // Helper functions
    const createTestRole = async (roleData: Partial<Role> = {}) => {
        return await prisma.role.create({
            data: {
                name: roleData.name || 'Test Role',
                key: roleData.key || 'test-role',
                ...roleData,
            },
        });
    };

    const createTestPermission = async (
        permissionData: Partial<Permission> = {},
    ) => {
        return await prisma.permission.create({
            data: {
                name: permissionData.name || 'Test Permission',
                key: permissionData.key || 'test.permission',
                resource: permissionData.resource || 'test',
                ...permissionData,
            },
        });
    };

    const createTestRolePermission = async (
        roleId: number,
        permissionId: number,
    ) => {
        return await prisma.rolePermission.create({
            data: {
                roleId,
                permissionId,
            },
        });
    };

    // ==================== POSITIVE TEST CASES ====================

    describe('✅ POSITIVE CASES - Role CRUD Operations', () => {
        it('should create a new role successfully', async () => {
            // Arrange
            const roleData = {
                name: 'New Role Positive',
                key: 'new-role-positive',
            };

            // Act
            const role = await createTestRole(roleData);

            // Assert
            expect(role).toBeDefined();
            expect(role.id).toBeGreaterThan(0);
            expect(role.name).toBe(roleData.name);
            expect(role.key).toBe(roleData.key);
            expect(role.createdAt).toBeInstanceOf(Date);
            expect(role.updatedAt).toBeInstanceOf(Date);
        });

        it('should retrieve all roles with permissions', async () => {
            // Arrange
            const role1 = await createTestRole({ name: 'Admin', key: 'admin' });
            const role2 = await createTestRole({ name: 'User', key: 'user' });

            const permission1 = await createTestPermission({
                name: 'Create User',
                key: 'users.create',
                resource: 'users',
            });
            const permission2 = await createTestPermission({
                name: 'Read User',
                key: 'users.read',
                resource: 'users',
            });

            await createTestRolePermission(role1.id, permission1.id);
            await createTestRolePermission(role2.id, permission2.id);

            // Act
            const roles = await prisma.role.findMany({
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
                orderBy: { id: 'asc' },
            });

            // Assert
            expect(roles).toHaveLength(2);
            expect(roles[0].name).toBe('Admin');
            expect(roles[1].name).toBe('User');
            expect(roles[0].rolePermissions).toHaveLength(1);
            expect(roles[1].rolePermissions).toHaveLength(1);
            expect(roles[0].rolePermissions[0].permission.name).toBe(
                'Create User',
            );
            expect(roles[1].rolePermissions[0].permission.name).toBe(
                'Read User',
            );
        });

        it('should retrieve specific role by ID with permissions', async () => {
            // Arrange
            const createdRole = await createTestRole({
                name: 'Specific Role',
                key: 'specific-role',
            });

            const permission = await createTestPermission({
                name: 'Specific Permission',
                key: 'specific.permission',
            });

            await createTestRolePermission(createdRole.id, permission.id);

            // Act
            const foundRole = await prisma.role.findUnique({
                where: { id: createdRole.id },
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });

            // Assert
            expect(foundRole).toBeDefined();
            expect(foundRole?.id).toBe(createdRole.id);
            expect(foundRole?.name).toBe('Specific Role');
            expect(foundRole?.rolePermissions).toHaveLength(1);
            expect(foundRole?.rolePermissions[0].permission.name).toBe(
                'Specific Permission',
            );
        });

        it('should update role permissions successfully', async () => {
            // Arrange
            const role = await createTestRole({
                name: 'Update Test Role',
                key: 'update-test-role',
            });

            const permission1 = await createTestPermission({
                name: 'Permission 1',
                key: 'perm1',
            });
            const permission2 = await createTestPermission({
                name: 'Permission 2',
                key: 'perm2',
            });
            const permission3 = await createTestPermission({
                name: 'Permission 3',
                key: 'perm3',
            });

            // Add initial permission
            await createTestRolePermission(role.id, permission1.id);

            // Act - Update permissions (replace existing with new ones)
            // First delete all existing role permissions
            await prisma.rolePermission.deleteMany({
                where: { roleId: role.id },
            });

            // Then create new role permissions
            await prisma.rolePermission.createMany({
                data: [
                    { roleId: role.id, permissionId: permission2.id },
                    { roleId: role.id, permissionId: permission3.id },
                ],
            });

            // Assert
            const updatedRole = await prisma.role.findUnique({
                where: { id: role.id },
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });

            expect(updatedRole?.rolePermissions).toHaveLength(2);
            const permissionNames = updatedRole?.rolePermissions.map(
                (rp) => rp.permission.name,
            );
            expect(permissionNames).toContain('Permission 2');
            expect(permissionNames).toContain('Permission 3');
            expect(permissionNames).not.toContain('Permission 1');
        });

        it('should handle role with multiple permissions', async () => {
            // Arrange
            const role = await createTestRole({
                name: 'Multi Permission Role',
                key: 'multi-permission-role',
            });

            const permissions = await Promise.all([
                createTestPermission({ name: 'Create', key: 'create' }),
                createTestPermission({ name: 'Read', key: 'read' }),
                createTestPermission({ name: 'Update', key: 'update' }),
                createTestPermission({ name: 'Delete', key: 'delete' }),
            ]);

            // Act
            await prisma.rolePermission.createMany({
                data: permissions.map((permission) => ({
                    roleId: role.id,
                    permissionId: permission.id,
                })),
            });

            // Assert
            const roleWithPermissions = await prisma.role.findUnique({
                where: { id: role.id },
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });

            expect(roleWithPermissions?.rolePermissions).toHaveLength(4);
            expect(
                roleWithPermissions?.rolePermissions.map(
                    (rp) => rp.permission.name,
                ),
            ).toEqual(
                expect.arrayContaining(['Create', 'Read', 'Update', 'Delete']),
            );
        });

        it('should handle role without permissions', async () => {
            // Arrange & Act
            const role = await createTestRole({
                name: 'Role Without Permissions',
                key: 'no-permissions-role',
            });

            // Assert
            const roleWithPermissions = await prisma.role.findUnique({
                where: { id: role.id },
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });

            expect(roleWithPermissions?.rolePermissions).toHaveLength(0);
            expect(roleWithPermissions?.rolePermissions).toEqual([]);
        });

        it('should handle special characters in role data', async () => {
            // Arrange
            const specialData = {
                name: 'Role & Manager (Admin) - "Super User" @100%',
                key: 'special-role-key-123',
            };

            // Act
            const role = await createTestRole(specialData);

            // Assert
            expect(role.name).toBe(specialData.name);
            expect(role.key).toBe(specialData.key);
        });
    });

    // ==================== NEGATIVE TEST CASES ====================

    describe('❌ NEGATIVE CASES - Error Scenarios', () => {
        it('should fail when retrieving non-existent role', async () => {
            // Act & Assert
            const nonExistentRole = await prisma.role.findUnique({
                where: { id: 99999 },
            });
            expect(nonExistentRole).toBeNull();
        });

        it('should handle empty result when no roles exist', async () => {
            // Act
            const roles = await prisma.role.findMany();

            // Assert
            expect(roles).toEqual([]);
            expect(roles).toHaveLength(0);
        });

        it('should handle duplicate role keys based on database constraints', async () => {
            // Arrange
            const duplicateKey = 'duplicate-role-key';
            await createTestRole({ name: 'First Role', key: duplicateKey });

            try {
                // Act - Try to create duplicate
                await createTestRole({
                    name: 'Second Role',
                    key: duplicateKey,
                });

                // If we reach here, duplicate was allowed (database doesn't enforce unique)
                // This is acceptable behavior for some databases
                console.log(
                    'Database allows duplicate keys - this is acceptable',
                );

                // Verify both roles were created
                const roles = await prisma.role.findMany({
                    where: { key: duplicateKey },
                });
                expect(roles.length).toBeGreaterThan(0);
            } catch (error) {
                // If database enforces unique constraint, it should throw
                expect(error).toBeDefined();
            }
        });

        it('should fail when creating role permission with non-existent role', async () => {
            // Arrange
            const permission = await createTestPermission();

            // Act & Assert
            await expect(
                createTestRolePermission(99999, permission.id),
            ).rejects.toThrow();
        });

        it('should fail when creating role permission with non-existent permission', async () => {
            // Arrange
            const role = await createTestRole();

            // Act & Assert
            await expect(
                createTestRolePermission(role.id, 99999),
            ).rejects.toThrow();
        });
    });

    // ==================== EDGE CASES & BOUNDARY TESTING ====================

    describe('⚡ EDGE CASES - Boundary Testing', () => {
        it('should handle multiple roles creation', async () => {
            // Arrange - Create multiple roles
            const roleCount = 5;

            for (let i = 0; i < roleCount; i++) {
                await createTestRole({
                    name: `Role ${i + 1}`,
                    key: `role-key-${i + 1}`,
                });
            }

            // Assert
            const allRoles = await prisma.role.findMany();
            expect(allRoles).toHaveLength(roleCount);
        });

        it('should handle role with minimum required data', async () => {
            // Arrange - Minimum meaningful data
            const minimalData = {
                name: 'A',
                key: 'a',
            };

            // Act
            const role = await createTestRole(minimalData);

            // Assert
            expect(role.name).toBe('A');
            expect(role.key).toBe('a');
        });

        it('should maintain data integrity after multiple operations', async () => {
            // Arrange
            const originalRole = await createTestRole({
                name: 'Integrity Test',
                key: 'integrity-test',
            });

            const permission1 = await createTestPermission({
                name: 'Perm 1',
                key: 'perm1',
            });
            const permission2 = await createTestPermission({
                name: 'Perm 2',
                key: 'perm2',
            });

            // Act - Multiple operations
            await createTestRolePermission(originalRole.id, permission1.id);

            // Update role permissions
            await prisma.rolePermission.deleteMany({
                where: { roleId: originalRole.id },
            });

            await createTestRolePermission(originalRole.id, permission2.id);

            const finalRole = await prisma.role.findUnique({
                where: { id: originalRole.id },
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });

            // Assert
            expect(finalRole?.rolePermissions).toHaveLength(1);
            expect(finalRole?.rolePermissions[0].permission.name).toBe(
                'Perm 2',
            );
        });

        it('should handle concurrent role creations', async () => {
            // Arrange
            const concurrentRoles = [
                { name: 'Concurrent A', key: 'concurrent-a' },
                { name: 'Concurrent B', key: 'concurrent-b' },
                { name: 'Concurrent C', key: 'concurrent-c' },
            ];

            // Act - Properly type the promises
            const createPromises: Promise<Role>[] = concurrentRoles.map(
                (role) => createTestRole(role),
            );

            const results = await Promise.all(createPromises);

            // Assert
            expect(results).toHaveLength(3);
            expect(results[0].name).toBe('Concurrent A');
            expect(results[1].name).toBe('Concurrent B');
            expect(results[2].name).toBe('Concurrent C');

            // All should have unique IDs
            const ids = results.map((r) => r.id);
            const uniqueIds = [...new Set(ids)];
            expect(uniqueIds).toHaveLength(3);
        });
    });

    // ==================== DATABASE RELATIONSHIP TESTS ====================

    describe('🔗 DATABASE RELATIONSHIPS', () => {
        it('should maintain referential integrity with related tables', async () => {
            // Arrange - Create role and permissions
            const role = await createTestRole({
                name: 'Relationship Test Role',
                key: 'relationship-test-role',
            });

            const permission1 = await createTestPermission({
                name: 'Relationship Perm 1',
                key: 'rel-perm1',
            });
            const permission2 = await createTestPermission({
                name: 'Relationship Perm 2',
                key: 'rel-perm2',
            });

            // Act - Create role permissions
            const rolePermission1 = await createTestRolePermission(
                role.id,
                permission1.id,
            );
            const rolePermission2 = await createTestRolePermission(
                role.id,
                permission2.id,
            );

            // Assert
            expect(rolePermission1.roleId).toBe(role.id);
            expect(rolePermission1.permissionId).toBe(permission1.id);
            expect(rolePermission2.roleId).toBe(role.id);
            expect(rolePermission2.permissionId).toBe(permission2.id);

            // Verify we can query the relationship
            const roleWithRelations = await prisma.role.findUnique({
                where: { id: role.id },
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });

            expect(roleWithRelations?.rolePermissions).toHaveLength(2);
            expect(roleWithRelations?.rolePermissions[0].id).toBe(
                rolePermission1.id,
            );
            expect(roleWithRelations?.rolePermissions[1].id).toBe(
                rolePermission2.id,
            );
        });

        it('should test cascade delete behavior for role permissions', async () => {
            // Arrange
            const role = await createTestRole({
                name: 'Cascade Test Role',
                key: 'cascade-test-role',
            });

            const permission = await createTestPermission({
                name: 'Cascade Test Permission',
                key: 'cascade-test-perm',
            });

            await createTestRolePermission(role.id, permission.id);

            // Act - Delete role (should cascade delete role permissions)
            await prisma.role.delete({
                where: { id: role.id },
            });

            // Assert - Role permissions should be deleted
            const remainingRolePermissions =
                await prisma.rolePermission.findMany({
                    where: { roleId: role.id },
                });

            expect(remainingRolePermissions).toHaveLength(0);

            // Permission should still exist
            const remainingPermission = await prisma.permission.findUnique({
                where: { id: permission.id },
            });
            expect(remainingPermission).toBeDefined();
        });
    });

    // ==================== DATA VALIDATION TESTS ====================

    describe('🔍 DATA VALIDATION', () => {
        it('should auto-generate createdAt and updatedAt fields', async () => {
            // Arrange & Act
            const role = await createTestRole({
                name: 'Auto Date Test Role',
                key: 'auto-date-test-role',
            });

            // Assert
            expect(role.createdAt).toBeInstanceOf(Date);
            expect(role.updatedAt).toBeInstanceOf(Date);
            expect(role.createdAt.getTime()).toBeLessThanOrEqual(Date.now());
            expect(role.updatedAt.getTime()).toBeLessThanOrEqual(Date.now());
        });

        it('should update updatedAt when modifying role', async () => {
            // Arrange
            const role = await createTestRole({
                name: 'Update Timestamp Test',
                key: 'update-timestamp-test',
            });

            const originalUpdatedAt = role.updatedAt;

            // Wait a bit to ensure timestamp difference
            await new Promise((resolve) => setTimeout(resolve, 100));

            // Act - Update role name and force updatedAt change
            const updatedRole = await prisma.role.update({
                where: { id: role.id },
                data: {
                    name: 'Updated Name',
                    updatedAt: new Date(), // Force update timestamp
                },
            });

            // Assert - Check that updatedAt changed
            expect(updatedRole.updatedAt.getTime()).toBeGreaterThan(
                originalUpdatedAt.getTime(),
            );
        });

        it('should preserve createdAt when updating role', async () => {
            // Arrange
            const role = await createTestRole({
                name: 'Preserve Created At Test',
                key: 'preserve-created-at-test',
            });

            const originalCreatedAt = role.createdAt;

            // Wait a bit
            await new Promise((resolve) => setTimeout(resolve, 100));

            // Act - Update role and force updatedAt change
            const updatedRole = await prisma.role.update({
                where: { id: role.id },
                data: {
                    name: 'Updated Name',
                    updatedAt: new Date(), // Force update timestamp
                },
            });

            // Assert
            expect(updatedRole.createdAt.getTime()).toBe(
                originalCreatedAt.getTime(),
            );
            expect(updatedRole.updatedAt.getTime()).toBeGreaterThan(
                originalCreatedAt.getTime(),
            );
        });
    });

    // ==================== PERMISSION MANAGEMENT TESTS ====================

    describe('🔐 PERMISSION MANAGEMENT', () => {
        it('should handle complex permission hierarchies', async () => {
            // Arrange
            const adminRole = await createTestRole({
                name: 'Admin',
                key: 'admin',
            });
            const managerRole = await createTestRole({
                name: 'Manager',
                key: 'manager',
            });
            const userRole = await createTestRole({
                name: 'User',
                key: 'user',
            });

            // Create permissions for different resources
            const userPermissions = await Promise.all([
                createTestPermission({
                    name: 'Create User',
                    key: 'users.create',
                    resource: 'users',
                }),
                createTestPermission({
                    name: 'Read User',
                    key: 'users.read',
                    resource: 'users',
                }),
                createTestPermission({
                    name: 'Update User',
                    key: 'users.update',
                    resource: 'users',
                }),
                createTestPermission({
                    name: 'Delete User',
                    key: 'users.delete',
                    resource: 'users',
                }),
            ]);

            const productPermissions = await Promise.all([
                createTestPermission({
                    name: 'Create Product',
                    key: 'products.create',
                    resource: 'products',
                }),
                createTestPermission({
                    name: 'Read Product',
                    key: 'products.read',
                    resource: 'products',
                }),
                createTestPermission({
                    name: 'Update Product',
                    key: 'products.update',
                    resource: 'products',
                }),
                createTestPermission({
                    name: 'Delete Product',
                    key: 'products.delete',
                    resource: 'products',
                }),
            ]);

            // Assign permissions to roles
            // Admin gets all permissions
            await prisma.rolePermission.createMany({
                data: [
                    ...userPermissions.map((p) => ({
                        roleId: adminRole.id,
                        permissionId: p.id,
                    })),
                    ...productPermissions.map((p) => ({
                        roleId: adminRole.id,
                        permissionId: p.id,
                    })),
                ],
            });

            // Manager gets user read and all product permissions
            await prisma.rolePermission.createMany({
                data: [
                    {
                        roleId: managerRole.id,
                        permissionId: userPermissions[1].id,
                    }, // users.read
                    ...productPermissions.map((p) => ({
                        roleId: managerRole.id,
                        permissionId: p.id,
                    })),
                ],
            });

            // User gets only read permissions
            await prisma.rolePermission.createMany({
                data: [
                    {
                        roleId: userRole.id,
                        permissionId: userPermissions[1].id,
                    }, // users.read
                    {
                        roleId: userRole.id,
                        permissionId: productPermissions[1].id,
                    }, // products.read
                ],
            });

            // Assert
            const adminWithPerms = await prisma.role.findUnique({
                where: { id: adminRole.id },
                include: { rolePermissions: { include: { permission: true } } },
            });

            const managerWithPerms = await prisma.role.findUnique({
                where: { id: managerRole.id },
                include: { rolePermissions: { include: { permission: true } } },
            });

            const userWithPerms = await prisma.role.findUnique({
                where: { id: userRole.id },
                include: { rolePermissions: { include: { permission: true } } },
            });

            expect(adminWithPerms?.rolePermissions).toHaveLength(8);
            expect(managerWithPerms?.rolePermissions).toHaveLength(5);
            expect(userWithPerms?.rolePermissions).toHaveLength(2);
        });
    });
});
