import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { RolesService } from '../../roles.service';
import { PrismaService } from '../../../../common/prisma/prisma.service';
import { UpdateRoleDto } from '../../dto/update-role.dto';
import { RoleResponse } from '../../../auth/response/auth-login.response';

describe('RolesService', () => {
    let service: RolesService;
    let prismaService: PrismaService;

    // Mock data
    const mockRole = {
        id: 1,
        name: 'Admin',
        key: 'admin',
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-01'),
    };

    const mockPermission = {
        id: 1,
        name: 'Create User',
        key: 'users.create',
        resource: 'users',
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-01'),
    };

    const mockRoleWithPermissions = {
        ...mockRole,
        rolePermissions: [
            {
                id: 1,
                roleId: 1,
                permissionId: 1,
                createdAt: new Date('2024-01-01'),
                updatedAt: new Date('2024-01-01'),
                permission: mockPermission,
            },
        ],
    };

    const mockRoles = [
        mockRoleWithPermissions,
        {
            id: 2,
            name: 'User',
            key: 'user',
            createdAt: new Date('2024-01-02'),
            updatedAt: new Date('2024-01-02'),
            rolePermissions: [
                {
                    id: 2,
                    roleId: 2,
                    permissionId: 2,
                    createdAt: new Date('2024-01-02'),
                    updatedAt: new Date('2024-01-02'),
                    permission: {
                        id: 2,
                        name: 'Read User',
                        key: 'users.read',
                        resource: 'users',
                        createdAt: new Date('2024-01-02'),
                        updatedAt: new Date('2024-01-02'),
                    },
                },
            ],
        },
    ];

    const expectedRoleResponse: RoleResponse = {
        id: 1,
        name: 'Admin',
        key: 'admin',
        permissions: [
            {
                id: 1,
                name: 'Create User',
                key: 'users.create',
                resource: 'users',
            },
        ],
    };

    // Mock PrismaService
    const mockPrismaService = {
        role: {
            findMany: jest.fn(),
            findUnique: jest.fn(),
        },
        rolePermission: {
            deleteMany: jest.fn(),
            createMany: jest.fn(),
        },
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                RolesService,
                {
                    provide: PrismaService,
                    useValue: mockPrismaService,
                },
            ],
        }).compile();

        service = module.get<RolesService>(RolesService);
        prismaService = module.get<PrismaService>(PrismaService);

        jest.clearAllMocks();
    });

    describe('findAll', () => {
        it('should return all roles with permissions', async () => {
            // Arrange
            mockPrismaService.role.findMany.mockResolvedValue(mockRoles);

            const expectedResponse: RoleResponse[] = [
                {
                    id: 1,
                    name: 'Admin',
                    key: 'admin',
                    permissions: [
                        {
                            id: 1,
                            name: 'Create User',
                            key: 'users.create',
                            resource: 'users',
                        },
                    ],
                },
                {
                    id: 2,
                    name: 'User',
                    key: 'user',
                    permissions: [
                        {
                            id: 2,
                            name: 'Read User',
                            key: 'users.read',
                            resource: 'users',
                        },
                    ],
                },
            ];

            // Act
            const result = await service.findAll();

            // Assert
            expect(result).toEqual(expectedResponse);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(prismaService.role.findMany).toHaveBeenCalledWith({
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(prismaService.role.findMany).toHaveBeenCalledTimes(1);
        });

        it('should return empty array when no roles exist', async () => {
            // Arrange
            mockPrismaService.role.findMany.mockResolvedValue([]);

            // Act
            const result = await service.findAll();

            // Assert
            expect(result).toEqual([]);
            expect(Array.isArray(result)).toBe(true);
            expect(result).toHaveLength(0);
        });

        it('should handle roles without permissions', async () => {
            // Arrange
            const roleWithoutPermissions = {
                ...mockRole,
                rolePermissions: [],
            };
            mockPrismaService.role.findMany.mockResolvedValue([
                roleWithoutPermissions,
            ]);

            const expectedResponse: RoleResponse[] = [
                {
                    id: 1,
                    name: 'Admin',
                    key: 'admin',
                    permissions: [],
                },
            ];

            // Act
            const result = await service.findAll();

            // Assert
            expect(result).toEqual(expectedResponse);
            expect(result[0].permissions).toHaveLength(0);
        });
    });

    describe('findOne', () => {
        it('should return a role with permissions when found', async () => {
            // Arrange
            const roleId = 1;
            mockPrismaService.role.findUnique.mockResolvedValue(
                mockRoleWithPermissions,
            );

            // Act
            const result = await service.findOne(roleId);

            // Assert
            expect(result).toEqual(expectedRoleResponse);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(prismaService.role.findUnique).toHaveBeenCalledWith({
                where: { id: roleId },
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(prismaService.role.findUnique).toHaveBeenCalledTimes(1);
        });

        it('should throw NotFoundException when role does not exist', async () => {
            // Arrange
            const roleId = 999;
            mockPrismaService.role.findUnique.mockResolvedValue(null);

            // Act & Assert
            await expect(service.findOne(roleId)).rejects.toThrow(
                NotFoundException,
            );
            await expect(service.findOne(roleId)).rejects.toThrow(
                `Role with Id ${roleId} not found`,
            );
        });

        it('should handle role without permissions', async () => {
            // Arrange
            const roleWithoutPermissions = {
                ...mockRole,
                rolePermissions: [],
            };
            mockPrismaService.role.findUnique.mockResolvedValue(
                roleWithoutPermissions,
            );

            const expectedResponse: RoleResponse = {
                id: 1,
                name: 'Admin',
                key: 'admin',
                permissions: [],
            };

            // Act
            const result = await service.findOne(1);

            // Assert
            expect(result).toEqual(expectedResponse);
            expect(result.permissions).toHaveLength(0);
        });
    });

    describe('update', () => {
        const updateRoleDto: UpdateRoleDto = {
            permission_ids: [1, 2, 3],
        };

        const updatedRoleWithPermissions = {
            ...mockRoleWithPermissions,
            rolePermissions: [
                {
                    ...mockRoleWithPermissions.rolePermissions[0],
                    permission: {
                        ...mockPermission,
                        id: 1,
                    },
                },
                {
                    id: 2,
                    roleId: 1,
                    permissionId: 2,
                    createdAt: new Date('2024-01-01'),
                    updatedAt: new Date('2024-01-01'),
                    permission: {
                        id: 2,
                        name: 'Update User',
                        key: 'users.update',
                        resource: 'users',
                        createdAt: new Date('2024-01-01'),
                        updatedAt: new Date('2024-01-01'),
                    },
                },
                {
                    id: 3,
                    roleId: 1,
                    permissionId: 3,
                    createdAt: new Date('2024-01-01'),
                    updatedAt: new Date('2024-01-01'),
                    permission: {
                        id: 3,
                        name: 'Delete User',
                        key: 'users.delete',
                        resource: 'users',
                        createdAt: new Date('2024-01-01'),
                        updatedAt: new Date('2024-01-01'),
                    },
                },
            ],
        };

        beforeEach(() => {
            // Mock findOne method (which is called internally in update)
            jest.spyOn(service, 'findOne').mockResolvedValue(
                expectedRoleResponse,
            );
        });

        it('should update role permissions successfully', async () => {
            // Arrange
            const roleId = 1;
            mockPrismaService.rolePermission.deleteMany.mockResolvedValue({
                count: 1,
            });
            mockPrismaService.rolePermission.createMany.mockResolvedValue({
                count: 3,
            });
            jest.spyOn(service, 'findOne')
                .mockResolvedValueOnce(expectedRoleResponse) // First call in update method
                .mockResolvedValueOnce({
                    // Second call for return value
                    id: 1,
                    name: 'Admin',
                    key: 'admin',
                    permissions: [
                        {
                            id: 1,
                            name: 'Create User',
                            key: 'users.create',
                            resource: 'users',
                        },
                        {
                            id: 2,
                            name: 'Update User',
                            key: 'users.update',
                            resource: 'users',
                        },
                        {
                            id: 3,
                            name: 'Delete User',
                            key: 'users.delete',
                            resource: 'users',
                        },
                    ],
                });

            // Act
            const result = await service.update(roleId, updateRoleDto);

            // Assert
            expect(result.permissions).toHaveLength(3);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(
                // eslint-disable-next-line @typescript-eslint/unbound-method
                prismaService.rolePermission.deleteMany,
            ).toHaveBeenCalledWith({
                where: { roleId },
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(
                // eslint-disable-next-line @typescript-eslint/unbound-method
                prismaService.rolePermission.createMany,
            ).toHaveBeenCalledWith({
                data: [
                    { roleId, permissionId: 1 },
                    { roleId, permissionId: 2 },
                    { roleId, permissionId: 3 },
                ],
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(roleId);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledTimes(2);
        });

        it('should handle empty permission_ids array', async () => {
            // Arrange
            const roleId = 1;
            const updateRoleDtoEmpty: UpdateRoleDto = {
                permission_ids: [],
            };
            mockPrismaService.rolePermission.deleteMany.mockResolvedValue({
                count: 1,
            });
            jest.spyOn(service, 'findOne')
                .mockResolvedValueOnce(expectedRoleResponse)
                .mockResolvedValueOnce({
                    ...expectedRoleResponse,
                    permissions: [],
                });

            // Act
            const result = await service.update(roleId, updateRoleDtoEmpty);

            // Assert
            expect(result.permissions).toHaveLength(0);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(
                // eslint-disable-next-line @typescript-eslint/unbound-method
                prismaService.rolePermission.deleteMany,
            ).toHaveBeenCalledWith({
                where: { roleId },
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(
                // eslint-disable-next-line @typescript-eslint/unbound-method
                prismaService.rolePermission.createMany,
            ).not.toHaveBeenCalled();
        });

        it('should throw NotFoundException when role does not exist', async () => {
            // Arrange
            const roleId = 999;
            const notFoundError = new NotFoundException(
                `Role with Id ${roleId} not found`,
            );
            jest.spyOn(service, 'findOne').mockRejectedValue(notFoundError);

            // Act & Assert
            await expect(service.update(roleId, updateRoleDto)).rejects.toThrow(
                NotFoundException,
            );
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(
                // eslint-disable-next-line @typescript-eslint/unbound-method
                prismaService.rolePermission.deleteMany,
            ).not.toHaveBeenCalled();
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(
                // eslint-disable-next-line @typescript-eslint/unbound-method
                prismaService.rolePermission.createMany,
            ).not.toHaveBeenCalled();
        });

        it('should handle database errors during permission deletion', async () => {
            // Arrange
            const roleId = 1;
            const dbError = new Error('Database connection failed');
            jest.spyOn(service, 'findOne').mockResolvedValue(
                expectedRoleResponse,
            );
            mockPrismaService.rolePermission.deleteMany.mockRejectedValue(
                dbError,
            );

            // Act & Assert
            await expect(service.update(roleId, updateRoleDto)).rejects.toThrow(
                'Database connection failed',
            );
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(
                // eslint-disable-next-line @typescript-eslint/unbound-method
                prismaService.rolePermission.createMany,
            ).not.toHaveBeenCalled();
        });

        it('should handle database errors during permission creation', async () => {
            // Arrange
            const roleId = 1;
            const dbError = new Error('Database connection failed');
            jest.spyOn(service, 'findOne').mockResolvedValue(
                expectedRoleResponse,
            );
            mockPrismaService.rolePermission.deleteMany.mockResolvedValue({
                count: 1,
            });
            mockPrismaService.rolePermission.createMany.mockRejectedValue(
                dbError,
            );

            // Act & Assert
            await expect(service.update(roleId, updateRoleDto)).rejects.toThrow(
                'Database connection failed',
            );
        });
    });

    // Edge cases
    describe('Edge Cases', () => {
        it('should handle very large role ID numbers', async () => {
            // Arrange
            const largeId = 9999999999;
            const roleWithLargeId = {
                ...mockRoleWithPermissions,
                id: largeId,
            };
            mockPrismaService.role.findUnique.mockResolvedValue(
                roleWithLargeId,
            );

            // Act
            const result = await service.findOne(largeId);

            // Assert
            expect(result.id).toBe(largeId);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(prismaService.role.findUnique).toHaveBeenCalledWith({
                where: { id: largeId },
                include: {
                    rolePermissions: {
                        include: {
                            permission: true,
                        },
                    },
                },
            });
        });

        it('should handle update with duplicate permission IDs by creating duplicates', async () => {
            // Arrange
            const roleId = 1;
            const updateRoleDtoWithDuplicates: UpdateRoleDto = {
                permission_ids: [1, 1, 2, 2, 3], // Duplicate IDs
            };

            jest.spyOn(service, 'findOne')
                .mockResolvedValueOnce(expectedRoleResponse)
                .mockResolvedValueOnce({
                    ...expectedRoleResponse,
                    permissions: [
                        {
                            id: 1,
                            name: 'Create User',
                            key: 'users.create',
                            resource: 'users',
                        },
                        {
                            id: 2,
                            name: 'Update User',
                            key: 'users.update',
                            resource: 'users',
                        },
                        {
                            id: 3,
                            name: 'Delete User',
                            key: 'users.delete',
                            resource: 'users',
                        },
                    ],
                });

            mockPrismaService.rolePermission.deleteMany.mockResolvedValue({
                count: 1,
            });
            mockPrismaService.rolePermission.createMany.mockResolvedValue({
                count: 5,
            }); // Should create all including duplicates

            // Act
            const result = await service.update(
                roleId,
                updateRoleDtoWithDuplicates,
            );

            // Assert
            expect(result.permissions).toHaveLength(3);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(
                prismaService.rolePermission.createMany,
            ).toHaveBeenCalledWith({
                data: [
                    { roleId, permissionId: 1 },
                    { roleId, permissionId: 1 }, // Duplicate
                    { roleId, permissionId: 2 },
                    { roleId, permissionId: 2 }, // Duplicate
                    { roleId, permissionId: 3 },
                ],
            });
        });
    });
});
