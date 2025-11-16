import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesController } from '../../roles.controller';
import { RolesService } from '../../roles.service';
import { UpdateRoleDto } from '../../dto/update-role.dto';
import { JwtAuthGuard } from '../../../auth/guard/logged-in-guard';
import { RoleResponse } from '../../../auth/response/auth-login.response';

// Mock data
const mockRoleResponse: RoleResponse = {
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
    ],
};

const mockRoleResponses: RoleResponse[] = [
    mockRoleResponse,
    {
        id: 2,
        name: 'User',
        key: 'user',
        permissions: [
            {
                id: 3,
                name: 'Read User',
                key: 'users.read',
                resource: 'users',
            },
        ],
    },
];

// Mock RolesService
const mockRolesService = {
    findAll: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
};

// Mock Guards
const mockJwtAuthGuard = {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    canActivate: jest.fn((context: ExecutionContext) => true),
};

// Mock Reflector
const mockReflector = {
    get: jest.fn(),
};

describe('RolesController', () => {
    let controller: RolesController;
    let service: RolesService;
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    let reflector: Reflector;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [RolesController],
            providers: [
                {
                    provide: RolesService,
                    useValue: mockRolesService,
                },
                {
                    provide: Reflector,
                    useValue: mockReflector,
                },
            ],
        })
            .overrideGuard(JwtAuthGuard)
            .useValue(mockJwtAuthGuard)
            .compile();

        controller = module.get<RolesController>(RolesController);
        service = module.get<RolesService>(RolesService);
        reflector = module.get<Reflector>(Reflector);

        jest.clearAllMocks();
    });

    describe('findAll', () => {
        it('should return all roles successfully', async () => {
            // Arrange
            mockRolesService.findAll.mockResolvedValue(mockRoleResponses);

            // Act
            const result = await controller.findAll();

            // Assert
            expect(result).toEqual({
                message: 'Roles retrieved successfully',
                data: mockRoleResponses,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findAll).toHaveBeenCalledWith();
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findAll).toHaveBeenCalledTimes(1);
        });

        it('should return empty array when no roles exist', async () => {
            // Arrange
            mockRolesService.findAll.mockResolvedValue([]);

            // Act
            const result = await controller.findAll();

            // Assert
            expect(result).toEqual({
                message: 'Roles retrieved successfully',
                data: [],
            });
            expect(Array.isArray(result.data)).toBe(true);
            expect(result.data).toHaveLength(0);
        });

        it('should handle service errors during findAll', async () => {
            // Arrange
            const serviceError = new Error('Database error');
            mockRolesService.findAll.mockRejectedValue(serviceError);

            // Act & Assert
            await expect(controller.findAll()).rejects.toThrow(
                'Database error',
            );
        });
    });

    describe('findOne', () => {
        it('should return a role when found', async () => {
            // Arrange
            const roleId = '1';
            mockRolesService.findOne.mockResolvedValue(mockRoleResponse);

            // Act
            const result = await controller.findOne(roleId);

            // Assert
            expect(result).toEqual({
                message: `Role with ID ${roleId} retrieved successfully`,
                data: mockRoleResponse,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(1); // +id conversion
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledTimes(1);
        });

        it('should handle string to number conversion for ID', async () => {
            // Arrange
            const roleId = '999';
            const role = { ...mockRoleResponse, id: 999 };
            mockRolesService.findOne.mockResolvedValue(role);

            // Act
            const result = await controller.findOne(roleId);

            // Assert
            expect(result.data!.id).toBe(999);
            expect(result.message).toBe(
                `Role with ID ${roleId} retrieved successfully`,
            );
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(999);
        });

        it('should propagate service errors for findOne', async () => {
            // Arrange
            const roleId = '999';
            mockRolesService.findOne.mockRejectedValue(
                new Error('Role not found'),
            );

            // Act & Assert
            await expect(controller.findOne(roleId)).rejects.toThrow(
                'Role not found',
            );
        });

        it('should handle roles without permissions', async () => {
            // Arrange
            const roleId = '1';
            const roleWithoutPermissions: RoleResponse = {
                ...mockRoleResponse,
                permissions: [],
            };
            mockRolesService.findOne.mockResolvedValue(roleWithoutPermissions);

            // Act
            const result = await controller.findOne(roleId);

            // Assert
            expect(result.data!.permissions).toHaveLength(0);
            expect(result.data!.permissions).toEqual([]);
        });
    });

    describe('update', () => {
        it('should update a role successfully', async () => {
            // Arrange
            const roleId = '1';
            const updateRoleDto: UpdateRoleDto = {
                permission_ids: [1, 2, 3],
            };

            const updatedRole = {
                ...mockRoleResponse,
                permissions: [
                    ...mockRoleResponse.permissions,
                    {
                        id: 3,
                        name: 'Delete User',
                        key: 'users.delete',
                        resource: 'users',
                    },
                ],
            };
            mockRolesService.update.mockResolvedValue(updatedRole);

            // Act
            const result = await controller.update(roleId, updateRoleDto);

            // Assert
            expect(result).toEqual({
                message: `Role with ID ${roleId} updated successfully`,
                data: updatedRole,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.update).toHaveBeenCalledWith(1, updateRoleDto);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.update).toHaveBeenCalledTimes(1);
        });

        it('should handle string to number conversion for ID in update', async () => {
            // Arrange
            const roleId = '999';
            const updateRoleDto: UpdateRoleDto = {
                permission_ids: [1, 2],
            };

            const updatedRole = { ...mockRoleResponse, id: 999 };
            mockRolesService.update.mockResolvedValue(updatedRole);

            // Act
            const result = await controller.update(roleId, updateRoleDto);

            // Assert
            expect(result.data!.id).toBe(999);
            expect(result.message).toBe(
                `Role with ID ${roleId} updated successfully`,
            );
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.update).toHaveBeenCalledWith(999, updateRoleDto);
        });

        it('should handle empty permission_ids in update', async () => {
            // Arrange
            const roleId = '1';
            const updateRoleDto: UpdateRoleDto = {
                permission_ids: [],
            };

            const updatedRole = {
                ...mockRoleResponse,
                permissions: [],
            };
            mockRolesService.update.mockResolvedValue(updatedRole);

            // Act
            const result = await controller.update(roleId, updateRoleDto);

            // Assert
            expect(result.data!.permissions).toHaveLength(0);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.update).toHaveBeenCalledWith(1, updateRoleDto);
        });

        it('should propagate service errors during update', async () => {
            // Arrange
            const roleId = '1';
            const updateRoleDto: UpdateRoleDto = {
                permission_ids: [1, 2, 3],
            };

            mockRolesService.update.mockRejectedValue(
                new Error('Update failed'),
            );

            // Act & Assert
            await expect(
                controller.update(roleId, updateRoleDto),
            ).rejects.toThrow('Update failed');
        });
    });

    // Test untuk controller guards
    describe('Controller Guards', () => {
        it('should use JwtAuthGuard', () => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const classGuards = Reflect.getMetadata(
                '__guards__',
                RolesController,
            );
            expect(classGuards).toContain(JwtAuthGuard);
        });
    });

    // Edge cases
    describe('Edge Cases', () => {
        it('should handle very large ID numbers', async () => {
            // Arrange
            const largeId = '9999999999';
            const role = { ...mockRoleResponse, id: 9999999999 };
            mockRolesService.findOne.mockResolvedValue(role);

            // Act
            const result = await controller.findOne(largeId);

            // Assert
            expect(result.data!.id).toBe(9999999999);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(9999999999);
        });

        it('should handle special characters in role names', async () => {
            // Arrange
            const roleWithSpecialChars: RoleResponse = {
                id: 1,
                name: 'Super Admin & Manager (All Access)',
                key: 'super_admin',
                permissions: [
                    {
                        id: 1,
                        name: 'Create & Update Users',
                        key: 'users.write',
                        resource: 'users',
                    },
                ],
            };
            mockRolesService.findAll.mockResolvedValue([roleWithSpecialChars]);

            // Act
            const result = await controller.findAll();

            // Assert
            expect(result.data![0].name).toContain('&');
            expect(result.data![0].name).toContain('(');
            expect(result.data![0].permissions[0].name).toContain('&');
        });

        it('should handle numeric string IDs with leading zeros', async () => {
            // Arrange
            const roleId = '001'; // Leading zeros
            const role = { ...mockRoleResponse, id: 1 }; // Should convert to number 1
            mockRolesService.findOne.mockResolvedValue(role);

            // Act
            const result = await controller.findOne(roleId);

            // Assert
            expect(result.data!.id).toBe(1);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(1); // +'001' = 1
        });

        it('should handle update with single permission', async () => {
            // Arrange
            const roleId = '1';
            const updateRoleDto: UpdateRoleDto = {
                permission_ids: [1], // Single permission
            };

            const updatedRole = {
                ...mockRoleResponse,
                permissions: [mockRoleResponse.permissions[0]],
            };
            mockRolesService.update.mockResolvedValue(updatedRole);

            // Act
            const result = await controller.update(roleId, updateRoleDto);

            // Assert
            expect(result.data!.permissions).toHaveLength(1);
            expect(result.message).toBe(
                `Role with ID ${roleId} updated successfully`,
            );
        });
    });
});
