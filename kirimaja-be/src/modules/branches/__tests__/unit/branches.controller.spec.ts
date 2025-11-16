import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, BadRequestException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { BranchesController } from '../../branches.controller';
import { BranchesService } from '../../branches.service';
import { CreateBranchDto } from '../../dto/create-branch.dto';
import { UpdateBranchDto } from '../../dto/update-branch.dto';
import { JwtAuthGuard } from '../../../auth/guard/logged-in-guard';
import { PermissionGuard } from '../../../auth/guard/permission.guard';
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { RequirePermissions } from '../../../auth/decorators/permissions.decorator';
import { Branch } from '@prisma/client';

// Mock data
const mockBranch: Branch = {
    id: 1,
    name: 'Test Branch',
    address: 'Jl. Test No.123',
    phoneNumber: '081234567890',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
};

const mockBranches: Branch[] = [
    mockBranch,
    {
        id: 2,
        name: 'Test Branch 2',
        address: 'Jl. Test No.456',
        phoneNumber: '081234567891',
        createdAt: new Date('2024-01-02'),
        updatedAt: new Date('2024-01-02'),
    },
];

// Mock BranchesService
const mockBranchesService = {
    create: jest.fn(),
    findAll: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
};

// Mock Guards
const mockJwtAuthGuard = {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    canActivate: jest.fn((context: ExecutionContext) => true),
};

const mockPermissionGuard = {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    canActivate: jest.fn((context: ExecutionContext) => true),
};

// Mock Reflector untuk permission decorator
const mockReflector = {
    get: jest.fn(),
};

describe('BranchesController', () => {
    let controller: BranchesController;
    let service: BranchesService;
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    let reflector: Reflector;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [BranchesController],
            providers: [
                {
                    provide: BranchesService,
                    useValue: mockBranchesService,
                },
                {
                    provide: Reflector,
                    useValue: mockReflector,
                },
            ],
        })
            .overrideGuard(JwtAuthGuard)
            .useValue(mockJwtAuthGuard)
            .overrideGuard(PermissionGuard)
            .useValue(mockPermissionGuard)
            .compile();

        controller = module.get<BranchesController>(BranchesController);
        service = module.get<BranchesService>(BranchesService);
        reflector = module.get<Reflector>(Reflector);

        jest.clearAllMocks();
    });

    describe('create', () => {
        it('should create a new branch successfully', async () => {
            // Arrange
            const createBranchDto: CreateBranchDto = {
                name: 'New Branch',
                address: 'Jl. New Branch No.123',
                phone_number: '081234567890',
            };

            mockBranchesService.create.mockResolvedValue(mockBranch);

            // Act
            const result = await controller.create(createBranchDto);

            // Assert
            expect(result).toEqual({
                message: 'Branch created successfully',
                data: mockBranch,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.create).toHaveBeenCalledWith(createBranchDto);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.create).toHaveBeenCalledTimes(1);
        });

        it('should handle service errors during creation', async () => {
            // Arrange
            const createBranchDto: CreateBranchDto = {
                name: 'New Branch',
                address: 'Jl. New Branch No.123',
                phone_number: '081234567890',
            };

            const serviceError = new BadRequestException('Invalid data');
            mockBranchesService.create.mockRejectedValue(serviceError);

            // Act & Assert
            await expect(controller.create(createBranchDto)).rejects.toThrow(
                BadRequestException,
            );
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.create).toHaveBeenCalledWith(createBranchDto);
        });
    });

    describe('findAll', () => {
        it('should return all branches successfully', async () => {
            // Arrange
            mockBranchesService.findAll.mockResolvedValue(mockBranches);

            // Act
            const result = await controller.findAll();

            // Assert
            expect(result).toEqual({
                message: 'Branches retrieved successfully',
                data: mockBranches,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findAll).toHaveBeenCalledWith();
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findAll).toHaveBeenCalledTimes(1);
        });

        it('should return empty array when no branches exist', async () => {
            // Arrange
            mockBranchesService.findAll.mockResolvedValue([]);

            // Act
            const result = await controller.findAll();

            // Assert
            expect(result).toEqual({
                message: 'Branches retrieved successfully',
                data: [],
            });
            expect(Array.isArray(result.data)).toBe(true);
            expect(result.data).toHaveLength(0);
        });
    });

    describe('findOne', () => {
        it('should return a branch when found', async () => {
            // Arrange
            const branchId = '1';
            mockBranchesService.findOne.mockResolvedValue(mockBranch);

            // Act
            const result = await controller.findOne(branchId);

            // Assert
            expect(result).toEqual({
                message: `Branch with ID ${branchId} retrieved successfully`,
                data: mockBranch,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(1); // +id conversion
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledTimes(1);
        });

        it('should handle string to number conversion for ID', async () => {
            // Arrange
            const branchId = '999';
            const branch = { ...mockBranch, id: 999 };
            mockBranchesService.findOne.mockResolvedValue(branch);

            // Act
            const result = await controller.findOne(branchId);

            // Assert
            expect(result.data!.id).toBe(999);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(999);
        });

        it('should propagate service errors for findOne', async () => {
            // Arrange
            const branchId = '999';
            mockBranchesService.findOne.mockRejectedValue(
                new BadRequestException('Branch not found'),
            );

            // Act & Assert
            await expect(controller.findOne(branchId)).rejects.toThrow(
                BadRequestException,
            );
        });
    });

    describe('update', () => {
        it('should update a branch successfully', async () => {
            // Arrange
            const branchId = '1';
            const updateBranchDto: UpdateBranchDto = {
                name: 'Updated Branch Name',
                address: 'Updated Address',
                phone_number: '081234567899',
            };

            const updatedBranch = { ...mockBranch, ...updateBranchDto };
            mockBranchesService.update.mockResolvedValue(updatedBranch);

            // Act
            const result = await controller.update(branchId, updateBranchDto);

            // Assert
            expect(result).toEqual({
                message: `Branch with ID ${branchId} updated successfully`,
                data: updatedBranch,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.update).toHaveBeenCalledWith(1, updateBranchDto);
        });

        it('should handle partial updates', async () => {
            // Arrange
            const branchId = '1';
            const partialUpdateDto: UpdateBranchDto = {
                name: 'Partially Updated Name',
                // address and phone_number not provided
            };

            const partiallyUpdatedBranch = {
                ...mockBranch,
                name: 'Partially Updated Name',
            };
            mockBranchesService.update.mockResolvedValue(
                partiallyUpdatedBranch,
            );

            // Act
            const result = await controller.update(branchId, partialUpdateDto);

            // Assert
            expect(result.data!.name).toBe('Partially Updated Name');
            expect(result.data!.address).toBe(mockBranch.address); // Should remain unchanged
        });
    });

    describe('remove', () => {
        it('should delete a branch successfully', async () => {
            // Arrange
            const branchId = '1';
            mockBranchesService.remove.mockResolvedValue(undefined);

            // Act
            const result = await controller.remove(branchId);

            // Assert
            expect(result).toEqual({
                message: `Branch with ID ${branchId} deleted successfully`,
                data: null,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.remove).toHaveBeenCalledWith(1);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.remove).toHaveBeenCalledTimes(1);
        });

        it('should handle service errors during deletion', async () => {
            // Arrange
            const branchId = '1';
            mockBranchesService.remove.mockRejectedValue(
                new BadRequestException('Delete failed'),
            );

            // Act & Assert
            await expect(controller.remove(branchId)).rejects.toThrow(
                BadRequestException,
            );
        });
    });

    // Test untuk permission decorators
    describe('Permission Decorators', () => {
        it('should have correct permissions for create', () => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const permissions = Reflect.getMetadata(
                'permissions',
                // eslint-disable-next-line @typescript-eslint/unbound-method
                BranchesController.prototype.create,
            );
            expect(permissions).toContain('branches.create'); // ← Check jika ada dalam array
            expect(Array.isArray(permissions)).toBe(true);
        });

        it('should have correct permissions for findAll', () => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const permissions = Reflect.getMetadata(
                'permissions',
                // eslint-disable-next-line @typescript-eslint/unbound-method
                BranchesController.prototype.findAll,
            );
            expect(permissions).toContain('branches.read');
            expect(Array.isArray(permissions)).toBe(true);
        });

        it('should have correct permissions for findOne', () => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const permissions = Reflect.getMetadata(
                'permissions',
                // eslint-disable-next-line @typescript-eslint/unbound-method
                BranchesController.prototype.findOne,
            );
            expect(permissions).toContain('branches.read');
            expect(Array.isArray(permissions)).toBe(true);
        });

        it('should have correct permissions for update', () => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const permissions = Reflect.getMetadata(
                'permissions',
                // eslint-disable-next-line @typescript-eslint/unbound-method
                BranchesController.prototype.update,
            );
            expect(permissions).toContain('branches.update');
            expect(Array.isArray(permissions)).toBe(true);
        });

        it('should have correct permissions for remove', () => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const permissions = Reflect.getMetadata(
                'permissions',
                // eslint-disable-next-line @typescript-eslint/unbound-method
                BranchesController.prototype.remove,
            );
            expect(permissions).toContain('branches.delete');
            expect(Array.isArray(permissions)).toBe(true);
        });
    });

    // Test untuk controller guards
    describe('Controller Guards', () => {
        it('should use JwtAuthGuard and PermissionGuard', () => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const classGuards = Reflect.getMetadata(
                '__guards__',
                BranchesController,
            );
            expect(classGuards).toContain(JwtAuthGuard);
            expect(classGuards).toContain(PermissionGuard);
        });
    });

    // Edge cases
    describe('Edge Cases', () => {
        it('should handle very large ID numbers', async () => {
            // Arrange
            const largeId = '9999999999';
            const branch = { ...mockBranch, id: 9999999999 };
            mockBranchesService.findOne.mockResolvedValue(branch);

            // Act
            const result = await controller.findOne(largeId);

            // Assert
            expect(result.data!.id).toBe(9999999999);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(9999999999);
        });

        it('should handle special characters in DTO data', async () => {
            // Arrange
            const createBranchDto: CreateBranchDto = {
                name: 'Branch & Co. (Main) - "Premium"',
                address: 'Jl. Test No.123, RT 01/RW 02',
                phone_number: '+62-812-3456-7890',
            };

            const branchWithSpecialChars = {
                ...mockBranch,
                ...createBranchDto,
            };
            mockBranchesService.create.mockResolvedValue(
                branchWithSpecialChars,
            );

            // Act
            const result = await controller.create(createBranchDto);

            // Assert
            expect(result.data!.name).toContain('&');
            expect(result.data!.name).toContain('"');
            expect(result.data!.address).toContain(',');
        });
    });
});
