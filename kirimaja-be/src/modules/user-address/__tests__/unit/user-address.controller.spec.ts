import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, BadRequestException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserAddressController } from '../../user-address.controller';
import { UserAddressService } from '../../user-address.service';
import { CreateUserAddressDto } from '../../dto/create-user-address.dto';
import { UpdateUserAddressDto } from '../../dto/update-user-address.dto';
import { JwtAuthGuard } from '../../../auth/guard/logged-in-guard';
import { UserAddress } from '@prisma/client';

// Mock data
const mockUserAddress: UserAddress = {
    id: 1,
    userId: 1,
    address: 'Test Address',
    tag: 'home',
    label: 'Home',
    photo: 'photo.jpg',
    latitude: -6.2,
    longitude: 106.8,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
};

const mockUserAddresses: UserAddress[] = [
    mockUserAddress,
    {
        id: 2,
        userId: 1,
        address: 'Test Address 2',
        tag: 'work',
        label: 'Office',
        photo: 'photo2.jpg',
        latitude: -6.3,
        longitude: 106.9,
        createdAt: new Date('2024-01-02'),
        updatedAt: new Date('2024-01-02'),
    },
];

// Mock UserAddressService
const mockUserAddressService = {
    create: jest.fn(),
    findAll: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
    cleanupPhotoFile: jest.fn(),
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

// Mock Request
const createMockRequest = (userId: number) =>
    ({
        user: { id: userId },
        headers: {},
        method: 'GET',
        url: '/',
        body: {},
        params: {},
        query: {},
        cookies: {},
    }) as any;

describe('UserAddressController', () => {
    let controller: UserAddressController;
    let service: UserAddressService;
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    let reflector: Reflector;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [UserAddressController],
            providers: [
                {
                    provide: UserAddressService,
                    useValue: mockUserAddressService,
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

        controller = module.get<UserAddressController>(UserAddressController);
        service = module.get<UserAddressService>(UserAddressService);
        reflector = module.get<Reflector>(Reflector);

        jest.clearAllMocks();
    });

    describe('create', () => {
        it('should create a new user address successfully without photo', async () => {
            // Arrange
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Test Address',
                tag: 'home',
                label: 'Home',
                photo: null,
            };

            const req = createMockRequest(1);
            mockUserAddressService.create.mockResolvedValue(mockUserAddress);

            // Act
            const result = await controller.create(
                createUserAddressDto,
                req,
                null as any, // Type assertion untuk null
            );

            // Assert
            expect(result).toEqual({
                message: 'User address created successfully',
                data: mockUserAddress,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.create).toHaveBeenCalledWith(
                createUserAddressDto,
                1,
                null,
            );
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.create).toHaveBeenCalledTimes(1);
        });

        it('should create a new user address successfully with photo', async () => {
            // Arrange
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Test Address',
                tag: 'home',
                label: 'Home',
                photo: null,
            };

            const mockFile = {
                filename: 'test-photo.jpg',
                originalname: 'photo.jpg',
                mimetype: 'image/jpeg',
                size: 1024,
            } as Express.Multer.File;

            const req = createMockRequest(1);
            mockUserAddressService.create.mockResolvedValue(mockUserAddress);

            // Act
            const result = await controller.create(
                createUserAddressDto,
                req,
                mockFile,
            );

            // Assert
            expect(result).toEqual({
                message: 'User address created successfully',
                data: mockUserAddress,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.create).toHaveBeenCalledWith(
                createUserAddressDto,
                1,
                'test-photo.jpg',
            );
        });

        it('should cleanup photo file when creation fails', async () => {
            // Arrange
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Test Address',
                tag: 'home',
                label: 'Home',
                photo: null,
            };

            const mockFile = {
                filename: 'test-photo.jpg',
                originalname: 'photo.jpg',
                mimetype: 'image/jpeg',
                size: 1024,
            } as Express.Multer.File;

            const req = createMockRequest(1);
            const serviceError = new BadRequestException('Creation failed');
            mockUserAddressService.create.mockRejectedValue(serviceError);
            mockUserAddressService.cleanupPhotoFile.mockResolvedValue(
                undefined,
            );

            // Act & Assert
            await expect(
                controller.create(createUserAddressDto, req, mockFile),
            ).rejects.toThrow(BadRequestException);

            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.cleanupPhotoFile).toHaveBeenCalledWith(
                'test-photo.jpg',
            );
        });

        it('should handle service errors during creation', async () => {
            // Arrange
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Test Address',
                tag: 'home',
                label: 'Home',
                photo: null,
            };

            const req = createMockRequest(1);
            const serviceError = new BadRequestException('Invalid data');
            mockUserAddressService.create.mockRejectedValue(serviceError);

            // Act & Assert
            await expect(
                controller.create(createUserAddressDto, req, null as any),
            ).rejects.toThrow(BadRequestException);
        });
    });

    describe('findAll', () => {
        it('should return all user addresses for authenticated user', async () => {
            // Arrange
            const req = createMockRequest(1);
            mockUserAddressService.findAll.mockResolvedValue(mockUserAddresses);

            // Act
            const result = await controller.findAll(req);

            // Assert
            expect(result).toEqual({
                message: 'User addresses retrieved successfully',
                data: mockUserAddresses,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findAll).toHaveBeenCalledWith(1);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findAll).toHaveBeenCalledTimes(1);
        });

        it('should return empty array when user has no addresses', async () => {
            // Arrange
            const req = createMockRequest(1);
            mockUserAddressService.findAll.mockResolvedValue([]);

            // Act
            const result = await controller.findAll(req);

            // Assert
            expect(result).toEqual({
                message: 'User addresses retrieved successfully',
                data: [],
            });
            expect(Array.isArray(result.data)).toBe(true);
            expect(result.data).toHaveLength(0);
        });
    });

    describe('findOne', () => {
        it('should return a user address when found', async () => {
            // Arrange
            const addressId = 1;
            mockUserAddressService.findOne.mockResolvedValue(mockUserAddress);

            // Act
            const result = await controller.findOne(addressId);

            // Assert
            expect(result).toEqual({
                message: 'User address retrieved successfully',
                data: mockUserAddress,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(1);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledTimes(1);
        });

        it('should propagate service errors for findOne', async () => {
            // Arrange
            const addressId = 999;
            mockUserAddressService.findOne.mockRejectedValue(
                new BadRequestException('User address not found'),
            );

            // Act & Assert
            await expect(controller.findOne(addressId)).rejects.toThrow(
                BadRequestException,
            );
        });
    });

    describe('update', () => {
        it('should update a user address successfully without photo', async () => {
            // Arrange
            const addressId = 1;
            const updateUserAddressDto: UpdateUserAddressDto = {
                address: 'Updated Address',
                tag: 'work',
            };

            const updatedAddress = {
                ...mockUserAddress,
                ...updateUserAddressDto,
            };
            mockUserAddressService.update.mockResolvedValue(updatedAddress);

            // Act
            const result = await controller.update(
                addressId,
                updateUserAddressDto,
                null as any, // Type assertion untuk null
            );

            // Assert
            expect(result).toEqual({
                message: 'User address updated successfully',
                data: updatedAddress,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.update).toHaveBeenCalledWith(
                1,
                updateUserAddressDto,
                null,
            );
        });

        it('should update a user address successfully with photo', async () => {
            // Arrange
            const addressId = 1;
            const updateUserAddressDto: UpdateUserAddressDto = {
                address: 'Updated Address',
                tag: 'work',
            };

            const mockFile = {
                filename: 'updated-photo.jpg',
                originalname: 'photo.jpg',
                mimetype: 'image/jpeg',
                size: 1024,
            } as Express.Multer.File;

            const updatedAddress = {
                ...mockUserAddress,
                ...updateUserAddressDto,
                photo: 'updated-photo.jpg',
            };
            mockUserAddressService.update.mockResolvedValue(updatedAddress);

            // Act
            const result = await controller.update(
                addressId,
                updateUserAddressDto,
                mockFile,
            );

            // Assert
            expect(result).toEqual({
                message: 'User address updated successfully',
                data: updatedAddress,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.update).toHaveBeenCalledWith(
                1,
                updateUserAddressDto,
                'updated-photo.jpg',
            );
        });

        it('should cleanup photo file when update fails', async () => {
            // Arrange
            const addressId = 1;
            const updateUserAddressDto: UpdateUserAddressDto = {
                address: 'Updated Address',
                tag: 'work',
            };

            const mockFile = {
                filename: 'updated-photo.jpg',
                originalname: 'photo.jpg',
                mimetype: 'image/jpeg',
                size: 1024,
            } as Express.Multer.File;

            const serviceError = new BadRequestException('Update failed');
            mockUserAddressService.update.mockRejectedValue(serviceError);
            mockUserAddressService.cleanupPhotoFile.mockResolvedValue(
                undefined,
            );

            // Act & Assert
            await expect(
                controller.update(addressId, updateUserAddressDto, mockFile),
            ).rejects.toThrow(BadRequestException);

            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.cleanupPhotoFile).toHaveBeenCalledWith(
                'updated-photo.jpg',
            );
        });

        it('should handle partial updates', async () => {
            // Arrange
            const addressId = 1;
            const partialUpdateDto: UpdateUserAddressDto = {
                tag: 'vacation',
                // address and label not provided
            };

            const partiallyUpdatedAddress = {
                ...mockUserAddress,
                tag: 'vacation',
            };
            mockUserAddressService.update.mockResolvedValue(
                partiallyUpdatedAddress,
            );

            // Act
            const result = await controller.update(
                addressId,
                partialUpdateDto,
                null as any, // Type assertion untuk null
            );

            // Assert
            expect(result.data!.tag).toBe('vacation');
            expect(result.data!.address).toBe(mockUserAddress.address); // Should remain unchanged
        });
    });

    describe('remove', () => {
        it('should delete a user address successfully', async () => {
            // Arrange
            const addressId = 1;
            mockUserAddressService.remove.mockResolvedValue(undefined);

            // Act
            const result = await controller.remove(addressId);

            // Assert
            expect(result).toEqual({
                message: 'User address deleted successfully',
                data: null,
            });
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.remove).toHaveBeenCalledWith(1);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.remove).toHaveBeenCalledTimes(1);
        });

        it('should handle service errors during deletion', async () => {
            // Arrange
            const addressId = 1;
            mockUserAddressService.remove.mockRejectedValue(
                new BadRequestException('Delete failed'),
            );

            // Act & Assert
            await expect(controller.remove(addressId)).rejects.toThrow(
                BadRequestException,
            );
        });
    });

    // Test untuk controller guards
    describe('Controller Guards', () => {
        it('should use JwtAuthGuard', () => {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const classGuards = Reflect.getMetadata(
                '__guards__',
                UserAddressController,
            );
            expect(classGuards).toContain(JwtAuthGuard);
        });
    });

    // Edge cases
    describe('Edge Cases', () => {
        it('should handle very large ID numbers', async () => {
            // Arrange
            const largeId = 9999999999;
            const address = { ...mockUserAddress, id: 9999999999 };
            mockUserAddressService.findOne.mockResolvedValue(address);

            // Act
            const result = await controller.findOne(largeId);

            // Assert
            expect(result.data!.id).toBe(9999999999);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findOne).toHaveBeenCalledWith(9999999999);
        });

        it('should handle special characters in address data', async () => {
            // Arrange
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Jl. Test No.123, RT 01/RW 02, Kec. "Special" & Co.',
                tag: 'home & office',
                label: 'Main Address (Primary)',
                photo: null,
            };

            const addressWithSpecialChars = {
                ...mockUserAddress,
                ...createUserAddressDto,
            };
            mockUserAddressService.create.mockResolvedValue(
                addressWithSpecialChars,
            );

            const req = createMockRequest(1);

            // Act
            const result = await controller.create(
                createUserAddressDto,
                req,
                null as any, // Type assertion untuk null
            );

            // Assert
            expect(result.data!.address).toContain('&');
            expect(result.data!.address).toContain('"');
            expect(result.data!.tag).toContain('&');
        });

        it('should handle null user ID in request', async () => {
            // Arrange
            const req = createMockRequest(null as any);
            mockUserAddressService.findAll.mockResolvedValue([]);

            // Act
            const result = await controller.findAll(req);

            // Assert
            expect(result.data).toEqual([]);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(service.findAll).toHaveBeenCalledWith(null);
        });
    });
});
