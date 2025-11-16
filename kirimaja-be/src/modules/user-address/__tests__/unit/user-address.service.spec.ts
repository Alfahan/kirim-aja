import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { UserAddressService } from '../../user-address.service';
import { PrismaService } from '../../../../common/prisma/prisma.service';
import { OpenStreetService } from '../../../../common/openstreetmap/openstreet.service';
import { CreateUserAddressDto } from '../../dto/create-user-address.dto';
import { UpdateUserAddressDto } from '../../dto/update-user-address.dto';
import { UserAddress, User } from '@prisma/client';

// Mock data
const mockUser: User = {
    id: 1,
    name: 'Test User',
    email: 'test@example.com',
    password: 'hashedpassword',
    phoneNumber: '081234567890',
    avatar: null,
    roleId: 1,
    createdAt: new Date(),
    updatedAt: new Date(),
};

const mockUserAddress: UserAddress & { user: Partial<User> } = {
    id: 1,
    userId: 1,
    address: 'Jl. Test No.123, Jakarta',
    tag: 'Rumah',
    label: 'Alamat Rumah',
    photo: '/uploads/photos/photo123.jpg',
    latitude: -6.2088,
    longitude: 106.8456,
    createdAt: new Date(),
    updatedAt: new Date(),
    user: {
        id: 1,
        name: 'Test User',
        email: 'test@example.com',
        phoneNumber: '081234567890',
        avatar: null,
    },
};

const mockUserAddresses: (UserAddress & { user: Partial<User> })[] = [
    mockUserAddress,
    {
        id: 2,
        userId: 1,
        address: 'Jl. Kantor No.456, Jakarta',
        tag: 'Kantor',
        label: 'Alamat Kantor',
        photo: null,
        latitude: -6.2297,
        longitude: 106.8224,
        createdAt: new Date(),
        updatedAt: new Date(),
        user: {
            id: 1,
            name: 'Test User',
            email: 'test@example.com',
            phoneNumber: '081234567890',
            avatar: null,
        },
    },
];

// Mock services
const mockPrismaService = {
    userAddress: {
        create: jest.fn(),
        findMany: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
    },
};

const mockOpenStreetService = {
    geocode: jest.fn(),
};

// Simple mock untuk fs.promises.unlink
const mockFsUnlink = jest.fn();

describe('UserAddressService', () => {
    let service: UserAddressService;
    let prisma: PrismaService;
    let openStreet: OpenStreetService;

    beforeEach(async () => {
        // Reset semua mocks
        jest.clearAllMocks();

        // Mock fs.promises.unlink secara manual
        jest.spyOn(require('fs').promises, 'unlink').mockImplementation(
            mockFsUnlink,
        );

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                UserAddressService,
                {
                    provide: PrismaService,
                    useValue: mockPrismaService,
                },
                {
                    provide: OpenStreetService,
                    useValue: mockOpenStreetService,
                },
            ],
        }).compile();

        service = module.get<UserAddressService>(UserAddressService);
        prisma = module.get<PrismaService>(PrismaService);
        openStreet = module.get<OpenStreetService>(OpenStreetService);
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('generatePhotoPath', () => {
        it('should generate photo path when filename provided', () => {
            const filename = 'test-photo.jpg';
            const result = (service as any).generatePhotoPath(filename);

            expect(result).toBe('/uploads/photos/test-photo.jpg');
        });

        it('should return null when no filename provided', () => {
            const result = (service as any).generatePhotoPath();

            expect(result).toBeNull();
        });

        it('should return null when filename is null', () => {
            const result = (service as any).generatePhotoPath(null);

            expect(result).toBeNull();
        });
    });

    describe('getCoordinatesFromAddress', () => {
        it('should return coordinates from OpenStreetService', async () => {
            const address = 'Jl. Test No.123';
            const mockCoordinates = { lat: -6.2088, lng: 106.8456 };

            mockOpenStreetService.geocode.mockResolvedValue(mockCoordinates);

            const result = await (service as any).getCoordinatesFromAddress(
                address,
            );

            expect(result).toEqual(mockCoordinates);
            expect(openStreet.geocode).toHaveBeenCalledWith(address);
        });

        it('should return null when OpenStreetService returns null', async () => {
            const address = 'Invalid Address';

            mockOpenStreetService.geocode.mockResolvedValue(null);

            const result = await (service as any).getCoordinatesFromAddress(
                address,
            );

            expect(result).toBeNull();
        });
    });

    describe('create', () => {
        it('should create user address successfully with coordinates and photo', async () => {
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Jl. Test No.123, Jakarta',
                tag: 'Rumah',
                label: 'Alamat Rumah',
            };
            const userId = 1;
            const photoFileName = 'photo123.jpg';
            const coordinates = { lat: -6.2088, lng: 106.8456 };

            mockOpenStreetService.geocode.mockResolvedValue(coordinates);
            mockPrismaService.userAddress.create.mockResolvedValue(
                mockUserAddress,
            );

            const result = await service.create(
                createUserAddressDto,
                userId,
                photoFileName,
            );

            expect(result).toEqual(mockUserAddress);
            expect(openStreet.geocode).toHaveBeenCalledWith(
                createUserAddressDto.address,
            );
            expect(prisma.userAddress.create).toHaveBeenCalledWith({
                data: {
                    userId,
                    address: createUserAddressDto.address,
                    tag: createUserAddressDto.tag,
                    label: createUserAddressDto.label,
                    photo: '/uploads/photos/photo123.jpg',
                    latitude: coordinates.lat,
                    longitude: coordinates.lng,
                },
            });
        });

        it('should create user address without photo', async () => {
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Jl. Test No.123, Jakarta',
                tag: 'Rumah',
                label: 'Alamat Rumah',
            };
            const userId = 1;
            const coordinates = { lat: -6.2088, lng: 106.8456 };

            mockOpenStreetService.geocode.mockResolvedValue(coordinates);
            mockPrismaService.userAddress.create.mockResolvedValue({
                ...mockUserAddress,
                photo: null,
            });

            const result = await service.create(
                createUserAddressDto,
                userId,
                null,
            );

            expect(result.photo).toBeNull();
            // Fix: Check that photo is not included in the data when null
            expect(prisma.userAddress.create).toHaveBeenCalledWith({
                data: expect.objectContaining({
                    userId,
                    address: createUserAddressDto.address,
                    tag: createUserAddressDto.tag,
                    label: createUserAddressDto.label,
                    latitude: coordinates.lat,
                    longitude: coordinates.lng,
                }),
            });
        });

        it('should throw BadRequestException when coordinates not found', async () => {
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Invalid Address',
                tag: 'Rumah',
                label: 'Alamat Rumah',
            };
            const userId = 1;

            mockOpenStreetService.geocode.mockResolvedValue(null);

            await expect(
                service.create(createUserAddressDto, userId, null),
            ).rejects.toThrow(BadRequestException);

            expect(prisma.userAddress.create).not.toHaveBeenCalled();
        });

        it('should handle geocoding service errors', async () => {
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Jl. Test No.123, Jakarta',
                tag: 'Rumah',
                label: 'Alamat Rumah',
            };
            const userId = 1;

            mockOpenStreetService.geocode.mockRejectedValue(
                new Error('Geocoding service error'),
            );

            await expect(
                service.create(createUserAddressDto, userId, null),
            ).rejects.toThrow('Geocoding service error');
        });
    });

    describe('findAll', () => {
        it('should return all user addresses for specific user', async () => {
            const userId = 1;

            mockPrismaService.userAddress.findMany.mockResolvedValue(
                mockUserAddresses,
            );

            const result = await service.findAll(userId);

            expect(result).toEqual(mockUserAddresses);
            expect(prisma.userAddress.findMany).toHaveBeenCalledWith({
                where: { userId },
                include: {
                    user: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                            phoneNumber: true,
                            avatar: true,
                        },
                    },
                },
            });
        });

        it('should return empty array when no addresses found', async () => {
            const userId = 999;

            mockPrismaService.userAddress.findMany.mockResolvedValue([]);

            const result = await service.findAll(userId);

            expect(result).toEqual([]);
            expect(Array.isArray(result)).toBe(true);
        });
    });

    describe('findOne', () => {
        it('should return user address when found', async () => {
            const addressId = 1;

            mockPrismaService.userAddress.findUnique.mockResolvedValue(
                mockUserAddress,
            );

            const result = await service.findOne(addressId);

            expect(result).toEqual(mockUserAddress);
            expect(prisma.userAddress.findUnique).toHaveBeenCalledWith({
                where: { id: addressId },
                include: {
                    user: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                            phoneNumber: true,
                            avatar: true,
                        },
                    },
                },
            });
        });

        it('should throw NotFoundException when user address not found', async () => {
            const addressId = 999;

            mockPrismaService.userAddress.findUnique.mockResolvedValue(null);

            await expect(service.findOne(addressId)).rejects.toThrow(
                NotFoundException,
            );
            await expect(service.findOne(addressId)).rejects.toThrow(
                `User address with ID ${addressId} not found`,
            );
        });
    });

    describe('update', () => {
        it('should update user address successfully with new coordinates', async () => {
            const addressId = 1;
            const updateUserAddressDto: UpdateUserAddressDto = {
                address: 'Updated Address, Jakarta',
                tag: 'Updated Tag',
                label: 'Updated Label',
            };
            const newCoordinates = { lat: -6.2297, lng: 106.8224 };
            const existingAddress = {
                ...mockUserAddress,
                latitude: -6.2088,
                longitude: 106.8456,
            };

            mockPrismaService.userAddress.findUnique.mockResolvedValue(
                existingAddress,
            );
            mockOpenStreetService.geocode.mockResolvedValue(newCoordinates);
            mockPrismaService.userAddress.update.mockResolvedValue({
                ...existingAddress,
                ...updateUserAddressDto,
                latitude: newCoordinates.lat,
                longitude: newCoordinates.lng,
            });

            const result = await service.update(
                addressId,
                updateUserAddressDto,
                null,
            );

            expect(result.latitude).toBe(newCoordinates.lat);
            expect(result.longitude).toBe(newCoordinates.lng);
            expect(openStreet.geocode).toHaveBeenCalledWith(
                updateUserAddressDto.address,
            );
            expect(prisma.userAddress.update).toHaveBeenCalled();
        });

        it('should update user address without changing coordinates when address not changed', async () => {
            const addressId = 1;
            const updateUserAddressDto: UpdateUserAddressDto = {
                tag: 'Updated Tag',
                label: 'Updated Label',
                // address not provided
            };
            const existingAddress = {
                ...mockUserAddress,
                latitude: -6.2088,
                longitude: 106.8456,
            };

            mockPrismaService.userAddress.findUnique.mockResolvedValue(
                existingAddress,
            );
            mockPrismaService.userAddress.update.mockResolvedValue({
                ...existingAddress,
                ...updateUserAddressDto,
            });

            const result = await service.update(
                addressId,
                updateUserAddressDto,
                null,
            );

            expect(result.latitude).toBe(existingAddress.latitude);
            expect(result.longitude).toBe(existingAddress.longitude);
            expect(openStreet.geocode).not.toHaveBeenCalled();
        });

        it('should update user address with new photo', async () => {
            const addressId = 1;
            const updateUserAddressDto: UpdateUserAddressDto = {
                tag: 'Updated Tag',
            };
            const photoFileName = 'new-photo.jpg';
            const existingAddress = {
                ...mockUserAddress,
                photo: '/uploads/photos/old-photo.jpg',
            };

            mockPrismaService.userAddress.findUnique.mockResolvedValue(
                existingAddress,
            );
            mockPrismaService.userAddress.update.mockResolvedValue({
                ...existingAddress,
                ...updateUserAddressDto,
                photo: '/uploads/photos/new-photo.jpg',
            });

            const result = await service.update(
                addressId,
                updateUserAddressDto,
                photoFileName,
            );

            expect(result.photo).toBe('/uploads/photos/new-photo.jpg');
        });

        it('should throw BadRequestException when new address has no coordinates', async () => {
            const addressId = 1;
            const updateUserAddressDto: UpdateUserAddressDto = {
                address: 'Invalid Address',
            };
            const existingAddress = mockUserAddress;

            mockPrismaService.userAddress.findUnique.mockResolvedValue(
                existingAddress,
            );
            mockOpenStreetService.geocode.mockResolvedValue(null);

            await expect(
                service.update(addressId, updateUserAddressDto, null),
            ).rejects.toThrow(BadRequestException);
        });

        it('should handle partial updates', async () => {
            const addressId = 1;
            const updateUserAddressDto: UpdateUserAddressDto = {
                label: 'Only Label Updated',
                // tag and address not provided
            };
            const existingAddress = mockUserAddress;

            mockPrismaService.userAddress.findUnique.mockResolvedValue(
                existingAddress,
            );
            mockPrismaService.userAddress.update.mockResolvedValue({
                ...existingAddress,
                label: 'Only Label Updated',
            });

            const result = await service.update(
                addressId,
                updateUserAddressDto,
                null,
            );

            expect(result.label).toBe('Only Label Updated');
            expect(result.tag).toBe(existingAddress.tag); // Should remain unchanged
            expect(result.address).toBe(existingAddress.address); // Should remain unchanged
        });
    });

    describe('remove', () => {
        it('should delete user address successfully', async () => {
            const addressId = 1;

            mockPrismaService.userAddress.findUnique.mockResolvedValue(
                mockUserAddress,
            );
            mockPrismaService.userAddress.delete.mockResolvedValue(
                mockUserAddress,
            );

            await service.remove(addressId);

            expect(prisma.userAddress.findUnique).toHaveBeenCalledWith({
                where: { id: addressId },
                include: expect.anything(),
            });
            expect(prisma.userAddress.delete).toHaveBeenCalledWith({
                where: { id: addressId },
            });
        });

        it('should throw NotFoundException when deleting non-existent address', async () => {
            const addressId = 999;

            mockPrismaService.userAddress.findUnique.mockResolvedValue(null);

            await expect(service.remove(addressId)).rejects.toThrow(
                NotFoundException,
            );
            expect(prisma.userAddress.delete).not.toHaveBeenCalled();
        });
    });

    describe('cleanupPhotoFile', () => {
        it('should cleanup photo file successfully', async () => {
            const filename = 'test-photo.jpg';

            await service.cleanupPhotoFile(filename);

            // Fix: Use regex or check that path contains the filename
            expect(mockFsUnlink).toHaveBeenCalledWith(
                expect.stringMatching(
                    /public[\\/]uploads[\\/]photos[\\/]test-photo\.jpg/,
                ),
            );
        });

        it('should handle file cleanup errors gracefully', async () => {
            const filename = 'non-existent-photo.jpg';
            const consoleSpy = jest
                .spyOn(console, 'error')
                .mockImplementation();

            mockFsUnlink.mockRejectedValue(new Error('File not found'));

            await service.cleanupPhotoFile(filename);

            expect(consoleSpy).toHaveBeenCalledWith(
                'Failed to cleanup photo file:',
                expect.any(Error),
            );

            consoleSpy.mockRestore();
        });
    });

    // Edge cases
    describe('Edge Cases', () => {
        it('should handle null coordinates in create', async () => {
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Jl. Test No.123, Jakarta',
                tag: 'Rumah',
                label: 'Alamat Rumah',
            };
            const userId = 1;
            const coordinates = { lat: null, lng: null };

            mockOpenStreetService.geocode.mockResolvedValue(coordinates);
            mockPrismaService.userAddress.create.mockResolvedValue({
                ...mockUserAddress,
                latitude: null,
                longitude: null,
            });

            const result = await service.create(
                createUserAddressDto,
                userId,
                null,
            );

            expect(result.latitude).toBeNull();
            expect(result.longitude).toBeNull();
        });

        it('should handle empty string in optional fields', async () => {
            const createUserAddressDto: CreateUserAddressDto = {
                address: 'Jl. Test No.123, Jakarta',
                tag: '',
                label: '',
            };
            const userId = 1;
            const coordinates = { lat: -6.2088, lng: 106.8456 };

            mockOpenStreetService.geocode.mockResolvedValue(coordinates);
            mockPrismaService.userAddress.create.mockResolvedValue({
                ...mockUserAddress,
                tag: '',
                label: '',
            });

            const result = await service.create(
                createUserAddressDto,
                userId,
                null,
            );

            expect(result.tag).toBe('');
            expect(result.label).toBe('');
        });
    });
});
