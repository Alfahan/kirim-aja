import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { BranchesService } from '../../branches.service';
import { PrismaService } from '../../../../common/prisma/prisma.service';
import { CreateBranchDto } from '../../dto/create-branch.dto';
import { UpdateBranchDto } from '../../dto/update-branch.dto';
import { Branch } from '@prisma/client';

// Helper function untuk create mock branch
const createMockBranch = (overrides?: Partial<Branch>): Branch => ({
    id: 1,
    name: 'Test Branch',
    address: 'Jl. Test No.123',
    phoneNumber: '081234567890',
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
});

// Mock data
const mockBranch = createMockBranch();
const mockBranches = [
    mockBranch,
    createMockBranch({
        id: 2,
        name: 'Test Branch 2',
        address: 'Jl. Test No.456',
        phoneNumber: '081234567891',
    }),
];

// Mock Prisma Service
const mockPrismaService = {
    branch: {
        create: jest.fn(),
        findMany: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
    },
};

describe('BranchesService', () => {
    let service: BranchesService;
    let prisma: PrismaService;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                BranchesService,
                {
                    provide: PrismaService,
                    useValue: mockPrismaService,
                },
            ],
        }).compile();

        service = module.get<BranchesService>(BranchesService);
        prisma = module.get<PrismaService>(PrismaService);
        jest.clearAllMocks();
    });

    describe('create', () => {
        it('should create a new branch successfully', async () => {
            const createBranchDto: CreateBranchDto = {
                name: 'Test Branch',
                address: 'Jl. Test No.123',
                phone_number: '081234567890',
            };

            mockPrismaService.branch.create.mockResolvedValue(mockBranch);

            const result = await service.create(createBranchDto);

            expect(result).toEqual(mockBranch);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(prisma.branch.create).toHaveBeenCalledWith({
                data: {
                    name: createBranchDto.name,
                    address: createBranchDto.address,
                    phoneNumber: createBranchDto.phone_number,
                },
            });
        });
    });

    describe('findAll', () => {
        it('should return an array of branches', async () => {
            mockPrismaService.branch.findMany.mockResolvedValue(mockBranches);

            const result = await service.findAll();

            expect(result).toEqual(mockBranches);
            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(prisma.branch.findMany).toHaveBeenCalledWith({});
        });
    });

    describe('findOne', () => {
        it('should return a branch when found', async () => {
            const branchId = 1;
            mockPrismaService.branch.findUnique.mockResolvedValue(mockBranch);

            const result = await service.findOne(branchId);

            expect(result).toEqual(mockBranch);
        });

        it('should throw NotFoundException when branch not found', async () => {
            const branchId = 999;
            mockPrismaService.branch.findUnique.mockResolvedValue(null);

            await expect(service.findOne(branchId)).rejects.toThrow(
                NotFoundException,
            );
        });
    });

    describe('update', () => {
        it('should update a branch successfully', async () => {
            const branchId = 1;
            const updateBranchDto: UpdateBranchDto = {
                name: 'Updated Branch Name',
                address: 'Updated Address',
                phone_number: '081234567899',
            };

            const updatedBranch = createMockBranch({
                name: updateBranchDto.name,
                address: updateBranchDto.address,
                phoneNumber: updateBranchDto.phone_number,
            });

            mockPrismaService.branch.findUnique.mockResolvedValue(mockBranch);
            mockPrismaService.branch.update.mockResolvedValue(updatedBranch);

            const result = await service.update(branchId, updateBranchDto);

            expect(result).toEqual(updatedBranch);
        });

        it('should handle partial updates', async () => {
            const branchId = 1;
            const partialUpdateDto: UpdateBranchDto = {
                name: 'Partially Updated Name',
                // address and phone_number not provided
            };

            const partiallyUpdatedBranch = createMockBranch({
                name: 'Partially Updated Name',
            });

            mockPrismaService.branch.findUnique.mockResolvedValue(mockBranch);
            mockPrismaService.branch.update.mockResolvedValue(
                partiallyUpdatedBranch,
            );

            const result = await service.update(branchId, partialUpdateDto);

            expect(result.name).toBe('Partially Updated Name');
            expect(result.address).toBe(mockBranch.address);
            expect(result.phoneNumber).toBe(mockBranch.phoneNumber);
        });
    });

    describe('remove', () => {
        it('should delete a branch successfully', async () => {
            const branchId = 1;
            mockPrismaService.branch.findUnique.mockResolvedValue(mockBranch);
            mockPrismaService.branch.delete.mockResolvedValue(mockBranch);

            await service.remove(branchId);

            // eslint-disable-next-line @typescript-eslint/unbound-method
            expect(prisma.branch.delete).toHaveBeenCalledWith({
                where: { id: branchId },
            });
        });
    });
});
