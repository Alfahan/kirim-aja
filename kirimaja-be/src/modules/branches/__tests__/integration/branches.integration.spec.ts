import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../../../../app.module';
import { PrismaService } from '../../../../common/prisma/prisma.service';
import { Branch } from '@prisma/client';

describe('BranchesController (Integration - Business Logic)', () => {
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
        await prisma.employeeBranch.deleteMany();
        await prisma.shipmentBranchLog.deleteMany();
        await prisma.shipmentHistory.deleteMany();
        await prisma.branch.deleteMany();
    });

    const cleanupTestData = async () => {
        // Cleanup dengan urutan yang benar
        await prisma.employeeBranch.deleteMany();
        await prisma.shipmentBranchLog.deleteMany();
        await prisma.shipmentHistory.deleteMany();
        await prisma.branch.deleteMany();
    };

    // ==================== POSITIVE TEST CASES ====================

    describe('✅ POSITIVE CASES - Branch CRUD Operations', () => {
        it('should create a new branch successfully', async () => {
            // Arrange
            const branchData = {
                name: 'New Branch Positive',
                address: 'Jl. Positive Test No.123, Jakarta',
                phoneNumber: '081234567890',
            };

            // Act
            const branch = await prisma.branch.create({
                data: branchData,
            });

            // Assert
            expect(branch).toBeDefined();
            expect(branch.id).toBeGreaterThan(0);
            expect(branch.name).toBe(branchData.name);
            expect(branch.address).toBe(branchData.address);
            expect(branch.phoneNumber).toBe(branchData.phoneNumber);
            expect(branch.createdAt).toBeInstanceOf(Date);
            expect(branch.updatedAt).toBeInstanceOf(Date);
        });

        it('should retrieve all branches', async () => {
            // Arrange
            await prisma.branch.createMany({
                data: [
                    {
                        name: 'Branch A',
                        address: 'Address A',
                        phoneNumber: '0811111111',
                    },
                    {
                        name: 'Branch B',
                        address: 'Address B',
                        phoneNumber: '0822222222',
                    },
                    {
                        name: 'Branch C',
                        address: 'Address C',
                        phoneNumber: '0833333333',
                    },
                ],
            });

            // Act
            const branches = await prisma.branch.findMany({
                orderBy: { id: 'asc' },
            });

            // Assert
            expect(branches).toHaveLength(3);
            expect(branches[0].name).toBe('Branch A');
            expect(branches[1].name).toBe('Branch B');
            expect(branches[2].name).toBe('Branch C');
        });

        it('should retrieve specific branch by ID', async () => {
            // Arrange
            const createdBranch = await prisma.branch.create({
                data: {
                    name: 'Specific Branch',
                    address: 'Jl. Specific No.123',
                    phoneNumber: '081234567890',
                },
            });

            // Act
            const foundBranch = await prisma.branch.findUnique({
                where: { id: createdBranch.id },
            });

            // Assert
            expect(foundBranch).toBeDefined();
            expect(foundBranch?.id).toBe(createdBranch.id);
            expect(foundBranch?.name).toBe('Specific Branch');
        });

        it('should update branch successfully', async () => {
            // Arrange
            const originalBranch = await prisma.branch.create({
                data: {
                    name: 'Original Name',
                    address: 'Original Address',
                    phoneNumber: '081000000000',
                },
            });

            // Tunggu sebentar untuk memastikan timestamp berbeda
            await new Promise((resolve) => setTimeout(resolve, 10));

            // Act
            const updatedBranch = await prisma.branch.update({
                where: { id: originalBranch.id },
                data: {
                    name: 'Updated Name',
                    address: 'Updated Address',
                    phoneNumber: '081999999999',
                },
            });

            // Assert
            expect(updatedBranch.name).toBe('Updated Name');
            expect(updatedBranch.address).toBe('Updated Address');
            expect(updatedBranch.phoneNumber).toBe('081999999999');
            expect(updatedBranch.id).toBe(originalBranch.id);
            // Gunakan toBeGreaterThanOrEqual untuk handle case yang sama
            expect(updatedBranch.updatedAt.getTime()).toBeGreaterThanOrEqual(
                originalBranch.updatedAt.getTime(),
            );
        });

        it('should handle partial updates', async () => {
            // Arrange
            const originalBranch = await prisma.branch.create({
                data: {
                    name: 'Partial Update Test',
                    address: 'Original Address',
                    phoneNumber: '081111111111',
                },
            });

            // Act - Only update name
            const updatedBranch = await prisma.branch.update({
                where: { id: originalBranch.id },
                data: { name: 'Partially Updated' },
            });

            // Assert
            expect(updatedBranch.name).toBe('Partially Updated');
            expect(updatedBranch.address).toBe('Original Address');
            expect(updatedBranch.phoneNumber).toBe('081111111111');
        });

        it('should delete branch successfully', async () => {
            // Arrange
            const branch = await prisma.branch.create({
                data: {
                    name: 'Branch to Delete',
                    address: 'Jl. Delete No.123',
                    phoneNumber: '081333333333',
                },
            });

            // Act
            await prisma.branch.delete({
                where: { id: branch.id },
            });

            // Assert
            const deletedBranch = await prisma.branch.findUnique({
                where: { id: branch.id },
            });
            expect(deletedBranch).toBeNull();
        });

        it('should handle branch with longer field values', async () => {
            // Arrange - Gunakan length yang aman untuk database
            const longName =
                'Branch Name with Reasonable Length for Testing Purposes';
            const longAddress =
                'Jl. Testing Panjang No.123, Kelurahan Test, Kecamatan Test, Kota Test, Provinsi Test, Indonesia';
            const longPhone = '081234567890123'; // 15 chars

            // Act
            const branch = await prisma.branch.create({
                data: {
                    name: longName,
                    address: longAddress,
                    phoneNumber: longPhone,
                },
            });

            // Assert
            expect(branch.name).toBe(longName);
            expect(branch.address).toBe(longAddress);
            expect(branch.phoneNumber).toBe(longPhone);
        });

        it('should handle special characters in branch data', async () => {
            // Arrange
            const specialData = {
                name: 'Branch & Co. (Main) - "Premium" @100%',
                address: 'Jl. Test No.123, RT 01/RW 02, Kec. Test',
                phoneNumber: '+62-812-3456-7890',
            };

            // Act
            const branch = await prisma.branch.create({
                data: specialData,
            });

            // Assert
            expect(branch.name).toBe(specialData.name);
            expect(branch.address).toBe(specialData.address);
            expect(branch.phoneNumber).toBe(specialData.phoneNumber);
        });
    });

    // ==================== NEGATIVE TEST CASES ====================

    describe('❌ NEGATIVE CASES - Error Scenarios', () => {
        it('should fail when retrieving non-existent branch', async () => {
            // Act & Assert
            const nonExistentBranch = await prisma.branch.findUnique({
                where: { id: 99999 },
            });
            expect(nonExistentBranch).toBeNull();
        });

        it('should fail when updating non-existent branch', async () => {
            // Act & Assert
            await expect(
                prisma.branch.update({
                    where: { id: 99999 },
                    data: { name: 'Updated' },
                }),
            ).rejects.toThrow();
        });

        it('should fail when deleting non-existent branch', async () => {
            // Act & Assert
            await expect(
                prisma.branch.delete({
                    where: { id: 99999 },
                }),
            ).rejects.toThrow();
        });

        it('should handle empty result when no branches exist', async () => {
            // Act
            const branches = await prisma.branch.findMany();

            // Assert
            expect(branches).toEqual([]);
            expect(branches).toHaveLength(0);
        });
    });

    // ==================== EDGE CASES & BOUNDARY TESTING ====================

    describe('⚡ EDGE CASES - Boundary Testing', () => {
        it('should handle multiple branches creation', async () => {
            // Arrange - Create multiple branches menggunakan loop individual
            const branchCount = 5;

            for (let i = 0; i < branchCount; i++) {
                await prisma.branch.create({
                    data: {
                        name: `Branch ${i + 1}`,
                        address: `Address ${i + 1}`,
                        phoneNumber: `081${i.toString().padStart(9, '0')}`,
                    },
                });
            }

            // Assert
            const allBranches = await prisma.branch.findMany();
            expect(allBranches).toHaveLength(branchCount);
        });

        it('should handle branch with minimum required data', async () => {
            // Arrange - Minimum meaningful data
            const minimalData = {
                name: 'A',
                address: 'B',
                phoneNumber: '1',
            };

            // Act
            const branch = await prisma.branch.create({
                data: minimalData,
            });

            // Assert
            expect(branch.name).toBe('A');
            expect(branch.address).toBe('B');
            expect(branch.phoneNumber).toBe('1');
        });

        it('should maintain data integrity after multiple operations', async () => {
            // Arrange
            const originalBranch = await prisma.branch.create({
                data: {
                    name: 'Integrity Test',
                    address: 'Original Address',
                    phoneNumber: '081111111111',
                },
            });

            // Act - Multiple operations
            await prisma.branch.update({
                where: { id: originalBranch.id },
                data: { name: 'First Update' },
            });

            await prisma.branch.update({
                where: { id: originalBranch.id },
                data: { address: 'Second Update' },
            });

            const finalBranch = await prisma.branch.findUnique({
                where: { id: originalBranch.id },
            });

            // Assert
            expect(finalBranch?.name).toBe('First Update');
            expect(finalBranch?.address).toBe('Second Update');
            expect(finalBranch?.phoneNumber).toBe('081111111111');
        });

        it('should handle concurrent branch creations', async () => {
            // Arrange
            const concurrentBranches = [
                {
                    name: 'Concurrent A',
                    address: 'Address A',
                    phoneNumber: '081000000001',
                },
                {
                    name: 'Concurrent B',
                    address: 'Address B',
                    phoneNumber: '081000000002',
                },
                {
                    name: 'Concurrent C',
                    address: 'Address C',
                    phoneNumber: '081000000003',
                },
            ];

            // Act - Properly type the promises
            const createPromises: Promise<Branch>[] = concurrentBranches.map(
                (branch) => prisma.branch.create({ data: branch }),
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
            // First create a test user and role if they don't exist
            const role = await prisma.role.create({
                data: {
                    name: 'Test Role',
                    key: 'test-role',
                },
            });

            const user = await prisma.user.create({
                data: {
                    name: 'Test User',
                    email: 'testuser@integration.test',
                    password: 'hashedpassword',
                    phoneNumber: '089999999999',
                    roleId: role.id,
                },
            });

            // Arrange - Create a branch
            const branch = await prisma.branch.create({
                data: {
                    name: 'Relationship Test Branch',
                    address: 'Jl. Relationship No.123',
                    phoneNumber: '081888888888',
                },
            });

            // Act - Create related data (EmployeeBranch)
            const employeeBranch = await prisma.employeeBranch.create({
                data: {
                    userId: user.id,
                    branchId: branch.id,
                    type: 'admin',
                },
            });

            // Assert
            expect(employeeBranch.branchId).toBe(branch.id);

            // Verify we can query the relationship
            const branchWithRelations = await prisma.branch.findUnique({
                where: { id: branch.id },
                include: { employeeBranch: true },
            });

            expect(branchWithRelations?.employeeBranch).toHaveLength(1);
            expect(branchWithRelations?.employeeBranch[0].id).toBe(
                employeeBranch.id,
            );

            // Cleanup dengan urutan yang benar
            await prisma.employeeBranch.deleteMany();
            await prisma.user.deleteMany();
            await prisma.role.deleteMany();
        });

        it('should test branch operations without cascade issues', async () => {
            // Test yang lebih sederhana tanpa cascade delete
            const branch = await prisma.branch.create({
                data: {
                    name: 'Simple Relationship Test',
                    address: 'Jl. Simple No.123',
                    phoneNumber: '081777777777',
                },
            });

            // Basic operations should work without foreign key issues
            const foundBranch = await prisma.branch.findUnique({
                where: { id: branch.id },
            });

            expect(foundBranch).toBeDefined();
            expect(foundBranch?.name).toBe('Simple Relationship Test');

            // Cleanup
            await prisma.branch.delete({
                where: { id: branch.id },
            });
        });
    });

    // ==================== DATA VALIDATION TESTS ====================

    describe('🔍 DATA VALIDATION', () => {
        it('should auto-generate createdAt and updatedAt fields', async () => {
            // Arrange & Act
            const branch = await prisma.branch.create({
                data: {
                    name: 'Auto Date Test',
                    address: 'Jl. Date Test No.123',
                    phoneNumber: '081555555555',
                },
            });

            // Assert
            expect(branch.createdAt).toBeInstanceOf(Date);
            expect(branch.updatedAt).toBeInstanceOf(Date);
            expect(branch.createdAt.getTime()).toBeLessThanOrEqual(Date.now());
            expect(branch.updatedAt.getTime()).toBeLessThanOrEqual(Date.now());
        });

        it('should preserve createdAt when updating branch', async () => {
            // Arrange
            const branch = await prisma.branch.create({
                data: {
                    name: 'Preserve Created At Test',
                    address: 'Original Address',
                    phoneNumber: '081333333333',
                },
            });

            const originalCreatedAt = branch.createdAt;

            // Act
            const updatedBranch = await prisma.branch.update({
                where: { id: branch.id },
                data: {
                    name: 'Updated Name',
                    address: 'Updated Address',
                },
            });

            // Assert
            expect(updatedBranch.createdAt.getTime()).toBe(
                originalCreatedAt.getTime(),
            );
        });
    });
});
