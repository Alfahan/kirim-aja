import { PrismaClient } from '@prisma/client';
import * as fs from 'fs';
import * as path from 'path';

const prisma = new PrismaClient();

export async function branchesSeed() {
    try {
        const branchesPath = path.resolve(__dirname, 'data', 'branches.json');
        
        // Check if file exists
        if (!fs.existsSync(branchesPath)) {
            console.error(`❌ File not found: ${branchesPath}`);
            return;
        }

        const branchesRaw = fs.readFileSync(branchesPath, 'utf-8');
        const branches = JSON.parse(branchesRaw).data;

        console.log(`🌿 Seeding ${branches.length} branches...`);

        let createdCount = 0;
        let skippedCount = 0;
        let errorCount = 0;

        // Use transaction for better performance
        const results = await Promise.allSettled(
            branches.map(async (branch) => {
                try {
                    // Check if branch exists by name or phone number
                    const existingBranch = await prisma.branch.findFirst({
                        where: { 
                            OR: [
                                { name: branch.name },
                                { phoneNumber: branch.phoneNumber }
                            ]
                        },
                    });

                    if (existingBranch) {
                        // Update existing branch if needed
                        if (existingBranch.address !== branch.address || 
                            existingBranch.phoneNumber !== branch.phoneNumber) {
                            
                            await prisma.branch.update({
                                where: { id: existingBranch.id },
                                data: {
                                    address: branch.address,
                                    phoneNumber: branch.phoneNumber,
                                },
                            });
                            console.log(`🔄 Updated branch: ${branch.name}`);
                            createdCount++; // Count as "processed"
                        } else {
                            console.log(`⏭️  Branch already exists, skipping: ${branch.name}`);
                            skippedCount++;
                        }
                        return;
                    }

                    // Create new branch
                    await prisma.branch.create({
                        data: {
                            name: branch.name,
                            address: branch.address,
                            phoneNumber: branch.phoneNumber,
                        },
                    });

                    createdCount++;
                    console.log(`✅ Created branch: ${branch.name}`);

                } catch (error) {
                    console.error(`❌ Error processing branch ${branch.name}:`, error);
                    throw error; // Re-throw to be caught by Promise.allSettled
                }
            })
        );

        // Handle individual promise results
        results.forEach((result, index) => {
            if (result.status === 'rejected') {
                console.error(`❌ Failed to process branch ${branches[index]?.name}:`, result.reason);
                errorCount++;
            }
        });

        console.log('\n📊 Branches Seeding Summary:');
        console.log(`✅ Created/Updated: ${createdCount}`);
        console.log(`⏭️  Skipped: ${skippedCount}`); // FIXED: changed skilledCount to skippedCount
        console.log(`❌ Errors: ${errorCount}`);
        console.log(`📝 Total processed: ${branches.length}`);

    } catch (error) {
        console.error('❌ Error in branchesSeed:', error);
        throw error;
    }
}

// For running directly
if (require.main === module) {
    branchesSeed()
        .catch((e) => {
            console.error('💥 Seeding failed:', e);
            process.exit(1);
        })
        .finally(async () => {
            await prisma.$disconnect();
        });
}