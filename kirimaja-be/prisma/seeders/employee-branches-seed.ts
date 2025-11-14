import { PrismaClient } from '@prisma/client';
import * as fs from 'fs';
import * as path from 'path';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

export async function employeeBranchesSeed() {
    try {
        const employeeBranchesPath = path.resolve(__dirname, 'data', 'employee-branches.json');
        
        if (!fs.existsSync(employeeBranchesPath)) {
            console.error(`File not found: ${employeeBranchesPath}`);
            return;
        }

        const employeeBranchesRaw = fs.readFileSync(employeeBranchesPath, 'utf-8');
        const employeeBranches = JSON.parse(employeeBranchesRaw).data;

        console.log(`Seeding ${employeeBranches.length} employee branches...`);

        let successCount = 0;
        let updateCount = 0;
        let skipCount = 0;
        let errorCount = 0;

        for (const employeeBranch of employeeBranches) {
            try {
                const role = await prisma.role.findFirst({
                    where: { key: employeeBranch.roleKey },
                });

                if (!role) {
                    console.error(`❌ Role with key "${employeeBranch.roleKey}" not found, skipping employee: ${employeeBranch.name}`);
                    errorCount++;
                    continue;
                }

                const branch = await prisma.branch.findFirst({
                    where: { 
                        name: employeeBranch.branchName
                    },
                });

                if (!branch) {
                    console.error(`❌ Branch with name "${employeeBranch.branchName}" not found, skipping employee: ${employeeBranch.name}`);
                    errorCount++;
                    continue;
                }

                // Check if user already exists
                const existingUser = await prisma.user.findFirst({
                    where: { 
                        OR: [
                            { email: employeeBranch.email },
                            { phoneNumber: employeeBranch.phoneNumber }
                        ]
                    },
                });

                if (existingUser) {
                    console.log(`⚠️ User already exists: ${employeeBranch.email}`);
                    
                    // Update user data
                    await prisma.user.update({
                        where: { id: existingUser.id },
                        data: {
                            name: employeeBranch.name,
                            phoneNumber: employeeBranch.phoneNumber,
                            roleId: role.id,
                            // Don't update password if already exists
                        },
                    });

                    // Check if employeeBranch relation already exists for this branch
                    const existingEmployeeBranch = await prisma.employeeBranch.findFirst({
                        where: { 
                            userId: existingUser.id,
                            branchId: branch.id
                        }
                    });

                    if (existingEmployeeBranch) {
                        // Update existing employeeBranch relation
                        await prisma.employeeBranch.update({
                            where: { id: existingEmployeeBranch.id },
                            data: {
                                type: employeeBranch.type,
                            },
                        });
                        console.log(`🔄 Updated existing employee branch: ${employeeBranch.email} at ${branch.name}`);
                        updateCount++;
                    } else {
                        // Check if user has employeeBranch in different branch
                        const existingOtherEmployeeBranches = await prisma.employeeBranch.findMany({
                            where: { 
                                userId: existingUser.id,
                                branchId: { not: branch.id } // Different branch
                            }
                        });

                        if (existingOtherEmployeeBranches.length > 0) {
                            // User pindah cabang - delete old relations and create new one
                            await prisma.employeeBranch.deleteMany({
                                where: { userId: existingUser.id }
                            });

                            // Create new employeeBranch relation
                            await prisma.employeeBranch.create({
                                data: {
                                    userId: existingUser.id,
                                    branchId: branch.id,
                                    type: employeeBranch.type,
                                },
                            });
                            console.log(`🔄 User moved branches: ${employeeBranch.email} from previous branch to ${branch.name}`);
                            updateCount++;
                            
                        } else {
                            // Create new employeeBranch relation for existing user
                            await prisma.employeeBranch.create({
                                data: {
                                    userId: existingUser.id,
                                    branchId: branch.id,
                                    type: employeeBranch.type,
                                },
                            });
                            console.log(`✅ Added new employee branch for existing user: ${employeeBranch.email} at ${branch.name}`);
                            successCount++;
                        }
                    }
                    
                } else {
                    // Create new user
                    const user = await prisma.user.create({
                        data: {
                            name: employeeBranch.name,
                            email: employeeBranch.email,
                            phoneNumber: employeeBranch.phoneNumber,
                            password: await bcrypt.hash(employeeBranch.password, 10),
                            avatar: employeeBranch.avatar || null,
                            roleId: role.id,
                        },
                    });

                    // Create employeeBranch relation
                    await prisma.employeeBranch.create({
                        data: {
                            userId: user.id,
                            branchId: branch.id,
                            type: employeeBranch.type,
                        },
                    });

                    successCount++;
                    console.log(`✅ Created new user and employee branch: ${employeeBranch.email} at ${branch.name}`);
                }

            } catch (error) {
                console.error(`❌ Error processing employee ${employeeBranch.name}:`, error);
                errorCount++;
            }
        }

        console.log('\n📊 Employee Branches Seeding Summary:');
        console.log(`✅ New created: ${successCount}`);
        console.log(`🔄 Updated: ${updateCount}`);
        console.log(`⚠️ Skipped: ${skipCount}`);
        console.log(`❌ Errors: ${errorCount}`);
        console.log(`📝 Total processed: ${employeeBranches.length}`);

    } catch (error) {
        console.error('❌ Error in employeeBranchesSeed:', error);
        throw error;
    }
}

// For running directly
if (require.main === module) {
    employeeBranchesSeed()
        .catch((e) => {
            console.error(e);
            process.exit(1);
        })
        .finally(async () => {
            await prisma.$disconnect();
        });
}