import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as fs from 'fs';
import * as path from 'path';

const prisma = new PrismaClient();

export async function usersSeed() {
    try {
        const usersPath = path.resolve(__dirname, 'data', 'users.json');
        
        // Check if file exists
        if (!fs.existsSync(usersPath)) {
            console.error(`❌ File not found: ${usersPath}`);
            return;
        }

        const usersRaw = fs.readFileSync(usersPath, 'utf-8');
        const users = JSON.parse(usersRaw).data;

        console.log(`👥 Seeding ${users.length} users...`);

        let createdCount = 0;
        let updatedCount = 0;
        let skippedCount = 0;
        let errorCount = 0;

        // Process users in parallel for better performance
        const results = await Promise.allSettled(
            users.map(async (user) => {
                try {
                    const role = await prisma.role.findFirst({
                        where: { key: user.roleKey },
                    });

                    if (!role) {
                        console.warn(`⚠️ Role with key "${user.roleKey}" not found. Skipping user "${user.name}" (${user.email})`);
                        skippedCount++;
                        return;
                    }

                    const hashedPassword = await bcrypt.hash(user.password, 12);

                    // Check if user exists to determine if we're creating or updating
                    const existingUser = await prisma.user.findFirst({
                        where: { 
                            OR: [
                                { email: user.email },
                                { phoneNumber: user.phoneNumber }
                            ]
                        },
                    });

                    if (existingUser) {
                        // Update existing user (but don't change password unless it's different)
                        const updateData: any = {
                            name: user.name,
                            avatar: user.avatar,
                            phoneNumber: user.phoneNumber,
                            roleId: role.id,
                        };

                        // Only update password if it's different (optional security measure)
                        // You can remove this if you always want to update password
                        const isPasswordSame = await bcrypt.compare(user.password, existingUser.password);
                        if (!isPasswordSame) {
                            updateData.password = hashedPassword;
                        }

                        await prisma.user.update({
                            where: { id: existingUser.id },
                            data: updateData,
                        });

                        updatedCount++;
                        console.log(`🔄 Updated user: ${user.name} (${user.email})`);
                    } else {
                        // Create new user
                        await prisma.user.create({
                            data: {
                                name: user.name,
                                email: user.email,
                                password: hashedPassword,
                                avatar: user.avatar,
                                phoneNumber: user.phoneNumber,
                                roleId: role.id,
                            },
                        });

                        createdCount++;
                        console.log(`✅ Created user: ${user.name} (${user.email})`);
                    }

                } catch (error) {
                    console.error(`❌ Error processing user ${user.name} (${user.email}):`, error);
                    throw error;
                }
            })
        );

        // Handle individual promise results
        results.forEach((result, index) => {
            if (result.status === 'rejected') {
                console.error(`❌ Failed to process user ${users[index]?.name}:`, result.reason);
                errorCount++;
            }
        });

        console.log('\n📊 Users Seeding Summary:');
        console.log(`✅ Created: ${createdCount}`);
        console.log(`🔄 Updated: ${updatedCount}`);
        console.log(`⏭️  Skipped: ${skippedCount}`);
        console.log(`❌ Errors: ${errorCount}`);
        console.log(`📝 Total processed: ${users.length}`);

    } catch (error) {
        console.error('❌ Error in usersSeed:', error);
        throw error;
    }
}

// For running directly
if (require.main === module) {
    usersSeed()
        .catch((e) => {
            console.error('💥 Seeding failed:', e);
            process.exit(1);
        })
        .finally(async () => {
            await prisma.$disconnect();
        });
}