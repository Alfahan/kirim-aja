import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { Permission } from '@prisma/client';

@Injectable()
export class PermissionsService {
    constructor(private prismaService: PrismaService) {}

    async findAll(): Promise<Permission[]> {
        return await this.prismaService.permission.findMany();
    }

    async getUserPermissions(userId: number): Promise<string[]> {
        const user = await this.prismaService.user.findUnique({
            where: { id: userId },
            include: {
                role: {
                    include: {
                        rolePermissions: {
                            include: {
                                permission: true,
                            },
                        },
                    },
                },
            },
        });

        if (!user) {
            return [];
        }

        return (
            user.role?.rolePermissions.map(
                (rolePermission) => rolePermission.permission.key,
            ) || []
        );
    }

    async userHasAnyPermission(
        userId: number,
        permission: string[],
    ): Promise<boolean> {
        const userPermissions = await this.getUserPermissions(userId);
        return permission.some((permission) =>
            userPermissions.includes(permission),
        );
    }

    async userHasAllAnyPermission(
        userId: number,
        permission: string[],
    ): Promise<boolean> {
        const userPermissions = await this.getUserPermissions(userId);
        return permission.every((permission) =>
            userPermissions.includes(permission),
        );
    }
}
