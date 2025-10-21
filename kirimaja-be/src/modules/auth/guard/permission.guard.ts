import {
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionsService } from 'src/modules/permissions/permissions.service';
import { PERMISSION_KEY } from '../decorators/permissions.decorator';

@Injectable()
export class PermissionGuard implements CanActivate {
    constructor(
        private reflector: Reflector,
        private permissionService: PermissionsService,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const requiredPermissions = this.reflector.getAllAndOverride(
            PERMISSION_KEY,
            [context.getHandler(), context.getClass()],
        );

        if (!requiredPermissions) {
            return true;
        }

        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const request = context.switchToHttp().getRequest();
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        const user = request.user;

        if (!user) {
            throw new ForbiddenException('User not authenticated');
        }

        if (
            typeof requiredPermissions == 'object' &&
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            requiredPermissions.type
        ) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            const { type, permissions } = requiredPermissions;

            let hasPermission = false;

            if (type == 'any') {
                hasPermission =
                    await this.permissionService.userHasAnyPermission(
                        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
                        user.id,
                        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
                        permissions,
                    );
            } else if (type == 'all') {
                hasPermission =
                    await this.permissionService.userHasAllAnyPermission(
                        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
                        user.id,
                        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
                        permissions,
                    );
            }

            if (!hasPermission) {
                throw new ForbiddenException(
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
                    `Access demied. Required permissions: ${permissions.join('. ')}`,
                );
            }
        } else {
            const permissions = Array.isArray(requiredPermissions)
                ? requiredPermissions
                : [requiredPermissions];
            const hasPermission =
                await this.permissionService.userHasAllAnyPermission(
                    user.id,
                    permissions,
                );
            if (!hasPermission) {
                throw new ForbiddenException(
                    `Access demied. Required permissions: ${permissions.join('. ')}`,
                );
            }
        }

        return true;
    }
}
