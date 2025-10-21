import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtAuthGuard } from './modules/auth/guard/logged-in-guard';
import { PermissionGuard } from './modules/auth/guard/permission.guard';
import { RequireAnyPermission } from './modules/auth/decorators/permissions.decorator';

@Controller()
@UseGuards(JwtAuthGuard, PermissionGuard)
export class AppController {
    constructor(private readonly appService: AppService) {}

    @Get()
    getHello(): string {
        return this.appService.getHello();
    }

    @Get('protected')
    @RequireAnyPermission('view_protected_resource')
    geProtected(): string {
        return 'This is a protected resource';
    }
}
