import { Controller, Get, UseGuards } from '@nestjs/common';
import { PermissionsService } from './permissions.service';
import { JwtAuthGuard } from '../auth/guard/logged-in-guard';
import { BaseResponse } from 'src/common/interface/base-response.interface';
import { Permission } from '@prisma/client';

@Controller('permissions')
@UseGuards(JwtAuthGuard)
export class PermissionsController {
    constructor(private readonly permissionsService: PermissionsService) {}

    @Get()
    async findAll(): Promise<BaseResponse<Permission[]>> {
        return {
            message: `Permissions retrieved successfully`,
            data: await this.permissionsService.findAll(),
        };
    }
}
