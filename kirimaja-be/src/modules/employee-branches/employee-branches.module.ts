import { Module } from '@nestjs/common';
import { EmployeeBranchesService } from './employee-branches.service';
import { EmployeeBranchesController } from './employee-branches.controller';
import { PrismaService } from '../../common/prisma/prisma.service';
import { PermissionsService } from '../permissions/permissions.service';

@Module({
    controllers: [EmployeeBranchesController],
    providers: [EmployeeBranchesService, PrismaService, PermissionsService],
})
export class EmployeeBranchesModule {}
