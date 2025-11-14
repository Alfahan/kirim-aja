import {
    Controller,
    Get,
    Post,
    Body,
    Patch,
    Param,
    Delete,
    UseGuards,
} from '@nestjs/common';
import { EmployeeBranchesService } from './employee-branches.service';
import { CreateEmployeeBranchDto } from './dto/create-employee-branch.dto';
import { UpdateEmployeeBranchDto } from './dto/update-employee-branch.dto';
import { JwtAuthGuard } from '../auth/guard/logged-in-guard';
import { PermissionGuard } from '../auth/guard/permission.guard';
import { RequirePermissions } from '../auth/decorators/permissions.decorator';
import { BaseResponse } from 'src/common/interface/base-response.interface';
import { EmployeeBranch } from '@prisma/client';

@Controller('employee-branches')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class EmployeeBranchesController {
    constructor(
        private readonly employeeBranchesService: EmployeeBranchesService,
    ) {}

    @Post()
    @RequirePermissions('employee.create')
    async create(
        @Body() createEmployeeBranchDto: CreateEmployeeBranchDto,
    ): Promise<BaseResponse<EmployeeBranch>> {
        return {
            data: await this.employeeBranchesService.create(
                createEmployeeBranchDto,
            ),
            message: 'Employee branch created successfully',
        };
    }

    @Get()
    @RequirePermissions('employee.read')
    async findAll(): Promise<BaseResponse<EmployeeBranch[]>> {
        return {
            data: await this.employeeBranchesService.findAll(),
            message: 'Employee branches retrieved successfully',
        };
    }

    @Get(':id')
    @RequirePermissions('employee.read')
    async findOne(
        @Param('id') id: string,
    ): Promise<BaseResponse<EmployeeBranch>> {
        return {
            data: await this.employeeBranchesService.findOne(+id),
            message: 'Employee branch retrieved successfully',
        };
    }

    @Patch(':id')
    @RequirePermissions('employee.update')
    update(
        @Param('id') id: string,
        @Body() updateEmployeeBranchDto: UpdateEmployeeBranchDto,
    ) {
        return this.employeeBranchesService.update(
            +id,
            updateEmployeeBranchDto,
        );
    }

    @Delete(':id')
    @RequirePermissions('employee.delete')
    async remove(@Param('id') id: string): Promise<BaseResponse<void>> {
        await this.employeeBranchesService.remove(+id);
        return {
            data: null,
            message: 'Employee branch delete successfully',
        };
    }
}
