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
import { BranchesService } from './branches.service';
import { CreateBranchDto } from './dto/create-branch.dto';
import { UpdateBranchDto } from './dto/update-branch.dto';
import { JwtAuthGuard } from '../auth/guard/logged-in-guard';
import { PermissionGuard } from '../auth/guard/permission.guard';
import { RequirePermissions } from '../auth/decorators/permissions.decorator';
import { BaseResponse } from 'src/common/interface/base-response.interface';
import { Branch } from '@prisma/client';

@Controller('branches')
@UseGuards(JwtAuthGuard, PermissionGuard)
export class BranchesController {
    constructor(private readonly branchesService: BranchesService) {}

    @Post()
    @RequirePermissions('branches.create')
    async create(
        @Body() createBranchDto: CreateBranchDto,
    ): Promise<BaseResponse<Branch>> {
        return {
            message: 'Branch created successfully',
            data: await this.branchesService.create(createBranchDto),
        };
    }

    @Get()
    @RequirePermissions('branches.read')
    async findAll(): Promise<BaseResponse<Branch[]>> {
        return {
            message: 'Branches retrieved successfully',
            data: await this.branchesService.findAll(),
        };
    }

    @Get(':id')
    @RequirePermissions('branches.read')
    async findOne(@Param('id') id: string): Promise<BaseResponse<Branch>> {
        // return this.branchesService.findOne(+id);
        return {
            message: `Branch with ID ${id} retrieved successfully`,
            data: await this.branchesService.findOne(+id),
        };
    }

    @Patch(':id')
    @RequirePermissions('branches.update')
    async update(
        @Param('id') id: string,
        @Body() updateBranchDto: UpdateBranchDto,
    ): Promise<BaseResponse<Branch>> {
        return {
            message: `Branch with ID ${id} updated successfully`,
            data: await this.branchesService.update(+id, updateBranchDto),
        };
    }

    @Delete(':id')
    @RequirePermissions('branches.delete')
    async remove(@Param('id') id: string): Promise<BaseResponse<Branch>> {
        // return this.branchesService.remove(+id);
        await this.branchesService.remove(+id);
        return {
            message: `Branch with ID ${id} deleted successfully`,
            data: null,
        };
    }
}
