import {
    Controller,
    Get,
    Post,
    Body,
    Patch,
    Param,
    Delete,
    UseGuards,
    UseInterceptors,
    UploadedFile,
    Req,
    ParseIntPipe,
    BadRequestException,
} from '@nestjs/common';
import { UserAddressService } from './user-address.service';
import { CreateUserAddressDto } from './dto/create-user-address.dto';
import { UpdateUserAddressDto } from './dto/update-user-address.dto';
import { JwtAuthGuard } from '../auth/guard/logged-in-guard';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { BaseResponse } from 'src/common/interface/base-response.interface';
import { UserAddress } from '@prisma/client';

// Reusable file interceptor configuration
const photoInterceptorConfig = FileInterceptor('photo', {
    storage: diskStorage({
        destination: './public/uploads/photos',
        filename: (req, file, cb) => {
            const uniqueSuffix =
                Date.now() + '-' + Math.round(Math.random() * 1e9);
            cb(null, uniqueSuffix + extname(file.originalname));
        },
    }),
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB
    },
    fileFilter: (req, file, cb) => {
        const allowedMimes = [
            'image/jpeg',
            'image/png',
            'image/jpg',
            'image/gif',
        ];

        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(
                new BadRequestException(
                    'Invalid file type. Only JPEG, PNG, JPG, GIF are allowed.',
                ),
                false,
            );
        }
    },
});

@Controller('user-addresses')
@UseGuards(JwtAuthGuard)
export class UserAddressController {
    constructor(private readonly userAddressService: UserAddressService) {}

    @Post()
    @UseInterceptors(photoInterceptorConfig)
    async create(
        @Body() createUserAddressDto: CreateUserAddressDto,
        @Req() req: Request & { user?: any },
        @UploadedFile() photo: Express.Multer.File,
    ): Promise<BaseResponse<UserAddress>> {
        try {
            const data = await this.userAddressService.create(
                createUserAddressDto,
                req.user.id,
                photo?.filename || null,
            );

            return {
                data,
                message: 'User address created successfully',
            };
        } catch (error) {
            // Clean up uploaded file if creation fails
            if (photo) {
                await this.userAddressService
                    .cleanupPhotoFile(photo.filename)
                    .catch(console.error);
            }
            throw error;
        }
    }

    @Get()
    async findAll(
        @Req() req: Request & { user?: any },
    ): Promise<BaseResponse<UserAddress[]>> {
        const data = await this.userAddressService.findAll(req.user.id);

        return {
            data,
            message: 'User addresses retrieved successfully',
        };
    }

    @Get(':id')
    async findOne(
        @Param('id', ParseIntPipe) id: number,
    ): Promise<BaseResponse<UserAddress>> {
        const data = await this.userAddressService.findOne(id);

        return {
            data,
            message: 'User address retrieved successfully',
        };
    }

    @Patch(':id')
    @UseInterceptors(photoInterceptorConfig)
    async update(
        @Param('id', ParseIntPipe) id: number,
        @Body() updateUserAddressDto: UpdateUserAddressDto,
        @UploadedFile() photo: Express.Multer.File,
    ): Promise<BaseResponse<UserAddress>> {
        try {
            const data = await this.userAddressService.update(
                id,
                updateUserAddressDto,
                photo?.filename || null,
            );

            return {
                data,
                message: 'User address updated successfully',
            };
        } catch (error) {
            // Clean up uploaded file if update fails
            if (photo) {
                await this.userAddressService
                    .cleanupPhotoFile(photo.filename)
                    .catch(console.error);
            }
            throw error;
        }
    }

    @Delete(':id')
    async remove(
        @Param('id', ParseIntPipe) id: number,
    ): Promise<BaseResponse<void>> {
        await this.userAddressService.remove(id);

        return {
            data: null,
            message: 'User address deleted successfully',
        };
    }
}
