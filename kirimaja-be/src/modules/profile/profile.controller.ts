import {
    Controller,
    Get,
    Body,
    Patch,
    UseGuards,
    Req,
    UseInterceptors,
    UploadedFile,
    BadRequestException,
} from '@nestjs/common';
import { ProfileService } from './profile.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { JwtAuthGuard } from '../auth/guard/logged-in-guard';
import { BaseResponse } from 'src/common/interface/base-response.interface';
import { ProfileResponse } from './response/profile.response';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';

@Controller('profile')
@UseGuards(JwtAuthGuard)
export class ProfileController {
    constructor(private readonly profileService: ProfileService) {}

    @Get()
    async findOne(
        @Req() req: Request & { user?: any },
    ): Promise<BaseResponse<ProfileResponse>> {
        return {
            message: 'Profile retrieved successfully',
            data: await this.profileService.findOne(req.user.id),
        };
    }

    @Patch()
    @UseInterceptors(
        FileInterceptor('avatar', {
            storage: diskStorage({
                destination: './public/uploads/photos',
                filename: (req, file, cb) => {
                    const uniqueSuffix =
                        Date.now() + '-' + Math.round(Math.random() * 1e9);
                    cb(null, uniqueSuffix + extname(file.originalname));
                },
            }),
            fileFilter: (req, file, cb) => {
                if (!file.originalname.match(/\.(jpg|jpeg|png|gif|avif)$/)) {
                    return cb(
                        new BadRequestException(
                            'Only image files are allowed!!',
                        ),
                        false,
                    );
                }
                cb(null, true);
            },
        }),
    )
    async update(
        @Req() req: Request & { user?: any },
        @Body() updateProfileDto: UpdateProfileDto,
        @UploadedFile() avatar?: Express.Multer.File,
    ): Promise<BaseResponse<ProfileResponse>> {
        return {
            message: 'Profile updated successfully',
            data: await this.profileService.update(
                req.user.id,
                updateProfileDto,
                avatar?.filename ?? undefined,
            ),
        };
    }
}
