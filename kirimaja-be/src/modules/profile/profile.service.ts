import { Injectable, NotFoundException } from '@nestjs/common';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { PrismaService } from '../../common/prisma/prisma.service';
import { ProfileResponse } from './response/profile.response';
import { plainToInstance } from 'class-transformer';
import * as bcrypt from 'bcrypt';

@Injectable()
export class ProfileService {
    constructor(private prismaService: PrismaService) {}

    async findOne(id: number): Promise<ProfileResponse> {
        const user = await this.prismaService.user.findUnique({
            where: { id },
            select: {
                id: true,
                email: true,
                name: true,
                avatar: true,
                phoneNumber: true,
            },
        });

        if (!user) {
            throw new NotFoundException(`User with id ${id} not  found`);
        }

        return plainToInstance(ProfileResponse, user, {
            excludeExtraneousValues: true,
        });
    }

    async update(
        id: number,
        updateProfileDto: UpdateProfileDto,
        avatarFileName?: string,
    ): Promise<ProfileResponse> {
        const user = await this.prismaService.user.findUnique({
            where: { id },
        });

        if (!user) {
            throw new NotFoundException(`User with id ${id} not found`);
        }

        const updatedData: any = {};

        if (updateProfileDto.email) {
            updatedData.email = updateProfileDto.email;
        }

        if (updateProfileDto.name) {
            updatedData.name = updateProfileDto.name;
        }

        if (updateProfileDto.phone_number) {
            updatedData.phoneNumber = updateProfileDto.phone_number;
        }

        if (avatarFileName) {
            updatedData.avatar = `/uploads/photos/${avatarFileName}`;
        }

        if (updateProfileDto.password) {
            const hashedPassword = await bcrypt.hash(
                updateProfileDto.password,
                10,
            );
            updatedData.password = hashedPassword;
        }

        const updatedUser = await this.prismaService.user.update({
            where: { id },
            data: updatedData,
            select: {
                id: true,
                email: true,
                name: true,
                avatar: true,
                phoneNumber: true,
            },
        });

        return plainToInstance(ProfileResponse, updatedUser, {
            excludeExtraneousValues: true,
        });
    }
}
