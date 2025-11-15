import {
    BadRequestException,
    Injectable,
    NotFoundException,
} from '@nestjs/common';
import { CreateUserAddressDto } from './dto/create-user-address.dto';
import { UpdateUserAddressDto } from './dto/update-user-address.dto';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { OpenStreetService } from 'src/common/openstreetmap/openstreet.service';
import { UserAddress } from '@prisma/client';

@Injectable()
export class UserAddressService {
    constructor(
        private prismaService: PrismaService,
        private openStreetService: OpenStreetService,
    ) {}

    private readonly UPLOADS_PATH = '/uploads/photos/';

    private generatePhotoPath(filename?: string): string | null {
        return filename ? `${this.UPLOADS_PATH}${filename}` : null;
    }

    private async getCoordinatesFromAddress(
        address: string,
    ): Promise<{ lat: number; lng: number } | null> {
        return await this.openStreetService.geocode(address);
    }

    async create(
        createUserAddressDto: CreateUserAddressDto,
        userId: number,
        photoFileName?: string | null,
    ): Promise<UserAddress> {
        const coordinates = await this.getCoordinatesFromAddress(
            createUserAddressDto.address,
        );

        // 2. Handle case when coordinates not found
        if (!coordinates) {
            // Option 1: Throw error
            throw new BadRequestException(
                'Could not determine coordinates for the provided address',
            );
        }

        if (photoFileName) {
            createUserAddressDto.photo = this.generatePhotoPath(photoFileName);
        }

        return await this.prismaService.userAddress.create({
            data: {
                userId,
                address: createUserAddressDto.address,
                tag: createUserAddressDto.tag,
                label: createUserAddressDto.label,
                photo: createUserAddressDto.photo,
                latitude: coordinates?.lat || null,
                longitude: coordinates?.lng || null,
            },
        });
    }

    async findAll(userId: number): Promise<UserAddress[]> {
        return await this.prismaService.userAddress.findMany({
            where: { userId },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                        phoneNumber: true,
                        avatar: true,
                    },
                },
            },
        });
    }

    async findOne(id: number): Promise<UserAddress> {
        const userAddress = await this.prismaService.userAddress.findUnique({
            where: { id },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                        phoneNumber: true,
                        avatar: true,
                    },
                },
            },
        });

        if (!userAddress) {
            throw new NotFoundException(`User address with ID ${id} not found`);
        }

        return userAddress;
    }

    async update(
        id: number,
        updateUserAddressDto: UpdateUserAddressDto,
        photoFileName?: string | null,
    ): Promise<UserAddress> {
        const userAddress = await this.findOne(id);

        let newLatitude: number | null = userAddress.latitude;
        let newLongitude: number | null = userAddress.longitude;

        // Handle address change and geocoding
        if (
            updateUserAddressDto.address &&
            updateUserAddressDto.address !== userAddress.address
        ) {
            const coordinates = await this.getCoordinatesFromAddress(
                updateUserAddressDto.address,
            );

            // Handle case when coordinates not found
            if (!coordinates) {
                throw new BadRequestException(
                    'Could not determine coordinates for the provided address',
                );
            }

            newLatitude = coordinates.lat;
            newLongitude = coordinates.lng;
        }

        // Handle photo update
        if (photoFileName) {
            updateUserAddressDto.photo = this.generatePhotoPath(photoFileName);
        }

        return await this.prismaService.userAddress.update({
            where: { id },
            data: {
                address: updateUserAddressDto.address ?? userAddress.address,
                tag: updateUserAddressDto.tag ?? userAddress.tag,
                label: updateUserAddressDto.label ?? userAddress.label,
                photo: updateUserAddressDto.photo ?? userAddress.photo,
                latitude: newLatitude,
                longitude: newLongitude,
            },
        });
    }

    async remove(id: number): Promise<void> {
        await this.findOne(id);
        await this.prismaService.userAddress.delete({
            where: { id },
        });
    }

    // Di UserAddressService
    async cleanupPhotoFile(filename: string): Promise<void> {
        try {
            const fs = require('fs').promises;
            const path = require('path');
            const filePath = path.join('./public/uploads/photos', filename);
            await fs.unlink(filePath);
        } catch (error) {
            console.error('Failed to cleanup photo file:', error);
        }
    }
}
