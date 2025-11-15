import { Module } from '@nestjs/common';
import { UserAddressService } from './user-address.service';
import { UserAddressController } from './user-address.controller';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { OpenStreetService } from 'src/common/openstreetmap/openstreet.service';

@Module({
    controllers: [UserAddressController],
    providers: [UserAddressService, PrismaService, OpenStreetService],
})
export class UserAddressModule {}
