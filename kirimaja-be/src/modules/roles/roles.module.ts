import { Module } from '@nestjs/common';
import { RolesService } from './roles.service';
import { RolesController } from './roles.controller';
import { PrismaService } from '../../common/prisma/prisma.service';
import { JwtStrategy } from '../auth/strategies/jwt.strategy';

@Module({
    controllers: [RolesController],
    providers: [RolesService, PrismaService, JwtStrategy],
})
export class RolesModule {}
