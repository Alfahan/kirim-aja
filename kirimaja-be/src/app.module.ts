import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './modules/auth/auth.module';
import { RolesModule } from './modules/roles/roles.module';
import { PermissionsModule } from './modules/permissions/permissions.module';
import { JwtAuthGuard } from './modules/auth/guard/logged-in-guard';
import { ProfileModule } from './modules/profile/profile.module';

@Module({
    imports: [AuthModule, RolesModule, PermissionsModule, ProfileModule],
    controllers: [AppController],
    providers: [AppService, JwtAuthGuard],
})
export class AppModule {}
