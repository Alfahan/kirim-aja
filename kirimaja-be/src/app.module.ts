import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './modules/auth/auth.module';
import { RolesModule } from './modules/roles/roles.module';

@Module({
    imports: [AuthModule, RolesModule],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {}
