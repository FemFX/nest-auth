import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from '@user/user.module';
import { options } from 'src/config';
import { STRATEGIES } from './strategies';
import { GUARDS } from './guards';
import { HttpModule } from '@nestjs/axios';

@Module({
    imports: [PassportModule, JwtModule.registerAsync(options()), UserModule, HttpModule],
    controllers: [AuthController],
    providers: [AuthService, ...STRATEGIES, ...GUARDS],
})
export class AuthModule {}
