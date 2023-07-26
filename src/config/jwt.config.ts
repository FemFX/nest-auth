import { JwtModuleAsyncOptions } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

export const options = (): JwtModuleAsyncOptions => ({
    inject: [ConfigService],
    useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: {
            expiresIn: configService.get('JWT_EXP', '5m'),
        },
    }),
});
