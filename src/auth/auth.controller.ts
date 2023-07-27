import {
    Controller,
    Post,
    Body,
    Get,
    BadRequestException,
    UnauthorizedException,
    Res,
    HttpStatus,
    UseInterceptors,
    ClassSerializerInterceptor,
    UseGuards,
    Req,
    Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';
import { Tokens } from './interfaces';
import { ConfigService } from '@nestjs/config';
import { Cookie, Public, UserAgent } from '@common/decorators';
import { Response, Request } from 'express';
import { UserResponse } from '@user/responses';
import { GoogleGuard } from './guards/google.guard';
import { HttpService } from '@nestjs/axios';
import { map, mergeMap, tap } from 'rxjs';
import { handleTimeoutAndErrors } from '@common/helpers';
import { YandexGuard } from './guards/yandex.guard';
import { Provider } from '@prisma/client';

const REFRESH_TOKEN = 'refresh_token';

@Public()
@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly configService: ConfigService,
        private readonly httpService: HttpService,
    ) {}
    @UseInterceptors(ClassSerializerInterceptor)
    @Post('register')
    async register(@Body() dto: RegisterDto) {
        const user = await this.authService.register(dto);
        if (!user) {
            throw new BadRequestException(
                `Не получается зарегистрировать пользователя с данными ${JSON.stringify(dto)}`,
            );
        }
        return new UserResponse(user);
    }

    @Post('login')
    async login(@Body() dto: LoginDto, @Res() res: Response, @UserAgent() agent: string) {
        const tokens = await this.authService.login(dto, agent);
        if (!tokens) {
            throw new BadRequestException(`Не получается войти с данными ${JSON.stringify(dto)}`);
        }
        this.setRefreshTokenToCookie(tokens, res);
    }
    @Get('logout')
    async logout(@Cookie(REFRESH_TOKEN) refreshToken: string, @Res() res: Response) {
        if (!refreshToken) {
            res.sendStatus(HttpStatus.OK);
            return;
        }
        await this.authService.deleteRefreshToken(refreshToken);
        res.cookie(REFRESH_TOKEN, '', { httpOnly: true, secure: true, expires: new Date() });
        res.sendStatus(HttpStatus.OK);
    }
    @Get('refresh')
    async refresh(@Cookie(REFRESH_TOKEN) refreshToken: string, @Res() res: Response, @UserAgent() agent: string) {
        if (!refreshToken) {
            throw new UnauthorizedException();
        }
        const tokens = await this.authService.refresh(refreshToken, agent);
        if (!tokens) {
            throw new UnauthorizedException();
        }
        this.setRefreshTokenToCookie(tokens, res);
    }

    private setRefreshTokenToCookie(tokens: Tokens, res: Response) {
        if (!tokens) {
            throw new UnauthorizedException();
        }
        res.cookie(REFRESH_TOKEN, tokens.refreshToken.token, {
            httpOnly: true,
            sameSite: 'lax',
            expires: new Date(tokens.refreshToken.exp),
            secure: this.configService.get('NODE_ENV', 'development') === 'production',
            path: '/',
        });
        return res.status(HttpStatus.CREATED).json({
            accessToken: tokens.accessToken,
        });
    }
    @UseGuards(GoogleGuard)
    @Get('google')
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    googleAuth() {}
    @UseGuards(GoogleGuard)
    @Get('google/callback')
    googleAuthCallback(@Req() req: Request, @Res() res: Response) {
        console.log(req.user);

        const token = req.user['accessToken'];

        return res.redirect(`http://localhost:3000/api/auth/success-google?token=${token}`);
    }
    //client
    @Get('success-google')
    successGoogle(@Query('token') token: string, @UserAgent() agent: string, @Res() res: Response) {
        //https://www.googleapis.com/oauth2/v3/userinfo GET
        return this.httpService.get(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${token}`).pipe(
            // map(({ data }) => {
            //     console.log(data);
            //     return data;
            // }),
            mergeMap(({ data: { email } }) => this.authService.providerAuth(email, agent, Provider.GOOGLE)),
            map((data) => this.setRefreshTokenToCookie(data, res)),
            handleTimeoutAndErrors(),
        );
    }

    @UseGuards(YandexGuard)
    @Get('yandex')
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    yandexAuth() {}
    @UseGuards(YandexGuard)
    @Get('yandex/callback')
    yandexAuthCallback(@Req() req: Request, @Res() res: Response) {
        console.log(req.user);

        const token = req.user['accessToken'];

        return res.redirect(`http://localhost:3000/api/auth/success-yandex?token=${token}`);
    }
    @Get('success-yandex')
    successYandex(@Query('token') token: string, @UserAgent() agent: string, @Res() res: Response) {
        //https://www.googleapis.com/oauth2/v3/userinfo GET
        return this.httpService.get(`https://login.yandex.ru/info?format=json&oauth_token=${token}`).pipe(
            // map(({ data }) => {
            //     console.log(data);
            //     return data;
            // }),
            mergeMap(({ data: { default_email } }) =>
                this.authService.providerAuth(default_email, agent, Provider.YANDEX),
            ),
            map((data) => this.setRefreshTokenToCookie(data, res)),
            handleTimeoutAndErrors(),
        );
    }
}
