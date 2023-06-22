import { AuthDto } from './dto/auth.dto';
import { randomUUID } from 'crypto';
import {
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
  Get,
  UseGuards,
  UnauthorizedException,
  Res,
  Req,
  UseInterceptors,
} from '@nestjs/common';
import { GetCurrentUserId, GetCurrentUser } from '../common/decorators';
import { AtGuard, RtGuard } from '../common/guards';
import { AuthService } from './auth.service';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';

import { LoggerInterceptor } from 'src/interceptor/LoggerInterceptor';
import { TransactionInterceptor } from 'src/interceptor/TransactionInterceptor';

@UseInterceptors(new LoggerInterceptor())
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(TransactionInterceptor)
  signup(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signup(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(TransactionInterceptor)
  signin(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signin(dto);
  }
  @UseGuards(AtGuard)
  @Get('logout')
  @HttpCode(HttpStatus.OK)
  @UseInterceptors(TransactionInterceptor)
  signout(@GetCurrentUserId() userId: typeof randomUUID): Promise<boolean> {
    return this.authService.signout(userId);
  }
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: typeof randomUUID,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ): Promise<Tokens> {
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @Get('verify')
  async getProtectedResource(@Headers('authorization') authHeader: string): Promise<any> {
    try {
      const token = authHeader.split(' ')[1];
      const { expired, payload } = await this.authService.verifyAccessToken(token);
      if (expired) {
        throw new UnauthorizedException(`Access token has expired`);
      }
      // Perform additional checks on the payload
      // ...
      return { status: 200, email: payload.email };
    } catch (err) {
      throw new UnauthorizedException('Invalid access token');
    }
  }

  @Post('login/google')
  async getGoogleOAuthUrl(@Req() req) {
    console.log('hello');

    const curl = req.body.curl;
    const redirectUrl = await this.authService.getGoogleOAuthUrl(curl);

    return { url: redirectUrl, curl };
  }

  @Get('login/google/callback')
  @UseGuards(AuthGuard('google'))
  async loginWithGoogleCallback(@Req() req, @Res() res): Promise<void> {
    const tokens = req.user;
    console.log(tokens);
    const state = req.query.state;
    console.log(state);

    const accessToken = tokens.access_token;
    const refreshToken = tokens.refresh_token;

    const redirectUrl = `${state}?access_token=${encodeURIComponent(accessToken)}&refresh_token=${encodeURIComponent(
      refreshToken,
    )}`;

    res.redirect(redirectUrl);
  }
}
