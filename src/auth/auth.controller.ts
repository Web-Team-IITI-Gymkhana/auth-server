import { AuthDto } from './dto/auth.dto';
import { randomUUID } from 'crypto';
import { USER_SERVICE } from 'src/constants';
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
  Query,
  UseInterceptors,
} from '@nestjs/common';
import { GetCurrentUserId, GetCurrentUser } from '../common/decorators';
import { AtGuard, RtGuard } from '../common/guards';
import { AuthService } from './auth.service';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { log } from 'console';
import { query } from 'express';
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
      return 'You have access to the protected resource';
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
    const jwt = await this.authService.validateGoogleOAuthLogin(req.query.code);
    // console.log(req.query);
    res.redirect(`http://localhost:3001/success?token=${jwt}`);
    // res.send({ message: 'success' });
  }
}
