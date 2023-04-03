import { AuthDto } from './dto/auth.dto';
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
} from '@nestjs/common';
import { GetCurrentUserId, GetCurrentUser } from '../common/decorators';
import { AtGuard, RtGuard } from '../common/guards';
import { AuthService } from './auth.service';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  signup(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signup(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  signin(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signin(dto);
  }
  @UseGuards(AtGuard)
  @Get('logout')
  @HttpCode(HttpStatus.OK)
  signout(@GetCurrentUserId() userId: string): Promise<boolean> {
    return this.authService.signout(userId);
  }
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: string,
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
}
