// google.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { AuthService } from './auth/auth.service';
// import {proxyport} from './main';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private authService: AuthService) {
    super({
      clientID: '603233410519-7l5m743sbl56ntteagmsortt1f32i2q7.apps.googleusercontent.com',
      clientSecret: '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',
      callbackURL: `http://localhost:3000/v1/auth/login/google/callback`,
      scope: ['profile', 'email'],
    });
  }

  // eslint-disable-next-line @typescript-eslint/ban-types
  async validate(accessToken: string, refreshToken: string, code: string) {
    console.log(code);
    const user = await this.authService.validateGoogleOAuthLogin(code);
    console.log(accessToken);
    console.log(refreshToken);
    return user;
  }
}
