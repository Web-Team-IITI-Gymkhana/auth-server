import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-google-oauth20';
import { AuthService } from './auth/auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private authService: AuthService) {
    super({
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: process.env.REDIRECT_URI,
      scope: ['profile', 'email'],
    });
  }

  // eslint-disable-next-line @typescript-eslint/ban-types
  async validate(state: string, refreshToken: string, code: string) {
    const user = await this.authService.validateGoogleOAuthLogin(code);

    return user;
  }
}
