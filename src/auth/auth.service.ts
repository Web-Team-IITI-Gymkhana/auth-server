import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';
import { Request, Response } from 'express';
import { JwtPayload, Tokens } from './types';
import * as jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { log } from 'console';

@Injectable()
export class AuthService {
  private readonly googleOAuth2Client: OAuth2Client;

  constructor(private config: ConfigService, private prisma: PrismaService, private jwtService: JwtService) {
    this.googleOAuth2Client = new OAuth2Client({
      clientId: '603233410519-7l5m743sbl56ntteagmsortt1f32i2q7.apps.googleusercontent.com',
      clientSecret: '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',
      redirectUri: `http://localhost:3000/v1/auth/login/google/callback`,
    });
  }

  async signup(dto: AuthDto): Promise<Tokens> {
    const { email, password, authType } = dto;

    const userExists = await this.prisma.user.findUnique({
      where: { email },
    });

    if (userExists) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user
      .create({
        data: {
          hashedPassword,
          email,
          authType: 'PASSWORD',
        },
      })
      .catch((error) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2002') {
            throw new ForbiddenException('Credentials incorrect');
          }
        }
        throw error;
      });

    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;

    //return { message: 'User created succefully' };
  }

  async signin(dto: AuthDto): Promise<Tokens> {
    const { email, password } = dto;

    const foundUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!foundUser) {
      throw new BadRequestException('Wrong credentials');
    }

    const compareSuccess = await this.comparePasswords({
      password,
      hash: foundUser.hashedPassword,
    });

    if (!compareSuccess) {
      throw new BadRequestException('Wrong credentials');
    }

    const tokens = await this.getTokens(foundUser.id, foundUser.email);
    await this.updateRtHash(foundUser.id, tokens.refresh_token);

    return tokens;
  }

  async signout(userId: string): Promise<boolean> {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRT: {
          not: null,
        },
      },
      data: {
        hashedRT: null,
      },
    });
    return true;
  }

  async verifyAccessToken(token: string): Promise<{ expired: boolean; payload: any }> {
    return new Promise((resolve, reject) => {
      jwt.verify(token, 'at-secret', (err, decoded) => {
        if (err) {
          if (err.name === 'TokenExpiredError') {
            //const timeRemaining = Math.floor((err.expiredAt.getTime() - Date.now()) / 1000);
            resolve({ expired: true, payload: null });
          } else {
            reject(err);
          }
        } else {
          resolve({ expired: false, payload: decoded });
        }
      });
    });
  }

  async refreshTokens(userId: string, rt: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashedRT) {
      throw new ForbiddenException('Access Denied');
    }

    const rtMatches = await this.comparePasswords({ password: rt, hash: user.hashedRT });
    if (!rtMatches) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async updateRtHash(userId: string, rt: string): Promise<void> {
    const hash = await this.hashPassword(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRT: hash,
      },
    });
  }

  async getTokens(userId: string, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;

    return await bcrypt.hash(password, saltOrRounds);
  }

  async comparePasswords(args: { hash: string; password: string }) {
    return await bcrypt.compare(args.password, args.hash);
  }

  async signToken(args: { userId: string; email: string }) {
    const payload = {
      id: args.userId,
      email: args.email,
    };

    const token = await this.jwtService.signAsync(payload, {
      secret: jwtSecret,
    });

    return token;
  }

  async getGoogleOAuthUrl(): Promise<string> {
    const authorizeUrl = this.googleOAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: ['profile', 'email'],
      state: 
    });
    return authorizeUrl;
  }

  async validateGoogleOAuthLogin(profile: any): Promise<any> {
    console.log('gauth happening');
  }
}
