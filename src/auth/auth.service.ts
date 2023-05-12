import { BadRequestException, ForbiddenException, Inject, Injectable } from '@nestjs/common';
//import { PrismaService } from 'prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
//import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';
import { JwtPayload, Tokens } from './types';
import * as jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { UserModel } from 'src/db/models';
import { USER_DAO } from 'src/constants';
import { randomUUID } from 'crypto';
import { log } from 'winston';

@Injectable()
export class AuthService {
  private readonly googleOAuth2Client: OAuth2Client;
  configService: any;

  constructor(
    private config: ConfigService,
    @Inject(USER_DAO)
    private readonly userModel: typeof UserModel,
    private jwtService: JwtService,
  ) {
    this.googleOAuth2Client = new OAuth2Client({
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      redirectUri: process.env.REDIRECT_URI,
    });
  }

  async signup(dto: AuthDto): Promise<Tokens> {
    const { email, password } = dto;

    const userExists = await this.userModel.findOne({
      where: { email },
    });

    if (userExists) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.userModel
      .create({
        hashedPassword,
        email,
        authType: 'PASSWORD',
      })
      .catch((error) => {
        if (error.name === 'SequelizeUniqueConstraintError') {
          throw new ForbiddenException('Credentials incorrect');
        }
        throw error;
      });

    const user = await this.userModel.findOne({
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

    const foundUser = await this.userModel.findOne({
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

  async signout(id: typeof randomUUID): Promise<boolean> {
    const data = {
      hashedRT: null,
    };
    await this.userModel
      .update(data, {
        where: {
          id: id,
        },
      })
      .then((result) => {
        console.log(result);
        return true;
      })
      .catch((err) => {
        console.log('user dosent exist');
        console.error(err);
        return false;
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

  async refreshTokens(id: typeof randomUUID, rt: string): Promise<Tokens> {
    const user = await this.userModel.findOne({
      where: {
        id: id,
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

  async updateRtHash(id: typeof randomUUID, rt: string): Promise<void> {
    const hash = await this.hashPassword(rt);
    await this.userModel.update(
      {
        hashedRT: hash,
      },
      {
        where: {
          id: id,
        },
      },
    );
  }

  async getTokens(id: typeof randomUUID, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: id,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '7d',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '346d',
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

  async signToken(args: { id: typeof randomUUID; email: string }) {
    const payload = {
      id: args.id,
      email: args.email,
    };

    const token = await this.jwtService.signAsync(payload, {
      secret: jwtSecret,
    });

    return token;
  }

  async getGoogleOAuthUrl(curl: any): Promise<string> {
    const authorizeUrl = this.googleOAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: ['profile', 'email'],
      state: curl,
    });
    return authorizeUrl;
  }

  async validateGoogleOAuthLogin(code: any): Promise<Tokens> {
    const email = code._json.email;
    let user: any;
    let isiitimember: boolean;
    isiitimember = false;
    if (code._json.hd == 'iiti.ac.in') {
      isiitimember = true;
    }
    const userExists = await this.userModel.findOne({
      where: { email },
    });

    if (userExists) {
      user = await this.userModel.findOne({
        where: {
          email,
        },
      });
    } else {
      await this.userModel
        .create({
          email,
          authType: 'GOOGLE',
          isVerified: isiitimember,
        })
        .catch((error) => {
          if (error.name === 'SequelizeUniqueConstraintError') {
            throw new ForbiddenException('Credentials incorrect');
          }
          throw error;
        });

      user = await this.userModel.findOne({
        where: {
          email,
        },
      });
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }
}
