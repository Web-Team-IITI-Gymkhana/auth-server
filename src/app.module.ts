/* eslint-disable prettier/prettier */
import { ConfigModule } from '@nestjs/config';

import { AppController } from './controller/AppController';
import { TransactionInterceptor } from './interceptor/TransactionInterceptor';

import { DatabaseModule } from './db/database.module';

import { Logger, Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from '../prisma/prisma.module';
// import { UsersModule } from './users/';
import { UserModule } from './users/user.module';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './google.strategy';
import { AuthService } from './auth/auth.service';
import { JwtService } from '@nestjs/jwt';
@Module({
  imports: [ConfigModule.forRoot(), DatabaseModule,AuthModule,PrismaModule, UserModule,PassportModule,],
  controllers: [AppController],
  providers: [Logger, TransactionInterceptor,GoogleStrategy,AuthService,JwtService],
})

export class AppModule { }
