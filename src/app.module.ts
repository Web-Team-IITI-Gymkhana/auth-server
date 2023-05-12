/* eslint-disable prettier/prettier */
import { ConfigModule } from '@nestjs/config';
import { AppController } from './controller/AppController';
import { TransactionInterceptor } from './interceptor/TransactionInterceptor';

import { DatabaseModule } from './db/database.module';

import { Logger, Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './google.strategy';
import { AuthService } from './auth/auth.service';
import { JwtService } from '@nestjs/jwt';
import { LoggerInterceptor } from './interceptor/LoggerInterceptor';
@Module({
  imports: [
    ConfigModule.forRoot(),
    DatabaseModule,
    AuthModule,
    PassportModule,
  ],
  controllers: [AppController],
  providers: [Logger, TransactionInterceptor, GoogleStrategy, AuthService, JwtService, LoggerInterceptor],
})
export class AppModule {}
