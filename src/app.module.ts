/* eslint-disable prettier/prettier */
import { ConfigModule } from '@nestjs/config';
import { AppController } from './controller/AppController';
import { TransactionInterceptor } from './interceptor/TransactionInterceptor';

import { DatabaseModule } from './db/database.module';

import { Logger, Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
//import { PrismaModule } from '../prisma/prisma.module';
// import { UsersModule } from './users/';
//import { UserModule } from './users/user.module';
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
    // SequelizeModule.forRoot({
    //   dialect: 'postgres',
    //   host: '@dpg-cgrh93vdvk4n7bsbuea0-a.singapore-postgres.render.com',
    //   port: 5432,
    //   username: 'new_auth_user',
    //   password: 'sqGE1invWBOJuuJVJDQDIsyVRxEqvM5F',
    //   database: 'new_auth',
    //   autoLoadModels: true,
    //   synchronize: true,
    // }),
  ],
  controllers: [AppController],
  providers: [Logger, TransactionInterceptor, GoogleStrategy, AuthService, JwtService, LoggerInterceptor],
})
export class AppModule {}
