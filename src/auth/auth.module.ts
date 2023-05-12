import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AtStrategy, RtStrategy } from './strategies';
import { ConfigService } from '@nestjs/config';
import { DatabaseModule } from 'src/db/database.module';

@Module({
  imports: [JwtModule, PassportModule, PassportModule.register({}), JwtModule.register({}), DatabaseModule],
  controllers: [AuthController],
  providers: [AuthService, AtStrategy, RtStrategy, ConfigService],
})
export class AuthModule {}
