import { ConfigModule } from '@nestjs/config';

import { AppController } from './controller/AppController';
import { TransactionInterceptor } from './interceptor/TransactionInterceptor';

import { DatabaseModule } from './db/database.module';

import { Logger, Module } from '@nestjs/common';
import { UserModule } from './users/user.module';

@Module({
  imports: [ConfigModule.forRoot(), DatabaseModule, UserModule],
  controllers: [AppController],
  providers: [Logger, TransactionInterceptor],
})
export class AppModule {}
