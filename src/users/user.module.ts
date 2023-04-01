import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { DatabaseModule } from 'src/db/database.module';
import { USER_SERVICE } from 'src/constants';

@Module({
  imports: [DatabaseModule],
  providers: [{ provide: USER_SERVICE, useClass: UserService }],
  exports: [USER_SERVICE],
  controllers: [UserController],
})
export class UserModule {}
