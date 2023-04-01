import { Inject, Injectable } from '@nestjs/common';
import { User } from './user.entity';
import { UserModel } from 'src/db/models';
import { USER_DAO } from 'src/constants';

@Injectable()
export class UserService {
  constructor(
    @Inject(USER_DAO)
    private readonly userModel: typeof UserModel,
  ) {}

  create(createUserDto: User): Promise<User> {
    return this.userModel.create({
      firstName: createUserDto.firstName,
      lastName: createUserDto.lastName,
    });
  }

  async findAll(): Promise<User[]> {
    return this.userModel.findAll();
  }

  findOne(id: string): Promise<User> {
    return this.userModel.findOne({
      where: {
        id,
      },
    });
  }

  async remove(id: string): Promise<void> {
    await this.userModel.destroy({ where: { id: id } });
  }
}
