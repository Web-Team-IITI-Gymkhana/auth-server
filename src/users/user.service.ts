import { Inject, Injectable } from '@nestjs/common';
import { User } from './user.entity';
import { UserModel } from 'src/db/models';
import { USER_DAO } from 'src/constants';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { Request } from 'express';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(
    @Inject(USER_DAO)
    private readonly userModel: typeof UserModel,
    private prisma: PrismaService,
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

  async getMyUser(id: string, req: Request) {
    const decodedUserInfo = req['user'] as { id: string; email: string };

    const foundUser = await this.prisma.user.findUnique({ where: { id } });

    if (!foundUser) {
      throw new NotFoundException();
    }

    if (foundUser.id !== decodedUserInfo.id) {
      throw new ForbiddenException();
    }

    delete foundUser.hashedPassword;

    return { user: foundUser };
  }

  async getUsers() {
    const users = await this.prisma.user.findMany({
      select: { id: true, email: true },
    });

    return { users };
  }
}
