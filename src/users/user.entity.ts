import { ApiProperty } from '@nestjs/swagger';
import { UserModel } from 'src/db/models/user';

export class User {
  @ApiProperty()
  id: string;
  @ApiProperty()
  firstName: string;
  @ApiProperty()
  lastName: string;
  @ApiProperty()
  isActive: boolean;
  @ApiProperty()
  createdAt?: Date;
  @ApiProperty()
  updatedAt?: Date;

  constructor(inputs: {
    id?: string;
    firstName: string;
    lastName: string;
    isActive: boolean;
    createdAt?: Date;
    updatedAt?: Date;
  }) {
    Object.assign(this, inputs);
  }

  static fromModel(user: UserModel): User {
    return new this({
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    });
  }
}
