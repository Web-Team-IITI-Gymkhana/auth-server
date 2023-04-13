import { randomUUID } from 'crypto';
import sequelize from 'sequelize';
import { Column, CreatedAt, DataType, Model, Table, Unique, UpdatedAt } from 'sequelize-typescript';

@Table({
  tableName: 'user',
})
export class UserModel extends Model {
  @Column({
    primaryKey: true,
    allowNull: false,
    type: sequelize.UUID,
    defaultValue: sequelize.UUIDV4,
  })
  UserId: typeof randomUUID;

  @Unique
  @Column
  email: string;

  @Column
  hashedPassword: string;

  @Column
  authType: string;

  @Column
  @CreatedAt
  createdAt: Date;

  @Column
  @UpdatedAt
  updatedAt: Date;

  @Column({ defaultValue: false })
  isVerified: boolean;

  @Column({
    allowNull: true,
  })
  hashedRT: string;
}
