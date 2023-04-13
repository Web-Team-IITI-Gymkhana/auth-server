import { Column, DataType, Model, Table, ForeignKey, BelongsTo } from 'sequelize-typescript';
import { UserModel } from './user';
import sequelize from 'sequelize';
import { randomUUID } from 'crypto';

@Table({
  tableName: 'profile',
})
export class ProfileModel extends Model {
  @Column({
    primaryKey: true,
    allowNull: false,
    type: sequelize.UUID,
    defaultValue: sequelize.UUIDV4,
  })
  id: typeof randomUUID;

  @Column({
    type: DataType.STRING(255),
  })
  Name: string;

  @Column({ type: DataType.STRING }) imageUrl: Record<string, any>;

  @Column({ type: DataType.JSON }) Metadata: Record<string, any>;

  @ForeignKey(() => UserModel)
  @Column(sequelize.UUID)
  profileId: string;

  @BelongsTo(() => UserModel, 'UserId')
  profile: UserModel;
}
