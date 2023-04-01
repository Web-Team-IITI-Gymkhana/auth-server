import { Column, DataType, Model, Table } from 'sequelize-typescript';
import cuid from 'cuid';

@Table({
  tableName: 'user',
})
export class UserModel extends Model {
  @Column({
    primaryKey: true,
    allowNull: false,
    type: DataType.STRING,
    defaultValue: cuid,
  })
  id: string;

  @Column
  firstName: string;

  @Column
  lastName: string;

  @Column({ defaultValue: true })
  isActive: boolean;
}
