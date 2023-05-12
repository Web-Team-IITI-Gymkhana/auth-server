import { Sequelize } from 'sequelize-typescript';

import { ProfileModel, UserModel } from './models';
import { USER_DAO } from 'src/constants';

export const databaseProviders = [
  {
    provide: 'SEQUELIZE',
    useFactory: async () => {
      const dbName = process.env.DB_NAME as string;
      const dbUser = process.env.DB_USERNAME as string;
      const dbHost = process.env.DB_HOST as string;
      const dbDriver = 'postgres';
      const dbPassword = process.env.DB_PASSWORD as string;
      const dbPort = Number(process.env.DB_PORT);
      console.log('host', dbHost);

      const sequelize = new Sequelize(dbName, dbUser, dbPassword, {
        host: dbHost,
        dialect: dbDriver,
        port: dbPort,
        pool: {
          max: 5,
          min: 1,
          acquire: 30000,
          idle: 10000,
        },
      });
      sequelize.addModels([UserModel, ProfileModel]);
      //await sequelize.sync({ force: true });

      return sequelize;
    },
  },
];

export const spacesProviders = [
  {
    provide: USER_DAO,
    useValue: UserModel,
  },
];
