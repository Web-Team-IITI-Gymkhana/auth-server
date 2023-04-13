import { Sequelize } from 'sequelize-typescript';
import { Logger } from '@nestjs/common';

import { isProductionEnv } from '../utils/utils';
import { ProfileModel, UserModel } from './models';
import { USER_DAO } from 'src/constants';

export const databaseProviders = [
  {
    provide: 'SEQUELIZE',
    useFactory: async () => {
      // const dbName = 'new_auth';
      // const dbUser = 'new_auth_user';
      // //<dialect>://<username>:<password>@<host>/<db_name>
      // const dbHost = 'dpg-cgrh93vdvk4n7bsbuea0-a.singapore-postgres.render.com';
      // const dbDriver = 'postgres';
      // const dbPassword = 'sqGE1invWBOJuuJVJDQDIsyVRxEqvM5F';
      const dbName = process.env.DB_NAME as string;
      const dbUser = process.env.DB_USERNAME as string;
      const dbHost = process.env.DB_HOST as string;
      const dbDriver = 'postgres';
      const dbPassword = process.env.DB_PASSWORD as string;
      const dbPort = Number(process.env.DB_PORT);
      console.log('host', dbHost);
      //const cloudDbUrl = process.env.DATABASE_URL;
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
