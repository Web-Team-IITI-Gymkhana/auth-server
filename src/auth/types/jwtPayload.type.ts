import { randomUUID } from 'crypto';

export type JwtPayload = {
  email: string;
  sub: typeof randomUUID;
};
