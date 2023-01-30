import { Types } from 'mongoose';

export interface UserType {
  _id: Types.ObjectId;
  username: string;
  password: string;
  member: boolean;
  admin: boolean;
}

declare global {
  namespace Express {
    interface User extends UserType {}
  }
}
