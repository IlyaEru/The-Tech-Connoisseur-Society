import { Types } from 'mongoose';

export interface PostType {
  _id: Types.ObjectId;
  title: string;
  body: string;
  user: Types.ObjectId;
  createdAt: Date;
}
