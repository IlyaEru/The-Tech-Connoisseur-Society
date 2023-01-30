import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxLength: 50,
    },
    password: {
      type: String,
      required: true,
      trim: true,
      minlength: 6,
      maxLength: 255,
    },
    member: {
      type: Boolean,
      default: false,
    },
    admin: {
      type: Boolean,
      default: false,
    },
  },
  {
    versionKey: false,
  },
);

const User = mongoose.model('User', userSchema);

export default User;
