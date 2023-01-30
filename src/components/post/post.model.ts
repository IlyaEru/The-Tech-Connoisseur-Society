import mongoose from 'mongoose';

import { DateTime } from 'luxon';

const postSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      maxLength: 50,
    },
    content: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      maxLength: 255,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    versionKey: false,
  },
);

postSchema.virtual('formattedCreatedAt').get(function () {
  return DateTime.fromJSDate(this.createdAt).toLocaleString(DateTime.DATE_MED);
});
const Post = mongoose.model('Post', postSchema);

export default Post;
