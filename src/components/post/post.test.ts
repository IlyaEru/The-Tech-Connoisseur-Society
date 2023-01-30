import Post from './post.model';
import mongoose from 'mongoose';

import { setUpDb, dropDb, dropCollections } from '../../config/test-db';

beforeAll(async () => {
  await setUpDb();
});

beforeEach(async () => {
  await dropCollections();
});

afterAll(async () => {
  await dropCollections();
  await dropDb();
});

const postData = {
  title: 'test',
  content: 'testBody',
  user: new mongoose.Types.ObjectId(),
  createdAt: new Date(),
};

describe('Post model', () => {
  test('should create a post', async () => {
    const post = await Post.create(postData);
    expect(post).toMatchObject(postData);
  });

  test('should not create a post without title', async () => {
    let error = null;
    try {
      await Post.create({
        body: 'testBody',
        user: new mongoose.Types.ObjectId(),
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a post without body', async () => {
    let error = null;
    try {
      await Post.create({
        title: 'test',
        user: new mongoose.Types.ObjectId(),
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a post without user', async () => {
    let error = null;
    try {
      await Post.create({
        title: 'test',
        body: 'testBody',
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a post with a short title', async () => {
    let error = null;

    try {
      await Post.create({
        title: 'te',
        body: 'testBody',
        user: new mongoose.Types.ObjectId(),
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a post with a short body', async () => {
    let error = null;

    try {
      await Post.create({
        title: 'test',
        body: 'te',
        user: new mongoose.Types.ObjectId(),
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a post with a short user', async () => {
    let error: any = null;

    try {
      await Post.create({
        title: 'test',
        body: 'testBody',
        user: new mongoose.Types.ObjectId('123'),
      });
    } catch (err) {
      error = err;
    }

    expect(error).not.toBeNull();
  });

  test('should have createdAt', async () => {
    const post = await Post.create(postData);
    expect(post.createdAt).toBeDefined();
  });

  test('should have formatted createdAt', async () => {
    const post: any = await Post.create({
      ...postData,
      createdAt: new Date('2020-01-01'),
    });
    expect(post.formattedCreatedAt).toBeDefined();
  });

  test('should not create a post with a long title', async () => {
    let error = null;

    try {
      await Post.create({
        title: 'te'.repeat(100),
        body: 'testBody',
        user: new mongoose.Types.ObjectId(),
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a post with a long body', async () => {
    let error = null;

    try {
      await Post.create({
        title: 'test',
        body: 'te'.repeat(100),
        user: new mongoose.Types.ObjectId(),
      });
    } catch (err) {
      error = err;
    }

    expect(error).toBeDefined();
  });
});
