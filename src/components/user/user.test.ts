import User from './user.model';

import { setUpDb, dropDb, dropCollections } from '../../config/test-db';
import mongoose from 'mongoose';

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

const userData = {
  username: 'test',
  password: 'testPassword',
};

describe('User model', () => {
  test('should create a user', async () => {
    const user = await User.create(userData);
    expect(user).toMatchObject(userData);
  });

  test('should not create a user without username', async () => {
    let error = null;
    try {
      await User.create({ password: 'testPassword' });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a user without password', async () => {
    let error = null;
    try {
      await User.create({ username: 'test' });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a user with a short username', async () => {
    let error = null;

    try {
      await User.create({ username: 'te', password: 'testPassword' });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a user with a short password', async () => {
    let error = null;
    try {
      await User.create({ username: 'test', password: 'test' });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a user with a long username', async () => {
    let error = null;
    try {
      await User.create({ ...userData, username: 'a'.repeat(51) });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a user with a long password', async () => {
    let error = null;
    try {
      await User.create({ ...userData, password: 'a'.repeat(256) });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(mongoose.Error.ValidationError);
  });

  test('should not create a user with a duplicate username', async () => {
    let error: any = null;
    try {
      await User.create(userData);
      await User.create(userData);
    } catch (err) {
      error = err;
    }
    expect(error.code).toBe(11000);
  });

  test;
});
