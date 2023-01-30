import { setUpDb, dropDb, dropCollections } from '../../config/test-db';
import request from 'supertest';
import User from '../user/user.model';
import dotenv from 'dotenv';

dotenv.config();

import app from '../../app';

const user1 = request.agent(app);

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
  passwordConfirmation: 'testPassword',
};

describe('authenticating a user', () => {
  // signup testing
  test('should get to sign up page', async () => {
    const response = await user1.get('/signup');
    expect(response.status).toBe(200);
  });

  test('should redirect upon signup', async () => {
    const response = await user1.post('/signup').send(userData);
    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/');
  });

  test('should create a user', async () => {
    await user1.post('/signup').send(userData);
    const user = User.find({ username: userData.username });
    expect(user).toBeDefined();
  });

  test('should not create a user with an existing username', async () => {
    await user1.post('/signup').send(userData);
    const response = await user1.post('/signup').send(userData);
    expect(response.status).toBe(200);
    expect(response.text).toContain('Username already exists');
  });

  test('should not create a user with a bad request', async () => {
    const badUserData = {
      username: 't',
      password: 't',
    };
    const response = await user1.post('/signup').send(badUserData);
    expect(response.status).toBe(200);
    expect(response.text).toContain(
      'Username must be between 3 and 50 characters',
    );
    expect(response.text).toContain(
      'Password must be between 6 and 255 characters',
    );
  });

  // login testing
  test('should get to login page', async () => {
    const response = await user1.get('/login');
    expect(response.status).toBe(200);
  });

  test('should login', async () => {
    const signupResponse = await user1.post('/signup').send(userData);
    expect(signupResponse.status).toBe(302);
    const response = await user1.post('/login').send(userData);
    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/');
  });

  test('should redirect upon login', async () => {
    await user1.post('/signup').send(userData);
    const response = await user1.post('/login').send(userData);
    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/');
    const homeResponse = await user1.get('/');
    expect(homeResponse.status).toBe(200);
    expect(homeResponse.text).toContain('logout');
  });

  test('should not login with a bad request', async () => {
    const badUserData = {
      username: 't',
      password: 't',
    };
    const response = await user1.post('/login').send(badUserData);
    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/login');
  });

  test('should not login with a bad password', async () => {
    await user1.post('/signup').send(userData);
    const badUserData = {
      username: userData.username,
      password: 'badPassword',
    };
    const response = await user1.post('/login').send(badUserData);
    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/login');
  });

  test('should not login with a bad username', async () => {
    await user1.post('/signup').send(userData);
    const badUserData = {
      username: 'badUsername',
      password: userData.password,
    };
    const response = await user1.post('/login').send(badUserData);
    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/login');
  });

  // logout testing
  test('should redirect upon logout', async () => {
    await user1.post('/signup').send(userData);
    const loginResponse = await user1.post('/login').send(userData);
    expect(loginResponse.status).toBe(302);
    const response = await user1.get('/logout');
    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/');
    const secondResponse = await user1.get('/');
    expect(secondResponse.text).toContain('Login');
    expect(secondResponse.text).toContain('Sign Up');
    expect(secondResponse.text).not.toContain('Logout');
  });

  test('should not logout if not logged in', async () => {
    const response = await user1.get('/logout');
    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/login');
  });

  // redirect testing
  test('should redirect to homepage if logged in', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const homeResponse = await user1.get('/');
    expect(homeResponse.status).toBe(200);
    expect(homeResponse.text).toContain('Logout');
    const response = await user1.get('/login');

    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/');
  });

  test('should redirect to homepage if logged in', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const homeResponse = await user1.get('/');
    expect(homeResponse.status).toBe(200);
    expect(homeResponse.text).toContain('Logout');
    const response = await user1.get('/signup');

    expect(response.status).toBe(302);
    expect(response.header.location).toBe('/');
  });

  // Becoming Member and Admin testing
  test('should become a member with right passcode', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const getMemberResponse = await user1.get('/member');
    expect(getMemberResponse.status).toBe(200);
    expect(getMemberResponse.text).toContain('Become a Member');
    const postMemberResponse = await user1.post('/member').send({
      passcode: process.env.MEMBER_PASSCODE,
    });
    expect(postMemberResponse.status).toBe(302);
    expect(postMemberResponse.header.location).toBe('/');

    const secondMemberResponse = await user1.get('/member');
    expect(secondMemberResponse.status).toBe(200);
    expect(secondMemberResponse.text).toContain(`You're a Member!`);
  });

  test('should not become a member with wrong passcode', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const getMemberResponse = await user1.get('/member');
    expect(getMemberResponse.status).toBe(200);
    expect(getMemberResponse.text).toContain('Become a Member');
    const postMemberResponse = await user1.post('/member').send({
      passcode: 'wrongPasscode',
    });

    expect(postMemberResponse.text).toContain('Incorrect passcode');
  });

  test('should become an admin with right passcode', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const getAdminResponse = await user1.get('/admin');
    expect(getAdminResponse.status).toBe(200);
    expect(getAdminResponse.text).toContain('Become an Admin');
    const postAdminResponse = await user1.post('/admin').send({
      passcode: process.env.ADMIN_PASSCODE,
    });
    expect(postAdminResponse.status).toBe(302);
    expect(postAdminResponse.header.location).toBe('/');

    const secondAdminResponse = await user1.get('/admin');
    expect(secondAdminResponse.status).toBe(200);
    expect(secondAdminResponse.text).toContain(`You're an Admin!`);
  });

  test('should not become an admin with wrong passcode', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const getAdminResponse = await user1.get('/admin');
    expect(getAdminResponse.status).toBe(200);
    expect(getAdminResponse.text).toContain('Become an Admin');
    const postAdminResponse = await user1.post('/admin').send({
      passcode: 'wrongPasscode',
    });
    expect(postAdminResponse.text).toContain('Incorrect passcode');
  });
});
