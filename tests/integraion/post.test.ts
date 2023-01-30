import request from 'supertest';
import app from '../../src/app';
import User from '../../src/components/user/user.model';
import dotenv from 'dotenv';
import { setUpTestDb } from '../utils/setupTestDb';
import Post from '../../src/components/post/post.model';

dotenv.config();

const user1 = request.agent(app);

setUpTestDb();

const userData = {
  username: 'test',
  password: 'testPassword',
  passwordConfirmation: 'testPassword',
};

const postData = {
  title: 'test',
  content: 'testBody',
};

describe('Post ', () => {
  // Creating New Post testing

  test('should create a new post', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const newPostResponse = await user1.get('/new-post');
    expect(newPostResponse.status).toBe(200);
    expect(newPostResponse.text).toContain('Create a New Post');
    const postNewPostResponse = await user1.post('/new-post').send({
      title: 'testTitle',
      content: 'testContent',
    });

    expect(postNewPostResponse.status).toBe(302);
    expect(postNewPostResponse.header.location).toBe('/');
  });

  test('should not create a new post if not logged in', async () => {
    const newPostResponse = await user1.get('/new-post');
    expect(newPostResponse.status).toBe(302);
    expect(newPostResponse.header.location).toBe('/login');
  });

  test('should not create a new post with bad title', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const newPostResponse = await user1.get('/new-post');
    expect(newPostResponse.status).toBe(200);
    expect(newPostResponse.text).toContain('Create a New Post');
    const postNewPostResponse = await user1.post('/new-post').send({
      title: '',
      content: 'testContent',
    });

    expect(postNewPostResponse.status).toBe(200);
    expect(postNewPostResponse.text).toContain(
      'Title must be between 3 and 50 characters',
    );
  });

  test('should not create a new post with bad content', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const newPostResponse = await user1.get('/new-post');
    expect(newPostResponse.status).toBe(200);
    expect(newPostResponse.text).toContain('Create a New Post');
    const postNewPostResponse = await user1.post('/new-post').send({
      title: 'testTitle',
      content: '',
    });

    expect(postNewPostResponse.status).toBe(200);
    expect(postNewPostResponse.text).toContain(
      'Content must be between 3 and 255 characters',
    );
  });

  // Seeing Posts Testing

  test('should see No posts yet', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    const response = await user1.get('/');
    expect(response.status).toBe(200);
    expect(response.text).toContain('No posts yet');
  });

  test('should see posts', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    await user1.post('/new-post').send(postData);
    const response = await user1.get('/');
    expect(response.status).toBe(200);
    expect(response.text).toContain('test');
    expect(response.text).toContain('testBody');
  });

  test('should not see posts author and creation time if not member', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    await user1.post('/new-post').send(postData);
    const response = await user1.get('/');
    expect(response.status).toBe(200);
    expect(response.text).toContain('Post by Member on N/A');
    expect(response.text).not.toContain('Post by test on');
  });

  test('should see posts author and creation time if member', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    await user1.post('/new-post').send(postData);
    const user2 = request.agent(app);
    await user2.post('/signup').send({
      username: 'test2',
      password: 'testPassword',
      passwordConfirmation: 'testPassword',
    });
    await user2.post('/login').send({
      username: 'test2',
      password: 'testPassword',
    });
    const notMemberResponse = await user2.get('/');
    expect(notMemberResponse.status).toBe(200);
    expect(notMemberResponse.text).toContain('Post by Member on N/A');
    await user2.post('/member').send({
      passcode: process.env.MEMBER_PASSCODE,
    });
    const memberResponse = await user2.get('/');
    expect(memberResponse.status).toBe(200);
    expect(memberResponse.text).toContain('Post by test on');
  });

  //   Deleting Posts Testing

  test('should delete post', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    await user1.post('/new-post').send(postData);
    await user1.post('/admin').send({
      passcode: process.env.ADMIN_PASSCODE,
    });
    const response = await user1.get('/');
    expect(response.status).toBe(200);
    expect(response.text).toContain('test');
    expect(response.text).toContain('Delete Post');

    const postId = await Post.findOne({ title: 'test' });

    const deleteResponse = await user1.post(`/delete-post/${postId?._id}`);
    expect(deleteResponse.status).toBe(302);
    expect(deleteResponse.header.location).toBe('/');

    const afterDeleteResponse = await user1.get('/');
    expect(afterDeleteResponse.status).toBe(200);
    expect(afterDeleteResponse.text).toContain('No posts yet');
  });

  test('should not see delete button if not admin', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    await user1.post('/new-post').send(postData);
    const response = await user1.get('/');
    expect(response.status).toBe(200);
    expect(response.text).toContain('test');
    expect(response.text).not.toContain('Delete Post');
  });

  test('should not delete post if not admin', async () => {
    await user1.post('/signup').send(userData);
    await user1.post('/login').send(userData);
    await user1.post('/new-post').send(postData);
    const postId = await Post.findOne({ title: 'test' });
    const deleteResponse = await user1.post(`/delete-post/${postId?._id}`);
    expect(deleteResponse.status).toBe(302);
    expect(deleteResponse.header.location).toBe('/admin');

    const afterDeleteResponse = await user1.get('/');
    expect(afterDeleteResponse.status).toBe(200);
    expect(afterDeleteResponse.text).toContain('test');
  });
});
