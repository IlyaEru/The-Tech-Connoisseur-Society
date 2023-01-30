import User from './src/components/user/user.model';
import Post from './src/components/post/post.model';
import bcrypt from 'bcryptjs';
import {
  setUpDb as setUpTestDB,
  dropDb,
  dropCollections,
} from './src/config/test-db';
import setUpDB from './src/config/db';

import { faker } from '@faker-js/faker';
import { Types } from 'mongoose';

const postsData = [
  {
    title: 'The Future of AI',
    content:
      'Artificial intelligence is revolutionizing the way we live and work. Stay ahead of the game with TTS.',
  },
  {
    title: '5G Technology Explained',
    content:
      'Get a handle on the basics of 5G technology and its potential to change the world with TTS.',
  },
  {
    title: 'Virtual Reality: The Next Frontier',
    content:
      'Virtual reality is no longer a thing of the future. Join TTS to explore the exciting possibilities.',
  },
  {
    title: 'The Rise of Blockchain',
    content:
      'From finance to gaming, blockchain is changing the world. Learn all about it with TTS.',
  },
  {
    title: 'AI Ethics: A Critical Discussion',
    content:
      'As AI technology advances, so do ethical concerns. Join TTS for a thought-provoking discussion.',
  },
  {
    title: 'The Internet of Things (IoT)',
    content:
      'The Internet of Things is connecting our world in new and exciting ways. Discover more with TTS.',
  },
  {
    title: 'Cybersecurity in the Digital Age',
    content:
      'Stay ahead of cyber threats with TTS, your guide to cybersecurity in the digital age.',
  },
  {
    title: 'The Future of Work: Automation and AI',
    content:
      'Automation and AI are changing the way we work. Stay informed with TTS.',
  },
  {
    title: 'Augmented Reality: Beyond Gaming',
    content:
      'Augmented Reality has applications far beyond gaming. Explore the possibilities with TTS.',
  },
  {
    title: 'Quantum Computing: The Next Revolution',
    content:
      'Quantum computing is the future of computing. Learn all about it with TTS.',
  },
];

const createRandomUser = async () => {
  const password = bcrypt.hashSync('password', 10);
  const user = new User({
    username: faker.name.firstName(),
    password: password,
    passwordConfirmation: password,
  });
  await user.save();
  return user;
};

const createPost = async (
  userId: Types.ObjectId,
  title: string,
  content: string,
) => {
  const post = new Post({
    title,
    content,
    user: userId,
  });
  await post.save();
  return post;
};
const populateDB = async () => {
  // await setUpTestDB(); // for testing
  await setUpDB(); // for development

  const users: any[] = [];
  const posts: any[] = [];
  for (let i = 0; i < 10; i++) {
    users.push(await createRandomUser());
  }
  console.log({ users });

  for (let i = 0; i < 10; i++) {
    posts.push(
      await createPost(users[i]._id, postsData[i].title, postsData[i].content),
    );
  }
  console.log(posts);
};
populateDB();
