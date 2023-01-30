import express from 'express';
import Post from '../post/post.model';

const getHomePage = async (req: express.Request, res: express.Response) => {
  const posts = await Post.find().populate('user');
  res.render('index', {
    pageTitle: 'The Tech Connoisseur Society',
    posts,
  });
};

export { getHomePage };
