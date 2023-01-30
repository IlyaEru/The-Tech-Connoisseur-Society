import express from 'express';
import Post from './post.model';

import { body, validationResult } from 'express-validator';

const getNewPost = (req: express.Request, res: express.Response) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  res.render('new-post', { pageTitle: 'New Post' });
};

const postNewPost = [
  body('title')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Title must be between 3 and 50 characters'),
  body('content')
    .trim()
    .isLength({ min: 3, max: 255 })
    .withMessage('Content must be between 3 and 255 characters'),
  async (req: express.Request, res: express.Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.render('new-post', {
        pageTitle: 'New Post',
        errors: errors.array(),
      });
    } else {
      if (!req.isAuthenticated()) {
        return res.redirect('/login');
      }
      const post = new Post({
        title: req.body.title,
        content: req.body.content,
        user: req.user._id,
      });
      await post.save();
      res.redirect('/');
    }
  },
];

const postDeletePost = async (req: express.Request, res: express.Response) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  if (!res.locals.isUserAdmin) {
    return res.redirect('/admin');
  }
  const post = await Post.findById(req.params.id);
  if (!post) {
    return res.redirect('/');
  }
  await Post.findByIdAndDelete(req.params.id);
  res.redirect('/');
};

export { getNewPost, postNewPost, postDeletePost };
