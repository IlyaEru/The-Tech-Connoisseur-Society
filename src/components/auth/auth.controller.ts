import express from 'express';
import bcrypt from 'bcryptjs';
import passport from 'passport';

import { body, validationResult } from 'express-validator';
import User from '../user/user.model';

const getSignup = (req: express.Request, res: express.Response) => {
  if (res.locals.isLoggedIn) {
    return res.redirect('/');
  }
  res.render('signup', { pageTitle: 'Sign up' });
};

const postSignup = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be between 3 and 50 characters'),
  body('password')
    .trim()
    .isLength({ min: 6, max: 255 })
    .withMessage('Password must be between 6 and 255 characters'),
  body('passwordConfirmation').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Password confirmation does not match password');
    }
    return true;
  }),
  async (req: express.Request, res: express.Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.render('signup', {
        pageTitle: 'Sign up',
        errors: errors.array(),
      });
    } else {
      const user = await User.findOne({ username: req.body.username });
      if (user) {
        res.render('signup', {
          pageTitle: 'Sign up',
          errors: [{ msg: 'Username already exists' }],
        });
      } else {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
          username: req.body.username,
          password: hashedPassword,
        });
        await user.save();
        res.redirect('/');
      }
    }
  },
];

const getLogin = (req: express.Request, res: express.Response) => {
  if (res.locals.isLoggedIn) {
    return res.redirect('/');
  }
  res.render('login', { pageTitle: 'Login' });
};

const postLogin = passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true,
});

const getLogout = (req: express.Request, res: express.Response) => {
  if (!res.locals.isLoggedIn) {
    return res.redirect('/login');
  }
  req.logout((done) => {
    return;
  });
  res.redirect('/');
};

export { getSignup, postSignup, getLogin, postLogin, getLogout };
