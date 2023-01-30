import express from 'express';
import User from './user.model';
import dotenv from 'dotenv';

import { body, validationResult } from 'express-validator';

dotenv.config();

const getMember = (req: express.Request, res: express.Response) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  res.render('member', { pageTitle: 'Become a Member' });
};

const postMember = [
  body('passcode')
    .trim()
    .exists()
    .withMessage('Passcode is required')
    .custom((value, { req }) => {
      if (
        value.trim().toLowerCase() !==
        process.env.MEMBER_PASSCODE?.toLowerCase()
      ) {
        throw new Error('Incorrect passcode');
      }
      return true;
    }),
  async (req: express.Request, res: express.Response) => {
    if (!req.isAuthenticated()) {
      return res.redirect('/login');
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.render('member', {
        pageTitle: 'Become a Member',

        errors: errors.array(),
      });
    } else {
      await User.findByIdAndUpdate(req.user._id, { member: true });
      res.redirect('/');
    }
  },
];

const getAdmin = (req: express.Request, res: express.Response) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  res.render('admin', { pageTitle: 'Become an Admin' });
};

const postAdmin = [
  body('passcode')
    .trim()
    .exists()
    .withMessage('Passcode is required')
    .custom((value, { req }) => {
      if (
        value.trim().toLowerCase() !== process.env.ADMIN_PASSCODE?.toLowerCase()
      ) {
        throw new Error('Incorrect passcode');
      } else {
        return true;
      }
    }),
  async (req: express.Request, res: express.Response) => {
    if (!req.isAuthenticated()) {
      return res.redirect('/login');
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.render('admin', {
        pageTitle: 'Become an Admin',

        errors: errors.array(),
      });
    } else {
      await User.findByIdAndUpdate(req.user._id, { admin: true });
      res.redirect('/');
    }
  },
];

export { getMember, postMember, getAdmin, postAdmin };
