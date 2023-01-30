import express from 'express';

import {
  getSignup,
  postSignup,
  getLogin,
  postLogin,
  getLogout,
} from './auth.controller';

const router = express.Router();

router.get('/signup', getSignup);

router.post('/signup', postSignup);

router.get('/login', getLogin);

router.post('/login', postLogin);

router.get('/logout', getLogout);

export default router;
