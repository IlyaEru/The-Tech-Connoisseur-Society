import express from 'express';

import homeRoutes from '../components/home';
import authRoutes from '../components/auth';
import userRoutes from '../components/user';
import postRoutes from '../components/post';

const router = express.Router();

router.use('/', homeRoutes);
router.use('/', authRoutes);
router.use('/', userRoutes);
router.use('/', postRoutes);

export default router;
