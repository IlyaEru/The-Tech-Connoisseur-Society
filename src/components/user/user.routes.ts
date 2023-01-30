import express from 'express';

import { getMember, postMember, getAdmin, postAdmin } from './user.controller';

const router = express.Router();

router.get('/member', getMember);
router.post('/member', postMember);

router.get('/admin', getAdmin);
router.post('/admin', postAdmin);

export default router;
