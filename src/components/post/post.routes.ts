import express from 'express';
import { getNewPost, postNewPost, postDeletePost } from './post.controller';

const router = express.Router();

router.get('/new-post', getNewPost);
router.post('/new-post', postNewPost);
router.post('/delete-post/:id', postDeletePost);

export default router;
