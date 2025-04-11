import express from 'express';

const router = express.Router();

router.get('/mbkauthe/', (req, res) => {
    res.send('Welcome to the main page!');
});

export default router;