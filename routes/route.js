import app from '../app.js';

const router = app.Router();

router.route('/Test10').get((req, res) => {
    res.send('Hello World!');
})