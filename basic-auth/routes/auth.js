'use strict';

const express = require('express');
const router = express.Router();

router.get('/signup', (req, res, next) => {
  res.render('auth/signup'); // without /auth!!
});

module.exports = router;