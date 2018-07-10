'use strict';

const express = require('express');
const router = express.Router();

const User = require('../models/users');

// Bcrypt to encrypt passwords
const bcrypt = require('bcrypt');
const bcryptSalt = 10;

router.get('/signup', (req, res, next) => {
  if (req.session.currentUser) {
    res.redirect('/');
    return;
  }
  const data = {
    messages: req.flash('signin-error')
  };
  res.render('auth/signup', data); // without /auth!!
});

router.post('/signup', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (req.session.currentUser) {
    res.redirect('/'); // Never render !! (would be like starting from scratch) --> when refreshing the page, does not send the form
    return;
  }

  if (!username || !password) {
    req.flash('signin-error', 'Please provide a username and a password');
    res.redirect('/auth/signup');
    return;
  }

  User.findOne({ username })
    .then(user => {
      if (user !== null) { // Checks if username is unique
        req.flash('signin-error', 'The username is already taken');
        res.redirect('/auth/signup');
        return;
      }

      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      const newUser = new User({
        username,
        password: hashPass
      });

      return newUser.save() // Should always go inside findOne, otherwise runs at the same time and findOne does not have time to finish
        .then(() => {
          req.session.currentUser = newUser;
          res.redirect('/');
          // return another promise
          //    .then()
          //    the error goes up and up until the catch
        });
      // .catch(next); --> delete this and add return to newUser.save()

      // newUser.save((err, result) => { ---> same as before but in callback function, no promise
      //   if (err) {
      //     res.redirect('/auth/signup');
      //   } else {
      //     req.session.currentUser = newUser;
      //     res.redirect('/');
      //   }
      // });
    })
    .catch(next);

  // .catch(err => { --> same as before
  //   next(err)
  // })
});

router.get('/login', (req, res, next) => {
  if (req.session.currentUser) {
    res.redirect('/');
    return;
  }
  const data = {
    messages: req.flash('login-error')
  };
  res.render('auth/login', data);
});

router.post('/login', (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (req.session.currentUser) {
    res.redirect('/');
    return;
  }

  if (!username || !password) {
    req.flash('login-error', 'Please provide a username and a password');
    res.redirect('/auth/login');
    return;
  }

  User.findOne({ username })
    .then(user => {
      if (!user) {
        req.flash('login-error', 'Username or password are incorrect');
        res.redirect('/auth/login');
        return;
      }

      if (!bcrypt.compareSync(password, user.password)) {
        req.flash('login-error', 'Username or password are incorrect');
        res.redirect('/auth/login');
        return;
      }

      req.session.currentUser = user;
      res.redirect('/');
    })
    .catch(next); // next without (), otherwise it calls next() always !!!!!!!!!
});

// LOG OUT
router.get('/logout', (req, res, next) => {
  delete req.session.currentUser; // IMPORTANT TO KNOW HOW TO DELETE!
  res.redirect('/auth/login');
});

module.exports = router;
