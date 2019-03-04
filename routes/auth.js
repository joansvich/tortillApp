var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');

const User = require('../models/User');

const saltRounds = 10;

/* GET home page. */
router.get('/signup', (req, res, next) => {
  if (req.session.currentUser) {
    res.redirect('/');
    return;
  }
  res.render('auth/signup');
});

router.post('/signup', async (req, res, next) => {
  const { username, password } = req.body;
  if (!password || !username) {
    res.redirect('/auth/signup');
    return;
  }
  try {
    const result = await User.findOne({ username });
    if (result) {
      res.redirect('/auth/signup');
      return;
    }

    // Encriptamos password
    const salt = bcrypt.genSaltSync(saltRounds);
    const hashedPassword = bcrypt.hashSync(password, salt);

    // Creamos el usuario
    const newUser = {
      username,
      password: hashedPassword
    };

    const createdUser = await User.create(newUser);
    // Guardamos el usuario en la sesión
    req.session.currentUser = createdUser;

    res.redirect('/');
  } catch (error) {
    next(error);
  }
});

router.get('/login', (req, res, next) => {
  if (req.session.currentUser) {
    res.redirect('/');
    return;
  }
  res.render('auth/login');
});

router.post('/login', async (req, res, next) => {
  if (req.session.currentUser) {
    res.redirect('/');
    return;
  }
  // extraer información del body
  const { username, password } = req.body;
  if (!password || !username) {
    res.redirect('/auth/login');
    return;
  }
  try {
    const user = await User.findOne({ username });
    if (!user) {
      res.redirect('/auth/login');
      return;
    }

    if (bcrypt.compareSync(password, user.password)) {
      // Save the login in the session!
      req.session.currentUser = user;
      res.redirect('/');
    } else {
      res.redirect('/auth/login');
    }
  } catch (error) {
    next(error);
  }
});

router.post('/logout', (req, res, next) => {
  if (!req.session.currentUser) {
    res.redirect('/');
    return;
  }
  delete req.session.currentUser;
  res.redirect('/');
});

module.exports = router;
