var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');

const User = require('../models/User');

const { requireAnon, requireUser, requiredFields } = require('../middlewares/auth');

const saltRounds = 10;

/* GET home page. */
router.get('/signup', requireAnon, (req, res, next) => {
  const data = {
    messages: req.flash('validation')
  };
  res.render('auth/signup', data);
});

router.post('/signup', requireAnon, requiredFields, async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const result = await User.findOne({ username });
    if (result) {
      req.flash('validation', 'This username is token');
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

router.get('/login', requireAnon, (req, res, next) => {
  const data = {
    messages: req.flash('validation')
  };
  res.render('auth/login', data);
});

router.post('/login', requireAnon, requiredFields, async (req, res, next) => {
  // extraer información del body
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      req.flash('validation', 'Username or Password incorrect');
      res.redirect('/auth/login');
      return;
    }

    if (bcrypt.compareSync(password, user.password)) {
      // Save the login in the session!
      req.session.currentUser = user;
      res.redirect('/');
    } else {
      req.flash('validation', 'Username or Password incorrect');
      res.redirect('/auth/login');
    }
  } catch (error) {
    next(error);
  }
});

router.post('/logout', requireUser, (req, res, next) => {
  delete req.session.currentUser;
  res.redirect('/');
});

module.exports = router;
