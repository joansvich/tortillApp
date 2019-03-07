const express = require('express');
const router = express.Router();

const Tortilla = require('../models/Tortilla');

const { requireUser } = require('../middlewares/auth');

const parser = require('../helpers/file-upload');

/* GET home page. */

router.get('/tortillas/:id', requireUser, parser.single('image'), async (req, res, next) => {
  const { id } = req.params;
  const { _id } = req.session.currentUser;
  try {
    const tortilla = await Tortilla.findById(id).populate('creator');
    let isCreator = false;
    if (tortilla.creator.equals(_id)) {
      isCreator = true;
    }
    res.render('tortillas/detail', { tortilla, isCreator });
  } catch (error) {
    next(error);
  }
});

router.get('/', async (req, res, next) => {
  try {
    const tortillas = await Tortilla.find();
    console.log(tortillas);
    res.render('tortillas/list', { tortillas });
  } catch (error) {
    next(error);
  }
});

router.get('/new', requireUser, (req, res, next) => {
  console.log(req);
  res.render('tortillas/create-edit');
});

router.get('/tortillas/:id/edit', requireUser, async (req, res, next) => {
  const { id } = req.params;
  const { _id } = req.session.currentUser;
  try {
    const tortilla = await Tortilla.findById(id);
    if (!tortilla.creator.equals(_id)) {
      res.redirect('/');
      return;
    }
    res.render('tortillas/create-edit', tortilla);
  } catch (error) {
    next(error);
  }
});

router.post('/tortillas/:id/delete', requireUser, async (req, res, next) => {
  const { id } = req.params;
  const { _id } = req.session.currentUser;
  try {
    const tortilla = await Tortilla.findById(id);
    if (tortilla.creator.equals(_id)) {
      await Tortilla.findByIdAndDelete(id);
    }
    res.redirect('/');
  } catch (error) {
    next(error);
  }
});

router.post('/', requireUser, parser.single('image'), async (req, res, next) => {
  const { _id, name, special, size, longitude, latitude } = req.body;
  const tortilla = {
    name,
    special,
    size,
    location: {
      type: 'Point',
      coordinates: [longitude, latitude]
    },
    imageUrl: req.file.url
  };
  try {
    if (_id) {
      await Tortilla.findByIdAndUpdate(_id, tortilla);
    } else {
      tortilla.creator = req.session.currentUser._id;
      await Tortilla.create(tortilla);
    }
    res.redirect('/');
  } catch (error) {
    next(error);
  }
});

router.post('/tortillas/:id/delete', requireUser, async (req, res, next) => {
  const { id } = req.params;
  const { _id } = req.session.currentUser;
  try {
    const tortilla = await Tortilla.findById(id);
    if (tortilla.creator.equals(_id)) {
      await Tortilla.findByIdAndDelete(id);
    }
    res.redirect('/');
  } catch (error) {
    next(error);
  }
});

module.exports = router;
