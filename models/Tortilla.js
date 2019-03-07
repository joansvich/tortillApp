'use strict';

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ObjectId = Schema.Types.ObjectId;

const tortillaSchema = new Schema({
  special: {
    type: String
  },
  size: {
    type: String,
    enum: ['small', 'medium', 'big']
  },
  creator: {
    type: ObjectId,
    ref: 'User'
  },
  name: {
    type: String,
    required: true
  },
  location: {
    type: {
      type: String,
      default: 'Point'
    },
    coordinates: [Number]
  },
  imageUrl: {
    type: String
  }
});

tortillaSchema.index({ location: '2dsphere' });

const Tortilla = mongoose.model('Tortilla', tortillaSchema);

module.exports = Tortilla;
