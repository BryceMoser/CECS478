var mongoose = require('mongoose');

var UserSchema = new mongoose.Schema({
    email: String,
    password: String
}, {collection: 'E2eChat'});

mongoose.model('User', UserSchema, 'E2eChat');

module.exports = mongoose.model('User');