let mongoose = require('mongoose');

var tokenSchema = new mongoose.Schema ({
    email: String,
    token: String
});

mongoose.model('Token', tokenSchema);

module.exports = mongoose.model('Token');