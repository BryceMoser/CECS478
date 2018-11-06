var mongoose = require('mongoose');

var messageSchema = new mongoose.Schema({
    email: String,
    message: String
});

mongoose.model('Message', messageSchema);

module.exports = mongoose.model('Message');