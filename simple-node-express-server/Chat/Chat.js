var mongoose = require('mongoose');

var messageSchema = new mongoose.Schema({
    sender: String,
    reciever: String,
    message: String,
    tag:  String, 
    iv: String, 
    RSACipher: String
});

mongoose.model('Message', messageSchema);

module.exports = mongoose.model('Message');