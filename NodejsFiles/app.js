var express = require('express');
var app = express();
var db = require('./db');
var AuthController = require('./Authorization/AuthController');
var ChatController = require('./Chat/ChatController');


var UserController = require('./user/UserController');

var port = process.env.PORT || 3000;


var server = app.listen(port, function(){
    console.log("Server started on port 3000");
    app.use('/registration', AuthController);
    app.use('/message', ChatController);
});

module.exports = app;
