var express = require('express');
var app = express();
var db = require('./db');
var reload = require('reload');
var AuthController = require('./Authorization/AuthController');
var ChatController = require('./Chat/ChatController');
var UserController = require('./user/UserController');


var port = 3000;

app.get('/', function(req, res){
    res.send("Super Secure Bro");
    app.use('/registration', AuthController);
    app.use('/message', ChatController);
    console.log("Server running");
});

app.listen(port);

reload(app);
