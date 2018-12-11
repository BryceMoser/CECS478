var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({extended : true}));
router.use(bodyParser.json());
var Chat = require('./Chat.js');
var VerifyToken = require('../Authorization/VerifyToken');
var User = require('../user/User');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');
let Token = require('../Authorization/Token');


router.post('/', VerifyToken, function(req, res, next) {

    Token.findOne({token: req.headers['x-access-token']}, (err, user) => {
        if(!req.body.message) res.status(400).send("No message input detected");
        if(!req.body.reciever) res.status(400).send("No reciever input detected");

        let sender = user.email;

        Chat.create({
            reciever: req.body.reciever,
            sender: sender,
            message: req.body.message,
            tag: req.body.tag,
            iv: req.body.iv,
            RSACipher: req.body.RSACipher
        },
        function(err){
            if(err) res.status(500).send("Error sending the message");
        });
        res.status(200).send(sender + ": " + req.body.message);
    });
});

router.get('/', VerifyToken, function(req, res) {

    Token.findOne({token: req.headers['x-access-token']}, (err , user) => {
        if(err) res.status(500).send("Internal server error");

        let reciever = user.email;
        
        Chat.find({reciever: reciever}, (err, messages) => {
            if(err) res.status(500).send("Internal server error");
            res.status(200).send(messages);
        });
        Chat.find({reciever: reciever}).remove().exec();
        
    });   
});

module.exports = router;