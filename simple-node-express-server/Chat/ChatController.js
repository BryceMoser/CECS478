var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({extended : true}));
router.use(bodyParser.json());
var Chat = require('./Chat.js');
var VerifyToken = require('../Authorization/VerifyToken');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');

router.post('/', VerifyToken, function(req, res, next) {
    Chat.create({
        email: req.body.email,
        message: req.body.message
    },
    function(err){
        if(err) res.status(500).send("Error sending the message");
    });
    res.status(200).send({message: req.body.message});
});

router.get('/', VerifyToken, function(req, res) {
    Chat.find({email: req.headers['email']},
        (err, messages) => {
        if(err) return res.status(500).send("Could not locate any messages");
        console.log(messages);
        res.status(200).send(messages);
        Chat.find({email: req.headers['email']}).remove().exec();
    });
    
});

console.log("ChatController Ready");


module.exports = router;