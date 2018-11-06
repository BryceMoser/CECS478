var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({extended : true}));
router.use(bodyParser.json());
var Chat = require('./Chat.js');
var VerifyToken = require('./VerifyToken');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');

router.post('message', VerifyToken, function(req, res, next) {
    if (err) return res.status(500).send('Error on the server.');
    Chat.create({
        email: req.body.email,
        message: req.body.message
    },
    function(err, user){
        if(!err) res.status(500).send("Error sending the message");
    });
    res.status(200).send({message: req.body.message});
});

module.exports = router;