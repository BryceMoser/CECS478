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

router.post('/', VerifyToken, function(req, res, next) {
    Chat.create({
        reciever: req.body.reciever,
        message: req.body.message
    },
    function(err){
        if(err) res.status(500).send("Error sending the message");
    });
    res.status(200).send({message: req.body.message});
});

router.get('/', VerifyToken, function(req, res) {
    let password = req.headers['password'];
    let reciever = req.headers['reciever'];

    User.findOne({email: reciever}, (err, user) => {
        if(!user) return res.status(404).send('Invaid User.');
        var passwordIsValid = bcrypt.compareSync(password, user.password);
        if(!passwordIsValid) return res.status(404).send('Invaid password.');
        
        Chat.find({reciever: reciever},
        (err, messages) => {
            if(!messages) return res.status(500).send("Could not locate any messages");
            res.status(200).send(messages);
            Chat.find({email: reciever}).remove().exec();
        });
    });    
});

console.log("ChatController Ready");


module.exports = router;