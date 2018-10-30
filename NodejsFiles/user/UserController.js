var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');

router.use(bodyParser.urlencoded({ extended: true}));
router.use(bodyParser.json());

var User = require('./User');

router.post('/', function (req, res) {
    console.log('req body: ', req.body);
    User.create({
        email: req.body.email,
        password: req.body.password
    },
    (err, user) => {
        if(err) return res.status(500).send("There was a problem adding the information to the database.");
        res.status(200).send(user);
    });
});

router.get('/', (req, res) => {
    User.find({},
        (err, users) => {
        if(err) return res.status(500).send("Could not locate user specified");
        res.status(200).send(users);
    });
});

module.exports = router;