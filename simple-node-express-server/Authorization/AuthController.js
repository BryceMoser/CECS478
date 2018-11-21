var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({extended : true}));
router.use(bodyParser.json());
var User = require('../user/User');
var VerifyToken = require('./VerifyToken');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');

router.post('/', function(req, res){
    var hashPass = bcrypt.hashSync(req.body.password, 8);

    User.create({
        email: req.body.email,
        password: hashPass
    },
    function(err, user){
        if (err) return res.status(500).send("Error registering user.")

        // jwt creation
        var token = jwt.sign({id: user._id}, config.secret, {
            expiresIn: 86400
        });

        res.status(200).send({auth: true, token: token});
    });
});

router.get('/me', VerifyToken, function(req, res, next) {
    User.findById(req.userId, { password: 0 }, function (err, user) {
      if (err) return res.status(500).send("There was a problem finding the user.");
      if (!user) return res.status(404).send("No user found.");
      
      res.status(200).send(user);
    });
  });

  //Login request
  router.post('/login', function(req, res) {
    User.findOne({ email: req.body.email }, function (err, user) {
      if (err) return res.status(500).send('Error on the server.');
      if (!user) return res.status(404).send('No user found.');
      var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
      if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
      var token = jwt.sign({ id: user._id }, config.secret, {
        expiresIn: 86400 // expires in 24 hours
      });
      res.status(200).send({ auth: true, token: token });
    });
  });


  router.get('/logout', function(req, res) {
    res.status(200).send({ auth: false, token: null });
  });

  console.log("AuthController Ready");

module.exports = router;