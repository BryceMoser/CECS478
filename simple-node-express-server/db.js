//var MongoClient = require('mongodb').MongoClient;
var mongoose = require('mongoose');
var url = "mongodb://C:Supersecure478@e2eproj-shard-00-00-re4xl.mongodb.net:27017,e2eproj-shard-00-01-re4xl.mongodb.net:27017,e2eproj-shard-00-02-re4xl.mongodb.net:27017/test?ssl=true&replicaSet=E2eproj-shard-0&authSource=admin&retryWrites=true";
console.log("\nAttempting db connection\n");

var options = {
    useNewUrlParser: true,
    poolSize: 10,
    reconnectTries: Number.MAX_VALUE
};

mongoose.connect(url, {dbName: 'E2eChat'}).then(
    function res() {
        console.log('Successfully connected!');
    }, function err() {
        console.log("An error has occured connecting to db");
    }
);

// MongoClient.connect(url, function(err, client) {
//     const collection = client.db("E2eChat").collection("users");
//     client.close();
// });
