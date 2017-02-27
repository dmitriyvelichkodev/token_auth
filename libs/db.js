'use strict';

let mongoose = require('mongoose'),
    config   = require('../config'),
	log      = require('./log')(module);

mongoose.connect(config.database);

let db = mongoose.connection;

db.on('error', function (err) {
    log.error('Connection error:', err.message);
});
db.once('open', function callback () {
    log.info("Connected to database");
});

let Schema = mongoose.Schema,
	User = new Schema({
		name:     { type: String, required: true  },
		password: { type: String, required: true  },
		salt:     { type: String, required: true  },
		email:    { type: String, required: true  },
		token:    { type: String, required: false }
	});

// validation
User.path('name'    ).validate(function (d) {
    return d.length > 0 && d.length < 85;
});
User.path('password').validate(function (d) {
    return d.length > 0 && d.length < 85;
});
User.path('email'   ).validate(function (d) {
    return d.length > 0 && d.length < 85;
});
User.path('token'   ).validate(function (d) {
    return d.length > 1;
});


let UserModel = mongoose.model('User', User);

module.exports.User = UserModel;
