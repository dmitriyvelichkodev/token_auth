'use strict';

let express        = require('express'),
    passport       = require('passport'),
    BearerStrategy = require('passport-http-bearer').Strategy,
    bodyParser     = require('body-parser'),
    morgan         = require('morgan'),
    config         = require('./config'),
    log            = require('./libs/log')(module),
    jwt            = require('jsonwebtoken');


let records = [
    { id: 1, name: 'jack', password: 'asdfasdf', email: 'jack@example.com', token: '123456789' },
    { id: 2, name: 'jill', password: '123123', email: 'jill@example.com', token: 'abcdefghi' }
];


passport.use(new BearerStrategy(
  function(token, cb) {
    findByToken(token, function(err, user) {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false); }
      return cb(null, user);
    });
	}
));

function findByToken(token, cb) {
	// TODO decript token and check expiraion time
	for(let i=0; i<records.length; i++) {
		if (records[i].token === token) {
			console.log(records[i]);
			return cb(null, records[i]);
		}
	}
	return cb(null, false);
}
function isAlreadyRegistered(user) {
	for(let i=0; i<records.length; i++) {
		if (records[i].email === user.email) {
			return true;
		}
	}
	return false;
}
function validateCredentials(user) {
	for(let i=0; i<records.length; i++) {
		if (records[i].email === user.email) {
			if (records[i].password === user.password) {
				let token = refreshToken(records[i].token);
				return {value: true, token: token};
			}
			else return {value: false};
		}
	}
	return {value: false};
}

function genToken(user, expirationTime) {
	return jwt.sign({email: user.email, name: user.name}, app.get('key'), {
	          expiresIn: 1440*60 
	        });
}
function refreshToken(token) {
	// TODO parse token check time and return fresh
	return token
}


let app = express();

// configuration 
var port = process.env.PORT || 8080; 
// TODO mongoose.connect(config.database); 
app.set('key', config.key);
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(passport.initialize());


app.post('/api/register',
	function(req, res) {
		let user = req.body;
		if (!(user.email && user.password)) {
			log.debug(`Didn't specify user email or password: ${req.url}`);
    		res.status(400).json({
	    		success: false,
	        	message: "Didn't specify user email or password"
	    	});
    		return;
		}
		if (isAlreadyRegistered(user)) {
			log.debug(`User has already registered: ${user.name}`);
			res.status(400).json({
				sucess: false,
				message: "User has already registered"
			});
			return;
		}

		let token = genToken(user, 4*60*60);

		// TODO save to bd
		records.push({ 
			id: records.length,
			name: user.name, 
			token: token, 
			email: user.email,
			password: user.password });

	    res.status(201).json({
	    	success: true,
	        token: token
	    });
    });

app.post('/api/login',
  	function(req, res) {
  		let user = req.body;
		if (!(user.email && user.password)) {
			log.debug(`Didn't specify user email or password: ${req.url}`);
			res.statusMessage = "Didn't specify user email or password";
    		res.status(400).end();
    		return;
		}	

		let result = validateCredentials(user);

		if (!result.value) {
			res.statusMessage = "Uncorrect password or email";
			res.status(400).end();
			return;
		}

    	res.status(200).json({
        	token: result.token
    	});
  });


app.get('/api/profile',
  passport.authenticate('bearer', { session: false }),
  function(req, res) {
    res.json({ 
    	email: req.user.email,
    	name: req.user.name
    });
  });


// other error handlers
app.use(function(req, res, next){
    res.status(404);
    log.debug(`Not found URL: ${req.url}`);
    res.send({error: 'Not found'});
    return;
});

app.use(function(err, req, res, next){
    res.status(err.status || 500);
    log.error(`Internal error(${res.statusCode}): ${err.message}`);
    res.send({ error: err.message });
    return;
});



app.listen(port, function(){
    log.info(`Express server listening on port ${port}`);
});

module.exports = app;
