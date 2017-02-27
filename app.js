'use strict';

// TODO clearer config
// TODO db migration
// TODO maybe create additional identity server for Oauth2

let express        = require('express'),
    passport       = require('passport'),
    BearerStrategy = require('passport-http-bearer').Strategy,
    bodyParser     = require('body-parser'),
    User           = require('./libs/db').User,
    crypto         = require('crypto'),
    morgan         = require('morgan'),
    config         = require('./config'),
    log            = require('./libs/log')(module),
    jwt            = require('jsonwebtoken');


function ServerReject(status, message) {
  this.status = status || 500;
  this.message = message || 'Internal Error';
  this.stack = (new Error()).stack;
}
ServerReject.prototype = Object.create(Error.prototype);
ServerReject.prototype.constructor = ServerReject;



passport.use(new BearerStrategy(
  function(token, cb) {
    findByToken(token, function(err, user) {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false); }
      return cb(null, user);
    });
    }
));



///PROMISE
function requestUser(reqUser) {
    return new Promise(function(resolve, reject) {
        if (!reqUser) 
            throw new ServerReject(400, "No user info specified");
        if (!reqUser.email) 
            throw new ServerReject(400, `Didn't specify user email`);
        if (!reqUser.password) 
            throw new ServerReject(400, `Didn't specify user password`); 

        User.findOne({"email": reqUser.email},
            function(err, resUser) {
                if(err) {
                    console.debug(err);
                    reject(err);
                }
                resolve({
                    reqUser: reqUser,
                    resUser: resUser
                });
            });
        });
}
function insertUser(user) {
    return new Promise(function(resolve, reject) {
        let tmp = new User(user);
        tmp.save(function (err, data) {
            if (err) {
                log.debug(`mongo : ${err}`);
                reject(`mongo : ${err}`);
            }
            else resolve({token: user.token});
        });
    });
}
function updateToken(user, expirationTime) {
    return new Promise(function(resolve, reject) {
        let newToken = genToken(user, expirationTime);
        User.update({email: user.email}, {token: newToken},
            function(err, affected, resp) {
                if (err) {
                    log.debug(`mongo : ${err}`);
                    reject(`mongo : ${err}`);
                }
                else resolve({token: newToken});
        });
    });
}
function deleteToken(user) {
    return new Promise(function(resolve, reject) {
        User.update({email: user.email}, {token: ""},
            function(err, affected, resp) {
                if (err) {
                    log.debug(`mongo : ${err}`);
                    reject(`mongo : ${err}`);
                }
                else resolve();
        });
    });
}
function findByToken(token, cb) {
    User.findOne({"token": token},
        function(err, user) {
            if(err) {
                console.debug(err);
                return cb(null, false);
            }
            if(!user) {
                console.debug("no entry for token");
                return cb(null, false);
            }
            try {
                jwt.verify(token, app.get('key'));
            } catch(e) {
                return cb(e, false);
            }
            return cb(null, user);
        });
}
function isValidCredentials(result) {
    return (result.reqUser.email === result.resUser.email &&
        passwordEncrypt(result.reqUser.password, result.resUser.salt) === result.resUser.password)
}
function genToken(user, expirationTime) {
    // var salt = new Buffer(crypto.randomBytes(16).toString('base64'), 'base64');
    // use not exactly bearer token
    return jwt.sign({email: user.email, name: user.name}, app.get('key'), {
              expiresIn: expirationTime 
            });
}
function passwordEncrypt(password, salt) {
    return crypto.createHmac('sha1', salt).update(password).digest('hex');
}



let app = express();

// configuration 
app.set('key', config.key);
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(passport.initialize());


app.post('/api/register',
    function(req, res) {
        let user = req.body;

        requestUser(user)
            .then(function(result) {
                if(result.resUser) {
                    throw new ServerReject(400, `User has already registered: ${result.resUser.email}`)
                } else {
                    let salt = crypto.randomBytes(128).toString('base64');
                    return insertUser({
                            name: result.reqUser.name, 
                            token: genToken(result.reqUser, 4*60*60), 
                            email: result.reqUser.email,
                            password: passwordEncrypt(result.reqUser.password, salt),
                            salt: salt 
                        });
                }
            })
            .then(function(result) {
                res.status(201).json({
                    success: true,
                    token: result.token
                });
            })
            .catch(function(err) {
                res.status(err.status);
                log.debug(`(${res.statusCode}): ${err.message}`);
                res.json({ 
                    success: false,
                    response: err.message
                });
            });
    });

app.post('/api/login',
    function(req, res) {
        let user = req.body;

        requestUser(user)
            .then(function(result) {
                if(!result.resUser)
                    throw new ServerReject(400, `User with: ${result.resUser.email} not registered yet`)
                if (!isValidCredentials(result))
                    throw new ServerReject(400, 'Password is incorrect');

                return updateToken(result.resUser, 4*60*60);
            })
            .then(function(result) {
                res.status(200).json({
                    success: true,
                    token: result.token
                });
            })
            .catch(function(err) {
                res.status(err.status);
                log.debug(`(${res.statusCode}): ${err.message}`);
                res.json({ 
                    success: false,
                    response: err.message
                });
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
    res.send({error: err.message});
    return;
});



app.listen(config.port, function(){
    log.info(`Express server listening on port ${config.port}`);
});

module.exports = app;
