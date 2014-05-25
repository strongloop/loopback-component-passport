var loopback = require('loopback');
var passport = require('passport');
var models = require('./models/user-identity');

module.exports = PassportConfigurator;

function PassportConfigurator(app) {
  if (!(this instanceof PassportConfigurator)) {
    return new PassportConfigurator(app);
  }
  this.app = app;
}

PassportConfigurator.prototype.setupModels = function (options) {
  options = options || {};
  // Set up relations
  this.userModel = options.userModel || loopback.getModelByType(loopback.User);
  this.userCredentialModel = options.userCredentialModel || loopback.getModelByType(models.UserCredential);
  this.userIdentityModel = options.userIdentityModel || loopback.getModelByType(models.UserIdentity);

  if (!this.userModel.relations.identities) {
    this.userModel.hasMany(this.userIdentityModel, {as: 'identities'});
  } else {
    this.userIdentityModel = this.userModel.relations.identities.modelTo;
  }

  if (!this.userModel.relations.credentials) {
    this.userModel.hasMany(this.userCredentialModel, {as: 'credentials'});
  } else {
    this.userCredentialModel = this.userModel.relations.credentials.modelTo;
  }
}

PassportConfigurator.prototype.init = function (noSession) {
  var self = this;
  self.app.use(passport.initialize());

  if (!noSession) {
    self.app.use(passport.session());

    // Serialization and deserialization is only required if passport session is
    // enabled

    passport.serializeUser(function (user, done) {
      done(null, user.id);
    });

    passport.deserializeUser(function (id, done) {

      // Look up the user instance by id
      self.userModel.findById(id, function (err, user) {
        if (err || !user) {
          return done(err, user);
        }
        user.identities(function (err, identities) {
          user.profiles = identities;
          user.credentials(function (err, accounts) {
            user.accounts = accounts;
            done(err, user);
          });
        });
      });
    });
  }
}

PassportConfigurator.prototype.configureProvider = function (name, options) {
  var self = this;
  options = options || {};
  var link = options.link;
  var AuthStrategy = require(options.module)[options.strategy || 'Strategy'];

  var authScheme = options.authScheme || 'oAuth 2.0';
  var clientID = options.clientID;
  var clientSecret = options.clientSecret;
  var callbackURL = options.callbackURL;
  var authPath = options.authPath || ((link ? '/link/' : '/auth/') + name);
  var callbackPath = options.callbackPath || ((link ? '/link/' : '/auth/') + name + '/callback');
  var successRedirect = options.successRedirect || (link ? '/link/account' : '/auth/account');
  var failureRedirect = options.failureRedirect || (link ? '/link.html' : '/login.html');
  var scope = options.scope;

  var session = !!options.session;

  function loginCallback(req, done) {
    return function (err, user, identity, token) {
      if (token) {
        req.accessToken = token;
      }
      done(err, user, identity, token);
    };
  }

  switch (authScheme.toLowerCase()) {
    case 'oauth':
    case 'oauth1':
    case 'oauth 1.0':
      passport.use(name, new AuthStrategy({
          consumerKey: options.consumerKey,
          consumerSecret: options.consumerSecret,
          callbackURL: callbackURL,
          passReqToCallback: true
        },
        function (req, token, tokenSecret, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(req.user.id, name, authScheme, profile,
                {token: token, tokenSecret: tokenSecret}, done);
            } else {
              done('No user is logged in');
            }
          } else {
            self.userIdentityModel.login(name, authScheme, profile,
              {token: token, tokenSecret: tokenSecret}, loginCallback(req, done));
          }
        }
      ));
      break;
    case 'openid':
      passport.use(name, new AuthStrategy({
          returnURL: options.returnURL,
          realm: options.realm,
          callbackURL: callbackURL,
          passReqToCallback: true
        },
        function (req, identifier, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(req.user.id, name, authScheme, profile,
                {identifier: identifier}, done);
            } else {
              done('No user is logged in');
            }
          } else {
            self.userIdentityModel.login(name, authScheme, profile,
              {identifier: identifier}, loginCallback(req, done));
          }
        }
      ));
      break;
    case 'openid connect':
      passport.use(name, new AuthStrategy({
          clientID: clientID,
          clientSecret: clientSecret,
          callbackURL: callbackURL,
          passReqToCallback: true
        },
        function (req, accessToken, refreshToken, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(req.user.id, name, authScheme, profile,
                {accessToken: accessToken, refreshToken: refreshToken}, done);
            } else {
              done('No user is logged in');
            }
          } else {
            self.userIdentityModel.login(name, authScheme, profile,
              {accessToken: accessToken, refreshToken: refreshToken}, loginCallback(req, done));
          }
        }
      ));
      break;
    default:
      passport.use(name, new AuthStrategy({
          clientID: clientID,
          clientSecret: clientSecret,
          callbackURL: callbackURL,
          passReqToCallback: true
        },
        function (req, accessToken, refreshToken, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(req.user.id, name, authScheme, profile,
                {accessToken: accessToken, refreshToken: refreshToken}, done);
            } else {
              done('No user is logged in');
            }
          } else {
            self.userIdentityModel.login(name, authScheme, profile,
              {accessToken: accessToken, refreshToken: refreshToken}, loginCallback(req, done));
          }
        }
      ));
  }

  /*
   * Redirect the user to Facebook for authentication.  When complete,
   * Facebook will redirect the user back to the application at
   * /auth/facebook/callback with the authorization code
   */
  if (link) {
    self.app.get(authPath, passport.authorize(name, {scope: scope, session: session}));
  } else {
    self.app.get(authPath, passport.authenticate(name, {scope: scope, session: session}));
  }

  /*
   * Facebook will redirect the user to this URL after approval. Finish the
   * authentication process by attempting to obtain an access token using the
   * authorization code. If access was granted, the user will be logged in.
   * Otherwise, authentication has failed.
   */
  if (link) {
    self.app.get(callbackPath, passport.authorize(name, {
        session: session,
        // successReturnToOrRedirect: successRedirect,
        successRedirect: successRedirect,
        failureRedirect: failureRedirect }),
      // passport.authorize doesn't handle redirect
      function (req, res, next) {
        res.redirect(successRedirect);
      }, function (err, req, res, next) {
        res.redirect(failureRedirect);
      });
  } else {
    self.app.get(callbackPath,
      passport.authenticate(name, {
        session: session,
        // successReturnToOrRedirect: successRedirect,
        successRedirect: successRedirect,
        failureRedirect: failureRedirect }));
  }
}
