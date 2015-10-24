var loopback = require('loopback'),
    passport = require('passport'),
    _ = require('lodash');

module.exports = PassportConfigurator;

/**
 The passport configurator
 @param {Object} app The Loopback app instance
 @returns {PassportConfigurator} an instance of PassportConfigurator
 @constructor
 @class
 */

function PassportConfigurator(app){

    if (!(this instanceof PassportConfigurator))
        return new PassportConfigurator(app);

    this.app = app;
}

PassportConfigurator.prototype = {
    app: null,
    userCredentialModel: null,
    userModel: null,

    init: function(){},
    setupModels: function(){}
};

/**
 * Set up data models for user identity/credential and application credential
 * @options {Object} options Options for models
 * @property {Model} [userModel] The user model class
 * @property {Model} [userCredentialModel] The user credential model class
 * @property {Model} [userIdentityModel] The user identity model class
 * @end
 */
PassportConfigurator.prototype.setupModels = function(options){
    options = options || {};

    this.userCredentialModel = options.userCredentialModel || loopback.getModelByType(this.app.models.UserCredential);
    this.userIdentityModel = options.userIdentityModel || loopback.getModelByType(this.app.models.UserIdentity);
    this.userModel = options.userModel || loopback.getModelByType(this.app.models.User);

    //The user will have multiple identities
    if (!this.userModel.relations.identities)
        this.userModel.hasMany(this.userIdentityModel, {as: 'identities'});
    else
        this.userIdentityModel = this.userModel.relations.identities.modelTo;

    //The user will have multiple credentials
    if (!this.userModel.relations.credentials)
        this.userModel.hasMany(this.userCredentialModel, {as: 'credentials'});
    else
        this.userCredentialModel = this.userModel.relations.credentials.modelTo;

    if (!this.userIdentityModel.relations.user)
        this.userIdentityModel.belongsTo(this.userModel, {as: 'user'});

    if (!this.userCredentialModel.relations.user)
        this.userCredentialModel.belongsTo(this.userModel, {as: 'user'});
};

/**
 * Initialize the passport configurator
 * @param {Boolean} noSession Set to true if no session is required
 * @returns {Passport}
 */
PassportConfigurator.prototype.init = function(noSession){
    var _this = this;

    //adding passport to the req object after the "session phase".
    _this.app.middleware('session:after', passport.initialize());

    if (!noSession){
        _this.app.middleware('session:after', passport.session());
        // Serialization and deserialization is only required if passport session is enabled

        passport.serializeUser(function(user, done) {
            done(null, user.id);
        });

        passport.deserializeUser(function(id, done) {

            // Look up the user instance by id
            _this.userModel.findById(id, function(err, user) {
                if (err || !user) {
                    return done(err, user);
                }
                user.identities(function(err, identities) {
                    user.profiles = identities;
                    user.credentials(function(err, accounts) {
                        user.accounts = accounts;
                        done(err, user);
                    });
                });
            });
        });
    }

    return passport;
};

/**
 * Configure a Passport strategy provider.
 * @param {String} name The provider name
 * @options {Object} General&nbsp;Options Options for the auth provider.
 * There are general options that apply to all providers, and provider-specific
 * options, as described below.
 * @property {Boolean} link Set to true if the provider is for third-party
 * account linking.
 * @property {Object} module The passport strategy module from require.
 * @property {String} authScheme The authentication scheme, such as 'local',
 * 'oAuth 2.0'.
 * @property {Boolean} [session] Set to true if session is required.  Valid
 * for any auth scheme.
 * @property {String} [authPath] Authentication route.
 *
 * @options {Object} oAuth2&nbsp;Options Options for oAuth 2.0.
 * @property {String} [clientID] oAuth 2.0 client ID.
 * @property {String} [clientSecret] oAuth 2.0 client secret.
 * @property {String} [callbackURL] oAuth 2.0 callback URL.
 * @property {String} [callbackPath] oAuth 2.0 callback route.
 * @property {String} [scope] oAuth 2.0 scopes.
 * @property {String} [successRedirect] The redirect route if login succeeds.
 * For both oAuth 1 and 2.
 * @property {String} [failureRedirect] The redirect route if login fails.
 * For both oAuth 1 and 2.
 *
 * @options {Object} Local&nbsp;Strategy&nbsp;Options Options for local
 * strategy.
 * @property {String} [usernameField] The field name for username on the form
 * for local strategy.
 * @property {String} [passwordField] The field name for password on the form
 * for local strategy.
 *
 * @options {Object} oAuth1&nbsp;Options Options for oAuth 1.0.
 * @property {String} [consumerKey] oAuth 1 consumer key.
 * @property {String} [consumerSecret] oAuth 1 consumer secret.
 * @property {String} [successRedirect] The redirect route if login succeeds.
 * For both oAuth 1 and 2.
 * @property {String} [failureRedirect] The redirect route if login fails.
 * For both oAuth 1 and 2.
 *
 * @options {Object} OpenID&nbsp;Options Options for OpenID.
 * @property {String} [returnURL] OpenID return URL.
 * @property {String} [realm] OpenID realm.
 * @end
 */

PassportConfigurator.prototype.configureProvider = function(name, options) {
    var _this = this;
    options = options || {};

    var link = options.link;

    var AuthStrategy = require(options.module)[options.strategy || 'Strategy'];
    var authScheme = options.authScheme;

    authScheme = (options.consumerKey) ? 'oAuth1'
        : (options.realm) ? 'OpenID'
        : (options.clientID) ? 'oAuth 2.0'
        : (options.usernameField) ? 'local'
        : 'local';

    var clientID = options.clientID;
    var clientSecret = options.clientSecret;
    var callbackURL = options.callbackURL;

    var authPath = options.authPath || ((link ? '/link/' : '/auth/') + name);
    var callbackPath = options.callbackPath || ((link ? '/link/' : '/auth/') + name + '/callback');

    var successRedirect = options.successRedirect || (link ? '/link/account' : '/auth/account');
    var failureRedirect = options.failureRedirect || (link ? '/link.html' : '/login.html');

    var scope = options.scope;
    var authType = authScheme.toLowerCase();

    var session = !!options.session;

    var loginCallback = options.loginCallback || function (req, done) {
            return function (err, user, identity, token) {
                var authInfo = {
                    identity: identity
                };
                if (token) {
                    authInfo.accessToken = token;
                }
                done(err, user, authInfo);
            };
        };

    // configure passport depending on authType
    switch (authType) {
        case 'ldap':
            setupLDAP();
            break;
        case 'local':
            setupLocal();
            break;
        case 'oauth':
        case 'oauth1':
        case 'oauth 1.0':
            setupOAuth();
            break;
        case 'openid':
            setupOpenID();
            break;
        case 'openid connect':
            setupOpenIDConnect();
            break;
        default:
            setupDefaultAuthStrategy();
    }


    /*
     * Redirect the user to Facebook for authentication.  When complete,
     * Facebook will redirect the user back to the application at
     * /auth/facebook/callback with the authorization code
     */

    if (authType === 'ldap' || authType == 'local') {
        var callback = options.customCallback || defaultCallback;
        _this.app.post(authPath, callback);
    }

    if (link)
        _this.app.get(authPath, passport.authorize(name, _.defaults({
            scope: scope,
            session: session
        }, options.authOptions)));
    else
        _this.app.get(authPath, passport.authenticate(name, _.defaults({
            scope: scope,
            session: session
        }, options.authOptions)));


    /*
     * Facebook will redirect the user to this URL after approval. Finish the
     * authentication process by attempting to obtain an access token using the
     * authorization code. If access was granted, the user will be logged in.
     * Otherwise, authentication has failed.
     */
    if (link) {
        _this.app.get(callbackPath, passport.authorize(name, _.defaults({
                session: session,
                successRedirect: successRedirect,
                failureRedirect: failureRedirect
            }, options.authOptions)),
            function (req, res, next) {
                res.redirect(successRedirect);
            }, function (err, req, res, next) {
                res.redirect(failureRedirect);
            });
    } else {
        console.log("AuthType ", authType);
        console.log("callbackPath ", callbackPath);

        var customCallback = options.customCallback || defaultCallback;
        _this.app.get(callbackPath, customCallback);
    }


    /*

     */
    function setupLDAP() {
        passport.use(name, new AuthStrategy(_.defaults({
                usernameField: options.usernameField || 'username',
                passwordField: options.passwordField || 'password',
                session: options.session, authInfo: true,
                passReqToCallback: true
            }, options),
            function (req, user, done) {
                if (user) {
                    var LdapAttributeForUsername = options.LdapAttributeForUsername || 'cn';
                    var LdapAttributeForMail = options.LdapAttributeForMail || 'mail';
                    var externalId = user[options.LdapAttributeForLogin || 'uid'];
                    var email = [].concat(user[LdapAttributeForMail])[0];
                    var profile = {
                        username: [].concat(user[LdapAttributeForUsername])[0],
                        id: externalId
                    };
                    if (!!email) {
                        profile.emails = [{value: email}]
                    }
                    var OptionsForCreation = _.defaults({
                        autoLogin: true
                    }, options);
                    _this.userIdentityModel.login(name, authScheme, profile, {},
                        OptionsForCreation, loginCallback(req, done))
                }
                else {
                    done(null)
                }
            }
        ));
    }

    function setupLocal() {
        passport.use(name, new AuthStrategy(_.defaults({
                usernameField: options.usernameField || 'username',
                passwordField: options.passwordField || 'password',
                session: options.session, authInfo: true
            }, options),
            function (username, password, done) {
                var query = {
                    where: {
                        or: [
                            {username: username},
                            {email: username}
                        ]
                    }
                };
                _this.userModel.findOne(query, function (err, user) {
                    if (err) {
                        return done(err);
                    }
                    if (user) {
                        var u = user.toJSON();
                        delete u.password;
                        var userProfile = {
                            provider: 'local',
                            id: u.id,
                            username: u.username,
                            emails: [
                                {
                                    value: u.email
                                }
                            ],
                            status: u.status,
                            accessToken: null
                        };

                        // If we need a token as well, authenticate using Loopbacks
                        // own login system, else defer to a simple password check
                        //will grab user info from providers.json file.  Right now
                        //this only can use email and username, which are the 2 most common
                        if (options.setAccessToken) {
                            switch (options.usernameField) {
                                case  'email':
                                    login({email: username, password: password});
                                    break;
                                case 'username':
                                    login({username: username, password: password});
                                    break;
                            }

                            function login(creds) {

                                _this.userModel.login(creds,
                                    function (err, accessToken) {
                                        if (err) {
                                            return done(err);
                                        }
                                        if (accessToken) {
                                            userProfile.accessToken = accessToken;
                                            done(null, user, {accessToken: accessToken});
                                        } else {
                                            done(null, false, {message: 'Failed to create token.'});
                                        }
                                    });
                            }
                        } else {
                            user.hasPassword(password, function (err, ok) {
                                if (ok) {
                                    done(null, userProfile);
                                } else {
                                    return done(null, false, {message: 'Incorrect password.'});
                                }
                            });
                        }
                    } else {
                        return done(null, false, {message: 'Incorrect username.'});
                    }
                });
            }
        ));
    }

    function setupOAuth() {
        passport.use(name, new AuthStrategy(_.defaults({
                consumerKey: options.consumerKey,
                consumerSecret: options.consumerSecret,
                callbackURL: callbackURL,
                passReqToCallback: true
            }, options),
            function (req, token, tokenSecret, profile, done) {
                if (link) {
                    if (req.user) {
                        _this.userCredentialModel.link(
                            req.user.id, name, authScheme, profile,
                            {token: token, tokenSecret: tokenSecret}, options, done);
                    } else {
                        done('No user is logged in');
                    }
                } else {
                    _this.userIdentityModel.login(name, authScheme, profile,
                        {
                            token: token,
                            tokenSecret: tokenSecret
                        }, options, loginCallback(req, done));
                }
            }
        ));
    }

    function setupOpenID() {
        passport.use(name, new AuthStrategy(_.defaults({
                returnURL: options.returnURL,
                realm: options.realm,
                callbackURL: callbackURL,
                passReqToCallback: true
            }, options),
            function (req, identifier, profile, done) {
                if (link) {
                    if (req.user) {
                        _this.userCredentialModel.link(
                            req.user.id, name, authScheme, profile,
                            {identifier: identifier}, options, done);
                    } else {
                        done('No user is logged in');
                    }
                } else {
                    _this.userIdentityModel.login(name, authScheme, profile,
                        {identifier: identifier}, options, loginCallback(req, done));
                }
            }
        ));
    }

    function setupOpenIDConnect() {
        passport.use(name, new AuthStrategy(_.defaults({
                clientID: clientID,
                clientSecret: clientSecret,
                callbackURL: callbackURL,
                passReqToCallback: true
            }, options),
            function (req, accessToken, refreshToken, profile, done) {
                if (link) {
                    if (req.user) {
                        _this.userCredentialModel.link(
                            req.user.id, name, authScheme, profile,
                            {
                                accessToken: accessToken,
                                refreshToken: refreshToken
                            }, options, done);
                    } else {
                        done('No user is logged in');
                    }
                } else {
                    _this.userIdentityModel.login(name, authScheme, profile,
                        {accessToken: accessToken, refreshToken: refreshToken},
                        options, loginCallback(req, done));
                }
            }
        ));
    }

    function setupDefaultAuthStrategy() {
        passport.use(name, new AuthStrategy(_.defaults({
                clientID: clientID,
                clientSecret: clientSecret,
                callbackURL: callbackURL,
                passReqToCallback: true
            }, options),
            function (req, accessToken, refreshToken, profile, done) {
                if (link) {
                    if (req.user) {
                        _this.userCredentialModel.link(
                            req.user.id, name, authScheme, profile,
                            {
                                accessToken: accessToken,
                                refreshToken: refreshToken
                            }, options, done);
                    } else {
                        done('No user is logged in');
                    }
                } else {
                    _this.userIdentityModel.login(name, authScheme, profile,
                        {accessToken: accessToken, refreshToken: refreshToken},
                        options, loginCallback(req, done));
                }
            }
        ));
    }

    function defaultCallback(req, res, next) {
        passport.authenticate(name,
            _.defaults({session: session}, options.authOptions),
            function (err, user, info) {
                if (err) {
                    return next(err);
                }
                if (!user) {
                    if (!!options.json) {
                        return res.status(401).json(info)
                    }
                    return res.redirect(failureRedirect);
                }

                // ensure the email has been verified before login.
                if (options.emailVerificationRequired && !user.emailVerified) {
                    err = new Error('login failed as the email has not been verified');
                    err.statusCode = 401;
                    err.code = 'EMAIL_NOT_VERIFIED';
                    return next(err);
                }

                // ensure the account has not been disabled before login
                if (user.disabled === true) {
                    err = new Error('login failed as the account is disabled');
                    err.statusCode = 401;
                    err.code = 'LOGIN_FAILED_ACCOUNT_DISABLED';
                    return next(err);
                }

                // if session is activated attach the user to the session
                if (session) {
                    req.logIn(user, function (err) {
                        if (err) {
                            return next(err);
                        }
                    });
                }

                if (info && info.accessToken) {
                    // if the access token is available and the JSON option is activated
                    if (!!options.json)
                        return res.json({'access_token': info.accessToken.id, 'userId': user.id});
                    // if the access token is available and the cookie option is activated
                    else
                        addCookies(req, res, user.id, info.accessToken.id, info.accessToken.ttl);
                }

                return res.redirect(successRedirect);
            })(req, res, next);
    }

    /**
     *
     * @param req
     * @param res
     * @param user_id
     * @param access_token
     * @param ttl
     */
    function addCookies(req, res, user_id, access_token, ttl) {
        res.cookie('access_token', access_token,
            {
                signed: req.signedCookies ? true : false,
                maxAge: 1000 * ttl
            });
        res.cookie('userId', user_id.toString(), {
            signed: req.signedCookies ? true : false,
            maxAge: 1000 * ttl
        });
    }
};