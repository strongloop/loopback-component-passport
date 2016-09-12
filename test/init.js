// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback-component-passport
// This file is licensed under the Artistic License 2.0.
// License text available at https://opensource.org/licenses/Artistic-2.0

'use strict';
var loopback = require('loopback');
var passport = module.exports = require('../lib/index');

var db = loopback.createDataSource('db', {connector: 'memory'});

loopback.Application.attachTo(db);
loopback.User.attachTo(db);
loopback.AccessToken.attachTo(db);

passport.UserIdentity.attachTo(db);
passport.UserCredential.attachTo(db);
passport.ApplicationCredential.attachTo(db);

