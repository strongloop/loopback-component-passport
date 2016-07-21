// Copyright IBM Corp. 2016. All Rights Reserved.
// Node module: loopback-component-passport
// This file is licensed under the Artistic License 2.0.
// License text available at https://opensource.org/licenses/Artistic-2.0

'use strict';
var loopback = require('loopback');
var m = require('./init');
var mock = require('mock-require');
var PassportConfigurator = require('../lib/passport-configurator.js');
var assert = require('assert');

describe('configureProvider', function() {
  var app;
  var passportConfigurator;

  function LDAPStrategy(options, verify) {};
  function LocalStrategy(options, verify) {};
  function OAuth1Strategy(options, verify) {};
  function OAuth2Strategy(options, verify) {};
  function OpenIDStrategy(options, verify) {};
  function OpenIDConnectStrategy(options, verify) {};

  function testReturnType(Strategy, module, authScheme) {
    var options = {
      'authScheme': authScheme,
      'module': module,
    };
    var strategy = passportConfigurator.configureProvider(authScheme + 'ProviderName', options);
    assert(strategy instanceof Strategy);
  }

  before('setup loopback and configurator', function() {
    app = loopback();
    passportConfigurator = new PassportConfigurator(app);
  });
  before('mock specific strategies', function() {
    mock('passport-ldapauth', LDAPStrategy);
    mock('passport-local', LocalStrategy);
    mock('passport-oauth1', OAuth1Strategy);
    mock('passport-oauth2', OAuth2Strategy);
    mock('passport-openid', OpenIDStrategy);
    mock('passport-openidconnect', OpenIDConnectStrategy);
  });

  it('returns an LDAPStrategy', function() {
    testReturnType(LDAPStrategy, 'passport-ldapauth', 'ldap');
  });

  it('returns an LocalStrategy', function() {
    testReturnType(LocalStrategy, 'passport-local', 'local');
  });

  it('returns an Oauth1Strategy', function() {
    testReturnType(OAuth1Strategy, 'passport-oauth1', 'oauth1');
  });

  it('returns an Oauth2Strategy', function() {
    testReturnType(OAuth2Strategy, 'passport-oauth2', 'oauth2');
  });

  it('returns an OpenIdStrategy', function() {
    testReturnType(OpenIDStrategy, 'passport-openid', 'openid');
  });

  it('returns an OpenIdConnectStrategy', function() {
    testReturnType(OpenIDConnectStrategy, 'passport-openidconnect', 'openid connect');
  });
});
