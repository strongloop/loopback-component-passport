// Copyright IBM Corp. 2016. All Rights Reserved.
// Node module: loopback-component-passport
// This file is licensed under the Artistic License 2.0.
// License text available at https://opensource.org/licenses/Artistic-2.0

'use strict';
var loopback = require('loopback');
var m = require('./init');
var mock = require('mock-require');
var PassportConfigurator = require('../lib/passport-configurator.js');
var passport = require('passport');
var assert = require('assert');
var request = require('supertest');
var sinon = require('sinon');

describe('login failure', function() {
  var passportAuthenticate;
  var app;

  before('set up loopback app', function() {
    app = loopback();
  });

  before('configure facebook strategy', function() {
    var passportConfigurator = new PassportConfigurator(app);

    //mock a strategy to work with
    function PassportFacebookStrategy(options, verify) {};
    PassportFacebookStrategy.prototype.authenticate = function(req, options) {};
    mock('passport-facebook', PassportFacebookStrategy);

    var options = {
      'provider': 'facebook',
      'module': 'passport-facebook',
      'callbackURL': '/auth/facebook/callback',
      'authPath': '/auth/facebook',
      'callbackPath': '/auth/facebook/callback',
      'successRedirect': '/auth/facebook/redirect',
      'failureRedirect': '/auth/facebook-failure',
      'failureQueryString': true,
      'link': false,
    };
    passportConfigurator.configureProvider('facebook-login', options);
  });

  afterEach('cleanup mocks', function() {
    if (passportAuthenticate) passportAuthenticate.restore();
  });

  it('redirects to failure with error', function(done) {
    passportAuthenticate = sinon.stub(passport, 'authenticate',
      getAuthenticateStubFunction('horrible mistake'));
    request(app)
      .get('/auth/facebook/callback')
      .expect(302)
      .end(function(err, res) {
        assert.equal(res.headers.location, '/auth/facebook-failure?error=horrible%20mistake');
        done();
      });
  });

  it('redirects to failure without error if empty string', function(done) {
    passportAuthenticate = sinon.stub(passport, 'authenticate', getAuthenticateStubFunction(''));
    request(app)
      .get('/auth/facebook/callback')
      .expect(302)
      .end(function(err, res) {
        assert.equal(res.headers.location, '/auth/facebook-failure');
        done();
      });
  });
});

describe('link failure', function() {
  var app;

  before('set up loopback app', function() {
    app = loopback();
  });

  before('setup facebook strategy', function() {
    var passportConfigurator = new PassportConfigurator(app);
    var linkOptions = {
      'provider': 'facebook',
      'module': 'passport-facebook',
      'callbackURL': '/auth/facebook-link/callback',
      'authPath': '/auth/facebook-link',
      'callbackPath': '/auth/facebook-link/callback',
      'successRedirect': '/auth/facebook-link/redirect',
      'failureRedirect': '/auth/facebook-failure',
      'failureQueryString': true,
      'link': true,
    };

    //passportConfigurator.configureProvider internally uses passport.authorize so stub it
    var passportAuthorize = sinon.stub(passport, 'authorize', getAuthorizeStubFunction('omg'));
    passportConfigurator.configureProvider('facebook-link', linkOptions);
    passportAuthorize.restore();
  });

  it('redirects to failure with error', function(done) {
    request(app)
      .get('/auth/facebook-link/callback')
      .expect(302)
      .end(function(err, res) {
        assert.equal(res.headers.location, '/auth/facebook-failure?error=omg');
        done();
      });
  });
});

function getAuthenticateStubFunction(wantedError) {
  return function(name, options, cb) {
    if (cb) cb(null, false, wantedError);
    return function(req, res, next) { next(); };
  };
}

function getAuthorizeStubFunction(err) {
  return function(passport, name, options, callback) {
    return function(req, res, next) { next(err); };
  };
}
