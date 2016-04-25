(function() {
  var loopback = require('loopback');
  var app = loopback();
  var m = require('./init');
  var mock = require('mock-require');
  var PassportConfigurator = require('../lib/passport-configurator.js');
  var passportConfigurator = new PassportConfigurator(app);
  var passport = require('passport');
  var assert = require('assert');
  var request = require('supertest');
  var sinon = require('sinon');
  var passportAuthenticate;

  //mock a strategy to work with
  function PassportFacebookStrategy(options, verify) {};
  PassportFacebookStrategy.prototype.authenticate = function(req, options) {};
  mock('passport-facebook', PassportFacebookStrategy);

  describe('Login failure', function() {
    before(function(done) {
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
      done();
    });

    afterEach(function(done) {
      if (passportAuthenticate) passportAuthenticate.restore();
      done();
    });

    it('redirects to failure with error', function(done) {
      passportAuthenticate = sinon.stub(passport, 'authenticate',
          getAuthenticateStubFunction('horrible mistake'));
      request(app)
          .get('/auth/facebook/callback')
          .expect(302)
          .end(function(err, response) {
            assert.equal(response.headers.location, '/auth/facebook-failure?error=horrible%20mistake');
            done();
          });
    });

    it('redirects to failure without error if empty string', function(done) {
      passportAuthenticate = sinon.stub(passport, 'authenticate', getAuthenticateStubFunction(''));
      request(app)
          .get('/auth/facebook/callback')
          .expect(302)
          .end(function(err, response) {
            assert.equal(response.headers.location, '/auth/facebook-failure');
            done();
          });
    });
  });

  describe('Link failure', function() {
    before(function(done) {
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
      var passportAuthorize = sinon.stub(passport, 'authorize', getAuthorizeStubFunction('omg'));
      passportConfigurator.configureProvider('facebook-link', linkOptions);
      passportAuthorize.restore();
      done();
    });

    it('redirects to failure with error', function(done) {
      request(app)
          .get('/auth/facebook-link/callback')
          .expect(302)
          .end(function(err, response) {
            assert.equal(response.headers.location, '/auth/facebook-failure?error=omg');
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
})();
