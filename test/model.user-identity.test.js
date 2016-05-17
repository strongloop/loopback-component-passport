// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback-component-passport
// This file is licensed under the Artistic License 2.0.
// License text available at https://opensource.org/licenses/Artistic-2.0

'use strict';
var m = require('./init');
var loopback = require('loopback');
var assert = require('assert');
var UserIdentity = m.UserIdentity;
var User = loopback.User;

describe('UserIdentity', function() {
  before(function setupUserIdentityRelation() {
    UserIdentity.belongsTo(User);
  });

  beforeEach(function setupDatabase(done) {
    User.destroyAll(done);
  });

  it('supports 3rd party login', function(done) {
    UserIdentity.login('facebook', 'oAuth 2.0',
      {emails: [
        {value: 'foo@bar.com'},
      ], id: 'f123', username: 'xyz',
      }, {accessToken: 'at1', refreshToken: 'rt1'},
      {autoLogin: false},
      function(err, user, identity, token) {
        assert(!err, 'No error should be reported');
        assert.equal(user.username, 'facebook.xyz');
        assert.equal(user.email, 'xyz@loopback.facebook.com');

        assert.equal(identity.externalId, 'f123');
        assert.equal(identity.provider, 'facebook');
        assert.equal(identity.authScheme, 'oAuth 2.0');
        assert.deepEqual(identity.credentials, {accessToken: 'at1', refreshToken: 'rt1'});

        assert.equal(user.id, identity.userId);
        assert(!token);

        // Follow the belongsTo relation
        identity.user(function(err, user) {
          assert(!err, 'No error should be reported');
          assert.equal(user.username, 'facebook.xyz');
          assert.equal(user.email, 'xyz@loopback.facebook.com');
          done();
        });
      });
  });

  it('supports 3rd party login if the identity already exists', function(done) {
    User.create({
      username: 'facebook.abc',
      email: 'abc@facebook.com',
      password: 'pass',
    }, function(err, user) {
      if (err) return done(err);
      UserIdentity.create({
        externalId: 'f456',
        provider: 'facebook',
        userId: user.id,
        authScheme: 'oAuth 2.0',
      }, function(err, identity) {
        if (err) return done(err);
        UserIdentity.login('facebook', 'oAuth 2.0',
          {emails: [
            {value: 'abc1@facebook.com'},
          ], id: 'f456', username: 'xyz',
          }, {accessToken: 'at2', refreshToken: 'rt2'}, function(err, user, identity, token) {
            if (err) return done(err);
            assert.equal(user.username, 'facebook.abc');
            assert.equal(user.email, 'abc@facebook.com');

            assert.equal(identity.externalId, 'f456');
            assert.equal(identity.provider, 'facebook');
            assert.equal(identity.authScheme, 'oAuth 2.0');
            assert.deepEqual(identity.credentials, {accessToken: 'at2', refreshToken: 'rt2'});

            assert.equal(user.id, identity.userId);

            assert(token);

            // Follow the belongsTo relation
            identity.user(function(err, user) {
              assert(!err, 'No error should be reported');
              assert.equal(user.username, 'facebook.abc');
              assert.equal(user.email, 'abc@facebook.com');
              done();
            });
          });
      });
    });
  });

  it('supports 3rd party login if user account already exists', function(done) {
    User.create({
      username: 'facebook.789',
      email: '789@facebook.com',
      password: 'pass',
    }, function(err, user) {
      UserIdentity.login('facebook', 'oAuth 2.0',
        {emails: [
          {value: '789@facebook.com'},
        ], id: 'f789', username: 'ttt',
        }, {accessToken: 'at3', refreshToken: 'rt3'}, function(err, user, identity, token) {
          assert(!err, 'No error should be reported');
          assert.equal(user.username, 'facebook.ttt');
          assert.equal(user.email, 'ttt@loopback.facebook.com');

          assert.equal(identity.externalId, 'f789');
          assert.equal(identity.provider, 'facebook');
          assert.equal(identity.authScheme, 'oAuth 2.0');
          assert.deepEqual(identity.credentials, {accessToken: 'at3', refreshToken: 'rt3'});

          assert.equal(user.id, identity.userId);
          assert(token);

          // Follow the belongsTo relation
          identity.user(function(err, user) {
            assert(!err, 'No error should be reported');
            assert.equal(user.username, 'facebook.ttt');
            assert.equal(user.email, 'ttt@loopback.facebook.com');
            done();
          });
        });
    });
  });

  it('supports 3rd party login with profileToUser option', function(done) {
    UserIdentity.login('facebook', 'oAuth 2.0',
      {emails: [
        {value: 'foo@baz.com'},
      ], id: 'f100', username: 'joy',
      }, {accessToken: 'at1', refreshToken: 'rt1'}, {
        profileToUser: function(provider, profile) {
          return {
            username: profile.username + '@facebook',
            email: profile.emails[0].value,
            password: 'sss',
          };
        }}, function(err, user, identity, token) {
          assert(!err, 'No error should be reported');
          assert.equal(user.username, 'joy@facebook');
          assert.equal(user.email, 'foo@baz.com');

          assert.equal(identity.externalId, 'f100');
          assert.equal(identity.provider, 'facebook');
          assert.equal(identity.authScheme, 'oAuth 2.0');
          assert.deepEqual(identity.credentials, {accessToken: 'at1', refreshToken: 'rt1'});

          assert.equal(user.id, identity.userId);
          assert(token);

        // Follow the belongsTo relation
          identity.user(function(err, user) {
            assert(!err, 'No error should be reported');
            assert.equal(user.username, 'joy@facebook');
            assert.equal(user.email, 'foo@baz.com');
            done();
          });
        });
  });

  it('supports ldap login', function(done) {
    var identity = {emails: [{value: 'fooldap@bar.com'}], id: 'f123ldap',
     username: 'xyzldap'};
    var credentials = {accessToken: 'atldap1', refreshToken: 'rtldap1'};
    var options = {autoLogin: false};
    UserIdentity.login('ldap', 'ldap', identity, credentials, options,
       function(err, user, identity, token) {
         if (err) return done(err);

         assert.equal(user.username, 'ldap.xyzldap');
         assert.equal(user.email, 'fooldap@bar.com');

         assert.equal(identity.externalId, 'f123ldap');
         assert.equal(identity.provider, 'ldap');
         assert.deepEqual(identity.credentials, {accessToken: 'atldap1',
       refreshToken: 'rtldap1'});

         assert.equal(user.id, identity.userId);
         assert(!token);

        // Follow the belongsTo relation
         identity.user(function(err, user) {
           if (err) return done(err);

           assert.equal(user.username, 'ldap.xyzldap');
           assert.equal(user.email, 'fooldap@bar.com');

           done();
         });
       });
  });

  it('supports accessToken option before email verification', function(done) {
    User.create({
      username: 'myLocalTest',
      email: 'myLocalTest@local.com',
      password: 'pass',
      emailVerified: 0,
    }, function(err, user) {
      if (err) return done(err);
      assert.equal(user.username, 'myLocalTest');
      assert.equal(user.email, 'myLocalTest@local.com');
      assert.equal(user.emailVerified, false);
      User.login({username: user.username, password: 'notpass'},
        function(err, user) {
          assert(err, 'LOGIN_FAILED');
        });
      User.login({username: user.username, password: 'pass'},
        function(err, user) {
          assert(err, 'LOGIN_FAILED');
        });
      done();
    });
  });

  it('supports accessToken option after verification', function(done) {
    User.create({
      username: 'myLocalTest2',
      email: 'myLocalTest2@local.com',
      password: 'pass',
      emailVerified: 1,
    }, function(err, user) {
      if (err) return done(err);
      assert.equal(user.username, 'myLocalTest2');
      assert.equal(user.email, 'myLocalTest2@local.com');
      assert.equal(user.emailVerified, true);
      User.login({username: user.username, password: 'notpass'},
        function(err, user) {
          assert(err, 'LOGIN_FAILED');
        });
      User.login({username: user.username, password: 'pass'},
        function(err, user) {
          if (err) return done(err);
        });
      done();
    });
  });

  describe('emailOptional set to false', function(err) {
    it('creates a user when given an email address', function(done) {
      var username = 'fbu123';
      UserIdentity.login('facebook', 'oAuth 2.0', {
        email: 'abc123@example.com',
        id: 'fbi123',
        username: username,
      }, {
        accessToken: 'at1',
        refreshToken: 'rt1',
      }, {
        emailOptional: false,
        profileToUser: customProfileToUser,
      }, function(err, user, identity, token) {
        if (err) return done(err);
        assert.equal(user.username, username);
        done();
      });
    });

    it('does not create a user if an email address was not given', function(done) {
      User.count(function(err, countBefore) {
        if (err) return done(err);
        UserIdentity.login('facebook', 'oAuth 2.0', {
          id: 'fbi234',
          username: 'fbu234',
        }, {
          accessToken: 'at2',
          refreshToken: 'rt2',
        }, {
          emailOptional: false,
          profileToUser: customProfileToUser,
        }, function(err, user, identity, token) {
          assert(err.match(/email is missing/), 'Should report error');
          assert(typeof user === 'undefined', 'Should not return a user instance');
          User.count(function(err, countAfter) {
            if (err) return done(err);
            assert.equal(countBefore, countAfter,
              'Expected user count after execution to remain the same');
            done();
          });
        });
      });
    });

    function customProfileToUser(provider, profile, options) {
      var userInfo = {
        username: profile.username,
        password: 'secret',
        email: profile.email,
      };
      return userInfo;
    }
  });
});
