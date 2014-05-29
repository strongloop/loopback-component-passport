var m = require('./init');
var loopback = require('loopback');
var assert = require('assert');
var UserIdentity = m.UserIdentity;
var UserCredential = m.UserCredential;
var User = loopback.User;

before(function (done) {
  User.destroyAll(done);
});

describe('UserIdentity', function () {

  before(function () {
    var ds = loopback.createDataSource({
      connector: 'memory'
    });

    UserIdentity.attachTo(ds);
    User.attachTo(ds);
    UserIdentity.belongsTo(User);
  });

  it('supports 3rd party login', function (done) {
    UserIdentity.login('facebook', 'oAuth 2.0',
      {emails: [
        {value: 'foo@bar.com'}
      ], id: 'f123', username: 'xyz'
      }, {accessToken: 'at1', refreshToken: 'rt1'},
      {autoLogin: false},
      function (err, user, identity, token) {
        assert(!err, 'No error should be reported');
        assert.equal(user.username, 'facebook.xyz');
        assert.equal(user.email, 'foo@bar.com');

        assert.equal(identity.externalId, 'f123');
        assert.equal(identity.provider, 'facebook');
        assert.equal(identity.authScheme, 'oAuth 2.0');
        assert.deepEqual(identity.credentials, {accessToken: 'at1', refreshToken: 'rt1'});

        assert.equal(user.id, identity.userId);
        assert(!token);

        // Follow the belongsTo relation
        identity.user(function (err, user) {
          assert(!err, 'No error should be reported');
          assert.equal(user.username, 'facebook.xyz');
          assert.equal(user.email, 'foo@bar.com');
          done();
        });
      });
  });

  it('supports 3rd party login if the identity already exists', function (done) {
    User.create({
      username: 'facebook.abc',
      email: 'abc@facebook.com',
      password: 'pass'
    }, function (err, user) {
      UserIdentity.create({
        externalId: 'f456',
        provider: 'facebook',
        userId: user.id,
        authScheme: 'oAuth 2.0'
      }, function (err, identity) {
        UserIdentity.login('facebook', 'oAuth 2.0',
          {emails: [
            {value: 'abc1@facebook.com'}
          ], id: 'f456', username: 'xyz'
          }, {accessToken: 'at2', refreshToken: 'rt2'}, function (err, user, identity,token) {
            assert(!err, 'No error should be reported');
            assert.equal(user.username, 'facebook.abc');
            assert.equal(user.email, 'abc@facebook.com');

            assert.equal(identity.externalId, 'f456');
            assert.equal(identity.provider, 'facebook');
            assert.equal(identity.authScheme, 'oAuth 2.0');
            assert.deepEqual(identity.credentials, {accessToken: 'at2', refreshToken: 'rt2'});

            assert.equal(user.id, identity.userId);

            assert(token);

            // Follow the belongsTo relation
            identity.user(function (err, user) {
              assert(!err, 'No error should be reported');
              assert.equal(user.username, 'facebook.abc');
              assert.equal(user.email, 'abc@facebook.com');
              done();
            });
          });
      });
    });
  });

  it('supports 3rd party login if user account already exists', function (done) {
    User.create({
      username: 'facebook.789',
      email: '789@facebook.com',
      password: 'pass'
    }, function (err, user) {
      UserIdentity.login('facebook', 'oAuth 2.0',
        {emails: [
          {value: '789@facebook.com'}
        ], id: 'f789', username: 'ttt'
        }, {accessToken: 'at3', refreshToken: 'rt3'}, function (err, user, identity, token) {
          assert(!err, 'No error should be reported');
          assert.equal(user.username, 'facebook.789');
          assert.equal(user.email, '789@facebook.com');

          assert.equal(identity.externalId, 'f789');
          assert.equal(identity.provider, 'facebook');
          assert.equal(identity.authScheme, 'oAuth 2.0');
          assert.deepEqual(identity.credentials, {accessToken: 'at3', refreshToken: 'rt3'});

          assert.equal(user.id, identity.userId);
          assert(token);

          // Follow the belongsTo relation
          identity.user(function (err, user) {
            assert(!err, 'No error should be reported');
            assert.equal(user.username, 'facebook.789');
            assert.equal(user.email, '789@facebook.com');
            done();
          });
        });
    });
  });

  it('supports 3rd party login with profileToUser option', function (done) {
    UserIdentity.login('facebook', 'oAuth 2.0',
      {emails: [
        {value: 'foo@baz.com'}
      ], id: 'f100', username: 'joy'
      }, {accessToken: 'at1', refreshToken: 'rt1'}, {
        profileToUser: function (provider, profile) {
          return {
            username: profile.username + '@facebook',
            email: profile.emails[0].value,
            password: 'sss'
          };
        }}, function (err, user, identity, token) {
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
        identity.user(function (err, user) {
          assert(!err, 'No error should be reported');
          assert.equal(user.username, 'joy@facebook');
          assert.equal(user.email, 'foo@baz.com');
          done();
        });
      });
  });

});

describe('UserCredential', function () {
  var userId = null;
  before(function (done) {
    var ds = loopback.createDataSource({
      connector: 'memory'
    });

    UserCredential.attachTo(ds);
    User.attachTo(ds);
    UserCredential.belongsTo(User);

    User.create({
      username: 'facebook.abc',
      email: 'uuu@facebook.com',
      password: 'pass'
    }, function (err, user) {
      userId = user.id;
      done(err);
    });
  });

  it('supports linked 3rd party accounts', function (done) {
    UserCredential.link(userId, 'facebook', 'oAuth 2.0',
      {emails: [
        {value: 'foo@bar.com'}
      ], id: 'f123', username: 'xyz'
      }, {accessToken: 'at1', refreshToken: 'rt1'}, function (err, cred) {
        assert(!err, 'No error should be reported');

        assert.equal(cred.externalId, 'f123');
        assert.equal(cred.provider, 'facebook');
        assert.equal(cred.authScheme, 'oAuth 2.0');
        assert.deepEqual(cred.credentials, {accessToken: 'at1', refreshToken: 'rt1'});

        assert.equal(userId, cred.userId);

        // Follow the belongsTo relation
        cred.user(function (err, user) {
          assert(!err, 'No error should be reported');
          assert.equal(user.username, 'facebook.abc');
          assert.equal(user.email, 'uuu@facebook.com');
          done();
        });
      });
  });

  it('supports linked 3rd party accounts if exists', function (done) {
    UserCredential.create({
      externalId: 'f456',
      provider: 'facebook',
      userId: userId,
      credentials: {accessToken: 'at1', refreshToken: 'rt1'}
    }, function (err, cred) {
      UserCredential.link(userId, 'facebook', 'oAuth 2.0',
        {emails: [
          {value: 'abc1@facebook.com'}
        ], id: 'f456', username: 'xyz'
        }, {accessToken: 'at2', refreshToken: 'rt2'}, function (err, cred) {
          assert(!err, 'No error should be reported');

          assert.equal(cred.externalId, 'f456');
          assert.equal(cred.provider, 'facebook');
          assert.deepEqual(cred.credentials, {accessToken: 'at2', refreshToken: 'rt2'});

          assert.equal(userId, cred.userId);

          // Follow the belongsTo relation
          cred.user(function (err, user) {
            assert(!err, 'No error should be reported');
            assert.equal(user.username, 'facebook.abc');
            assert.equal(user.email, 'uuu@facebook.com');
            done();
          });
        });
    });
  });

});

