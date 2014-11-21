var m = require('./init');
var loopback = require('loopback');
var assert = require('assert');
var UserCredential = m.UserCredential;
var User = loopback.User;

before(function (done) {
  User.destroyAll(done);
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
