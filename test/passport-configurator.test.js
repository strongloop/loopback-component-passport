var m = require('./init');
var loopback = require('loopback');
var assert = require('assert');
var UserIdentity = m.UserIdentity;
var User = loopback.User;
var UserCredential = m.UserCredential;
var PassportConfigurator = m.PassportConfigurator;
var app = loopback();
var passportConfigurator = new PassportConfigurator(app);

before(function(done) {
  User.destroyAll(done);
});

describe('PassportConfigurator', function() {
  before(function() {
    var ds = loopback.createDataSource({
      connector: 'memory',
    });

    UserIdentity.attachTo(ds);
    User.attachTo(ds);
    UserIdentity.belongsTo(User);

    passportConfigurator.init();
    passportConfigurator.setupModels({
      userModel: User,
      userIdentityModel: UserIdentity,
      userCredentialModel: UserCredential,
    });
  });

  it('supports user ldap profile configuration with all minimal config', function(done) {
    var providerConfig = {
      ldap: {
        provider: 'ldap',
        authScheme: 'ldap',
        module: 'passport-ldapauth',
        authPath: '/auth/ldap',
        successRedirect: '/auth/account',
        failureRedirect: '/ldap',
        session: true,
        failureFlash: true,
        profileAttributesFromLDAP: {
          login: 'uid',
          username: 'uid',
          displayName: 'displayName',
          email: 'mail',
          externalId: 'uid',
<<<<<<< HEAD
          id: 'uid',
        },
      },
    };
=======
          id: 'uid'
        }
      }
    }
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests

    /* user's ldap attributes */
    var userFromLdap = {
      uid: 'john-doe-uid',
      displayName: 'John Doe',
<<<<<<< HEAD
      mail: 'john.doe@somewhere.sw',
=======
      mail: 'john.doe@somewhere.sw'
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
    };
    var profile = passportConfigurator._buildUserLdapProfile(userFromLdap, providerConfig.ldap);

    assert.equal(profile.login, userFromLdap.uid, '"login" should take value of "uid"');
    assert.equal(profile.username, userFromLdap.uid, '"username" should take value of "uid"');
<<<<<<< HEAD
    assert.equal(profile.displayName, userFromLdap.displayName,
      '"displayName" should take value of "displayName"');
    assert.equal(profile.email, userFromLdap.mail, '"email" should take value of "mail"');
    assert.deepEqual(profile.emails, [{ value: userFromLdap.mail }],
      '"emails" should be comptued from "mail"');
=======
    assert.equal(profile.displayName, userFromLdap.displayName, '"displayName" should take value of "displayName"');
    assert.equal(profile.email, userFromLdap.mail, '"email" should take value of "mail"');
    assert.deepEqual(profile.emails, [{value: userFromLdap.mail}], '"emails" should be comptued from "mail"');
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
    assert.equal(profile.externalId, userFromLdap.uid, '"externalId" should take value of "uid"');
    done();
  });

  it('supports user ldap profile configuration with missing ldap mapping configuration', function(done) {
    var providerConfig = {
      ldap: {
        provider: 'ldap',
        authScheme: 'ldap',
        module: 'passport-ldapauth',
        authPath: '/auth/ldap',
        successRedirect: '/auth/account',
        failureRedirect: '/ldap',
        session: true,
        failureFlash: true,
        profileAttributesFromLDAP: {
          // empty mapping
<<<<<<< HEAD
        },
      },
    };
=======
        }
      }
    }
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests

    /* user's ldap attributes */
    var userFromLdap = {
      cn: 'John Doe',
      uid: 'john-doe-uid',
      displayName: 'John Doe',
<<<<<<< HEAD
      mail: 'john.doe@somewhere.sw',
=======
      mail: 'john.doe@somewhere.sw'
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
    };
    var profile = passportConfigurator._buildUserLdapProfile(userFromLdap, providerConfig.ldap);

    // 3 ldap attributes are required in profile: username, emails, id.
    // They should be present even if not defiend in Ldap mapping, set to default Ldap attributes
    assert.equal(profile.username, userFromLdap.cn, '"username" should take value of "cn"');
<<<<<<< HEAD
    assert.deepEqual(profile.emails, [{ value: userFromLdap.mail }],
      '"emails" should be comptued from "mail"');
    assert.equal(profile.id, userFromLdap.uid, '"id" should take value of "uid"');
    done();
  });
=======
    assert.deepEqual(profile.emails, [{value: userFromLdap.mail}], '"emails" should be comptued from "mail"');
    assert.equal(profile.id, userFromLdap.uid, '"id" should take value of "uid"');
    done();
  });

>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
});
