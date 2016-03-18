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
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 2.1.0
=======
>>>>>>> 2.1.0
          id: 'uid',
        },
      },
    };
<<<<<<< HEAD
<<<<<<< HEAD
=======
=======
          id: 'uid'
        }
      }
    }
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
>>>>>>> 2.1.0
=======
>>>>>>> 2.1.0

    /* user's ldap attributes */
    var userFromLdap = {
      uid: 'john-doe-uid',
      displayName: 'John Doe',
<<<<<<< HEAD
<<<<<<< HEAD
      mail: 'john.doe@somewhere.sw',
=======
<<<<<<< HEAD
      mail: 'john.doe@somewhere.sw',
=======
      mail: 'john.doe@somewhere.sw'
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
>>>>>>> 2.1.0
=======
      mail: 'john.doe@somewhere.sw',
>>>>>>> 2.1.0
    };
    var profile = passportConfigurator._buildUserLdapProfile(userFromLdap, providerConfig.ldap);

    assert.equal(profile.login, userFromLdap.uid, '"login" should take value of "uid"');
    assert.equal(profile.username, userFromLdap.uid, '"username" should take value of "uid"');
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 2.1.0
=======
>>>>>>> 2.1.0
    assert.equal(profile.displayName, userFromLdap.displayName,
      '"displayName" should take value of "displayName"');
    assert.equal(profile.email, userFromLdap.mail, '"email" should take value of "mail"');
    assert.deepEqual(profile.emails, [{ value: userFromLdap.mail }],
      '"emails" should be comptued from "mail"');
<<<<<<< HEAD
<<<<<<< HEAD
=======
=======
    assert.equal(profile.displayName, userFromLdap.displayName, '"displayName" should take value of "displayName"');
    assert.equal(profile.email, userFromLdap.mail, '"email" should take value of "mail"');
    assert.deepEqual(profile.emails, [{value: userFromLdap.mail}], '"emails" should be comptued from "mail"');
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
>>>>>>> 2.1.0
=======
>>>>>>> 2.1.0
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
<<<<<<< HEAD
        },
      },
    };
=======
<<<<<<< HEAD
        },
      },
    };
=======
        }
      }
    }
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
>>>>>>> 2.1.0
=======
        },
      },
    };
>>>>>>> 2.1.0

    /* user's ldap attributes */
    var userFromLdap = {
      cn: 'John Doe',
      uid: 'john-doe-uid',
      displayName: 'John Doe',
<<<<<<< HEAD
<<<<<<< HEAD
      mail: 'john.doe@somewhere.sw',
=======
<<<<<<< HEAD
      mail: 'john.doe@somewhere.sw',
=======
      mail: 'john.doe@somewhere.sw'
>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
>>>>>>> 2.1.0
=======
      mail: 'john.doe@somewhere.sw',
>>>>>>> 2.1.0
    };
    var profile = passportConfigurator._buildUserLdapProfile(userFromLdap, providerConfig.ldap);

    // 3 ldap attributes are required in profile: username, emails, id.
    // They should be present even if not defiend in Ldap mapping, set to default Ldap attributes
    assert.equal(profile.username, userFromLdap.cn, '"username" should take value of "cn"');
<<<<<<< HEAD
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 2.1.0
=======
>>>>>>> 2.1.0
    assert.deepEqual(profile.emails, [{ value: userFromLdap.mail }],
      '"emails" should be comptued from "mail"');
    assert.equal(profile.id, userFromLdap.uid, '"id" should take value of "uid"');
    done();
  });
<<<<<<< HEAD
<<<<<<< HEAD
=======
=======
    assert.deepEqual(profile.emails, [{value: userFromLdap.mail}], '"emails" should be comptued from "mail"');
    assert.equal(profile.id, userFromLdap.uid, '"id" should take value of "uid"');
    done();
  });

>>>>>>> b392de7... refactor ldap mapping configuration dto be testable and add tests
>>>>>>> 2.1.0
=======
>>>>>>> 2.1.0
});
