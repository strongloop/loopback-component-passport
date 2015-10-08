/**
 * Tracks third-party logins and profiles.
 *
 * @param {String} provider   Auth provider name, such as facebook, google, twitter, linkedin.
 * @param {String} authScheme Auth scheme, such as oAuth, oAuth 2.0, OpenID, OpenID Connect.
 * @param {String} externalId Provider specific user ID.
 * @param {Object} profile User profile, see http://passportjs.org/guide/profile.
 * @param {Object} credentials Credentials.  Actual properties depend on the auth scheme being used:
 *
 * - oAuth: token, tokenSecret
 * - oAuth 2.0: accessToken, refreshToken
 * - OpenID: openId
 * - OpenID: Connect: accessToken, refreshToken, profile
 * @param {*} userId The LoopBack user ID.
 * @param {Date} created The created date
 * @param {Date} modified The last modified date
 *
 * @class
 * @inherits {DataModel}
 */
module.exports = function(UserCredential) {
  var utils = require('./utils');

  /**
   * Link a third party account to a LoopBack user
   * @param {String} provider The provider name
   * @param {String} authScheme The authentication scheme
   * @param {Object} profile The profile
   * @param {Object} credentials The credentials
   * @param {Object} [options] The options
   * @callback {Function} cb The callback function
   * @param {Error|String} err The error object or string
   * @param {Object} [credential] The user credential object
   */
  UserCredential.link = function (userId, provider, authScheme, profile,
                                  credentials, options, cb) {
    options = options || {};
    if(typeof options === 'function' && cb === undefined) {
      cb = options;
      options = {};
    }
    var userCredentialModel = utils.getModel(this, UserCredential);
    /**
     * Create the credential data object to pass to the model.
     * Once ES6 computed property name syntax is in node we can go back to not having to store this in a var
     */
    var credentialSearchObj={
      provider: provider,
      externalId: profile.id
    };
    credentialSearchObj[userCredentialModel.relations.user.keyFrom]=userId;
    userCredentialModel.findOne({where: credentialSearchObj}, function (err, extCredential) {
      if (err) {
        return cb(err);
      }

      var date = new Date();
      if (extCredential) {
        // Find the user for the given extCredential
        extCredential.credentials = credentials;
        return extCredential.updateAttributes({profile: profile,
          credentials: credentials, modified: date}, cb);
      }
     
     /**
     * Create the linkedaccount ata object to pass to the model.
     * Once ES6 computed property name syntax is in node we can go back to not having to store this in a var
     */
      var linkedAccountObj={
        provider: provider,
        externalId: profile.id,
        authScheme: authScheme,
        profile: profile,
        credentials: credentials,
        created: date,
        modified: date
      };
      linkedAccountObj[userCredentialModel.relations.user.keyFrom]=userId;
     // Create the linked account
      userCredentialModel.create(linkedAccountObj, function (err, i) {
        cb(err, i);
      });

    });
  }
  return UserCredential;
};
