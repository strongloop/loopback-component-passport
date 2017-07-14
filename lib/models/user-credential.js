// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback-component-passport
// This file is licensed under the Artistic License 2.0.
// License text available at https://opensource.org/licenses/Artistic-2.0

'use strict';
var utils = require('./utils');

module.exports = UserCredential;

/**
 * @class
 * @classdesc Tracks third-party logins and profiles.
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
 * @inherits {DataModel}
 */
function UserCredential(UserCredential) {
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
  UserCredential.link = function(userId, provider, authScheme, profile,
                                  credentials, options, cb) {
    options = options || {};
    if (typeof options === 'function' && cb === undefined) {
      cb = options;
      options = {};
    }
    var userCredentialModel = utils.getModel(this, UserCredential);
    userCredentialModel.findOne({where: {
      userId: userId,
      provider: provider,
      externalId: profile.id,
    }}, function(err, extCredential) {
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

      // Create the linked account
      userCredentialModel.create({
        provider: provider,
        externalId: profile.id,
        authScheme: authScheme,
        profile: profile,
        credentials: credentials,
        userId: userId,
        created: date,
        modified: date,
      }, function(err, i) {
        cb(err, i);
      });
    });
  };
  return UserCredential;
};
